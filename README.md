# FSearch

Whole-disk file search for macOS: fuzzy names, filters, indexed content grep
and symbol lookup. Link it into an app as a crate, or use the CLI and its
small daemon (JSON lines over a local socket).

```
cargo build --release && ./target/release/fsearch install   # -> ~/.local/bin/fsearch
fsearch fsearch main            # fuzzy name search (starts the daemon on first use)
fsearch 'ext:rs grep:apply_dir' # content search, narrowed by name filters
fsearch stdio                   # JSON lines on stdin/stdout
```

## As a library

```toml
[dependencies]
fsearch = { path = "../FSearch" }
```

```rust
let home = std::env::var("HOME").unwrap();
let engine = fsearch::Engine::start(fsearch::Options {
    dir: fsearch::default_dir(&home), // shared with the CLI
    home: home.clone(),
    skip: None, // or folders never to open (see below)
})?;

let mut q = fsearch::Query::parse("fsearch main ext:rs", &home)?;
q.limit = 200;
let hits = engine.search(&q)?; // Err only until the index is loaded

let mut q = fsearch::Query::parse("in:~/Developer grep:apply_dir", &home)?;
let grep = fsearch::Grep::new(&q.grep.take().unwrap(), q.grep_mode)?;
let (found, _) = engine.grep(&q, &grep)?;
```

`Engine::start` returns at once and loads in the background (milliseconds when
an index exists). Any number of processes can run an engine over the same
`dir`: the first one takes `daemon.lock` and owns the files (crawl, saves,
content index); the rest load the saved index, follow FSEvents themselves in
memory, open the content index read-only, and take over within 10 s when the
owner exits. So an app and the CLI share one index and never crawl twice.

`skip: None` decides from Full Disk Access (below). An app that must never put
a privacy prompt on screen passes the folders from `fsearch::gated()` it has
not been let into.

## Numbers (M4 Max, this Mac: 7.66M files and folders, 518k text files indexed)

Measured in-process (the library, as an app calls it), against a fresh `fd`
listing of the disk and a full read of every indexable file as ground truth.

| | |
|---|---|
| found: 2000 random entries on disk, by name in their folder | 99.95% (the miss: a folder cargo created mid-run, found since) |
| exact file name, whole disk, rank of the right file | #1 for 99.2%, top 10 for 99.8% |
| name without extension / folder + name | #1 for 79% / 86.5%, top 10 for 99% |
| exact-name query, whole disk | p50 1.3 ms, p90 5 ms |
| typing (every prefix of 80 names, 200 results) | p50 1.7 ms, p90 7.9 ms, p99 9.8 ms |
| one-letter query (worst case) | ~12 ms |
| rename / move / delete visible in search | ~15 / 15 / 50 ms |
| new folder with 50 files, all visible | ~65 ms |
| edited text file, new content searchable | ~2.3 s (2 s quiet debounce) |
| content recall (329 patterns: literals, regexes, symbols) | 100%; precision 99.6-99.9% (files edited mid-run) |
| content query, default (top 50) | p50 9 ms, p90 71 ms; common words 3-30 ms |
| `sym:` (definition lookup) | 0.2-2 ms (exhaustive `sym:main`, 9.9k files: 0.4 s) |
| lost FSEvents history (relist changed folders) | ~8-13 s instead of a recrawl |
| `fd` for one name, no index | 25.9 s |
| first-ever crawl of the whole disk | ~20 s, then never again |
| content index first build | ~30-45 s |
| compaction (fold changes into the base, save) | ~1 s, about hourly on a busy disk |
| daemon footprint | ~135 MB shortly after a content rebuild (index pages are clean, evictable mmap) |
| on disk | 280 MB names + ~700 MB content |

The crawl is bound by two Endpoint Security clients on this Mac (MDM,
VPN) that tax every `open()` (~19 µs per directory); file reads peak at
4 threads for the same reason, so content reads use a 4-thread pool.

## Full Disk Access

Started from a terminal that has Full Disk Access, the daemon inherits it
and indexes everything. Run any other way (e.g. as a login item) it needs its
own grant: System Settings > Privacy & Security > Full Disk Access > add
`~/.local/bin/fsearch`, then `fsearch install --login` (an ad-hoc signed
build's grant is tied to that exact binary, so re-grant after rebuilding, or
sign it with a stable identity). Without the grant
it detects that at startup and stays out of consent-gated folders
(Desktop, Documents, Downloads, iCloud, app containers, CloudStorage,
/Volumes) instead of blocking on a privacy prompt. It never downloads iCloud
placeholders and never blocks on FIFOs.

## How it works

- **Crawl** (`walk.rs`): parallel `getattrlistbulk` + `openat` over `/`,
  crossing firmlinks (so `/Users` etc. appear once) but not mount points.
  One syscall returns hundreds of entries with type, size, mtime, flags.
  Only happens on the very first run, or if FSEvents history is lost.
- **Name index** (`index.rs`): one mmap'd file. Entries are laid out one
  directory block at a time in DFS order, so any folder's subtree is a single
  contiguous range (`in:` is a range bound, not a filter). Names are interned
  (7.5M entries share ~2M names) with a per-name character mask.
- **Query** (`query.rs`): score each *distinct* name once (mask prefilter, then
  an fzf-style fuzzy score), then score entries: a rare query visits only the
  entries carrying a matching name (a name -> entries list in the index), a
  common one makes one sequential pass with a table lookup each. Multi-word
  queries match words against the name or any folder on the path via a
  per-directory memo (built top-down in parallel). The name table is kept for
  the next keystroke: a query that extends the last one rescores only the
  names that matched it. Ranking adds a location prior (home and apps over
  caches and system) and recency. Searches run on their own user-interactive
  thread pool, so a caller's low-priority thread doesn't land them on
  efficiency cores.
- **Live** (`live.rs`, `fsevents.rs`): a whole-disk FSEvents stream at
  directory granularity. Each changed directory is re-listed and diffed against
  the index (idempotent), landing in a small overlay plus a tombstone bitset;
  listing happens outside the write lock, so searches never wait on the disk.
  The base is compacted and saved now and then with the FSEvents id, so a
  restart replays only what happened since. If FSEvents loses track (dropped
  events, or no history back to the save), every folder is `lstat`ed in
  parallel and the ones modified since the last in-sync moment are relisted:
  ~8 s instead of a recrawl.
- **Content** (`content.rs`): a trigram index over your text files (home,
  minus dependencies, caches, build output, bundles; files up to 1 MiB).
  Immutable mmap'd segments: delta-varint posting lists, bitsets for common
  trigrams, tiered merging. A query becomes an AND/OR of trigrams (regexes are
  planned from their syntax tree), the postings pick candidates, and candidates
  are read fresh from disk and matched, so results are never stale.
  Definitions (`fn x`, `class X`, `def x`, `struct`, `const`, ...) are indexed
  as extra keys beside the trigrams, so `sym:` reads only the files that
  define the name. Kept in sync by the same directory diffs as the name index, debounced
  (2 s of quiet, at most 5 min) so files apps rewrite constantly cost little.
  `in:` outside the indexed area (e.g. `in:/etc`) greps the files the name
  index lists there instead of crawling.

## Query language

Words are fuzzy (all must match, the name or a folder on the path).
`'exact`, `^prefix`, `suffix$`, `!exclude`. Filters:

| filter | example |
|---|---|
| `ext:` | `ext:rs,toml` |
| `type:` | `image video audio doc code archive font app` |
| `kind:` | `file dir link` |
| `in:` | `in:~/Developer` |
| `size:` | `size:>10mb`, `size:1k..2m` |
| `mtime:` | `mtime:<7d` (modified within 7 days) |
| `re:` / `path:` | regex on the name / full path |
| `grep:` / `regex:` / `sym:` | content: literal / regex / definition of a symbol |
| `limit:` | `limit:200` |

Content search uses smart case (case-sensitive only if the pattern has an
uppercase letter).

## API

One JSON object per line over `~/Library/Application Support/FSearch/fsearch.sock`
or `fsearch stdio`. Any filter can be given as a field instead of in `q`.

```json
{"id": 1, "q": "fsearch main", "limit": 20}
{"id": 2, "q": "readme", "in": "~/Developer", "kind": "file"}
{"id": 3, "op": "grep", "pattern": "fn\\s+apply_dir", "mode": "regex", "ext": "rs"}
{"id": 4, "op": "status"}
```

Responses:

```json
{"id":1,"ok":true,"took_us":412,"hits":[{"path":"/Users/noah/Developer/Tools/FSearch/src/main.rs","kind":"file","size":2246,"mtime":1791248887,"score":412}]}
{"id":3,"ok":true,"took_us":5800,"source":"index","candidates":2530,"read":448,"indexing":0,
 "files":[{"path":".../live.rs","matches":[{"line":93,"text":"    pub fn apply_dir(&mut self, ..."}]}]}
```

Ops: `search` (default), `grep`, `status`, `save` (compact + persist now), `ping`.

## Files

`~/Library/Application Support/FSearch/`: `index.bin` (names), `content/`
(segments), `daemon.lock` (held by the engine that owns these), `daemon.log`,
`fsearch.sock`. `fsearch uninstall` removes the
LaunchAgent and keeps these.
