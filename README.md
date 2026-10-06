# FSearch

Whole-disk file search for macOS: fuzzy names, filters, and indexed content
grep, served by a small daemon over a local JSON-lines API.

```
fsearch install                 # copy to ~/.local/bin, run as a LaunchAgent
fsearch fsearch main            # fuzzy name search
fsearch 'ext:rs grep:apply_dir' # content search, narrowed by name filters
fsearch stdio                   # JSON lines on stdin/stdout
```

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
  an fzf-style fuzzy score), then one sequential pass over entries with a table
  lookup each. Multi-word queries match words against the name or any folder on
  the path via a per-directory memo computed in one pass. Ranking adds a
  location prior (home and apps over caches and system) and recency.
- **Live** (`live.rs`, `fsevents.rs`): a whole-disk FSEvents stream at
  directory granularity. Each changed directory is re-listed and diffed against
  the index (idempotent), landing in a small overlay plus a tombstone bitset;
  the base is compacted and saved now and then with the FSEvents id, so a
  restart replays only what happened since.
- **Content** (`content.rs`): a trigram index over your text files (home,
  minus dependencies, caches, build output, bundles; files up to 1 MiB).
  Immutable mmap'd segments: delta-varint posting lists, bitsets for common
  trigrams, tiered merging. A query becomes an AND/OR of trigrams (regexes are
  planned from their syntax tree), the postings pick candidates, and candidates
  are read fresh from disk and matched, so results are never stale.
  Kept in sync by the same directory diffs as the name index.
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
(segments), `daemon.log`, `fsearch.sock`. `fsearch uninstall` removes the
LaunchAgent and keeps these.
