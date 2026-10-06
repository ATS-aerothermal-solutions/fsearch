//! The daemon: owns the live index, applies FSEvents, answers JSON lines
//! over a unix socket. `fsearch stdio` and the CLI are thin clients.

use crate::fsevents::{self, HISTORY_DONE, MUST_SCAN_SUBDIRS};
use crate::index::Index;
use crate::live::{Applied, Live};
use crate::content::{self, Content, Grep};
use crate::query::{GrepMode, Query, Searcher, is_filter};
use crate::walk::{self, KIND_DIR, KIND_FILE, KIND_LINK};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

const COMPACT_PENDING: usize = 200_000;
// Saving rewrites ~250 MB; restart replays FSEvents history anyway, so
// only persist twice a day (or when the overlay gets big).
const COMPACT_EVERY: Duration = Duration::from_secs(12 * 3600);
const SCAN_THREADS: usize = 8;

pub struct Shared {
    live: RwLock<Option<Live>>,
    content: RwLock<Content>,
    home: String,
    dir: PathBuf,
    /// Wakes the apply loop; an empty batch is a no-op wake-up.
    wake: Sender<Vec<fsevents::Event>>,
    save_requested: AtomicBool,
    /// (dirs, trees) for the content worker to re-sync.
    content_tx: Sender<(Vec<Vec<u8>>, Vec<Vec<u8>>)>,
    content_pending: AtomicUsize,
}

pub fn socket_path(dir: &Path) -> PathBuf {
    dir.join("fsearch.sock")
}

fn log(msg: impl AsRef<str>) {
    eprintln!("{} {}", crate::query::now_secs(), msg.as_ref());
}

pub fn serve(dir: PathBuf, home: String) {
    // One daemon per user: a second one would steal the socket and race
    // index writes. The lock dies with the process.
    let lock = std::fs::File::create(dir.join("daemon.lock")).expect("lock file");
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        log("another fsearch daemon is running");
        return;
    }
    let fda = has_full_disk_access() && std::env::var_os("FSEARCH_RESTRICT").is_none();
    if !fda {
        let h = home.as_str();
        let skip = [
            format!("{h}/Desktop"),
            format!("{h}/Documents"),
            format!("{h}/Downloads"),
            format!("{h}/Library/Mobile Documents"),
            format!("{h}/Library/Containers"),
            format!("{h}/Library/Group Containers"),
            format!("{h}/Library/CloudStorage"),
            format!("{h}/Pictures/Photos Library.photoslibrary"),
            "/Volumes".to_string(),
        ];
        log("no Full Disk Access: skipping consent-gated folders (grant it to fsearch to index everything)");
        let _ = walk::SKIP.set(skip.into_iter().map(String::into_bytes).collect());
    }
    let idx_path = dir.join("index.bin");
    let base = Index::load(&idx_path);
    // Watch before scanning so nothing that changes mid-scan is missed;
    // replaying it afterwards is harmless because diffs are idempotent.
    let since = match &base {
        Some(b) if b.event_id != 0 => b.event_id,
        _ => unsafe { fsevents::FSEventsGetCurrentEventId() },
    };
    let (tx, rx) = std::sync::mpsc::channel();
    fsevents::watch(since, 0.1, tx.clone());

    let (ctx, crx) = std::sync::mpsc::channel();
    let content = Content::open(dir.join("content"));
    let shared = Arc::new(Shared {
        live: RwLock::new(None),
        content: RwLock::new(content),
        home,
        dir: dir.clone(),
        wake: tx,
        save_requested: AtomicBool::new(false),
        content_tx: ctx,
        content_pending: AtomicUsize::new(0),
    });
    let sock = socket_path(&dir);
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).expect("bind socket");
    let s2 = shared.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let s = s2.clone();
            std::thread::spawn(move || handle(conn, &s));
        }
    });

    let base = match base {
        Some(b) => {
            log(format!("loaded {} entries, replaying events since {}", b.n, b.event_id));
            b
        }
        None => full_build(&shared, since),
    };
    *shared.live.write().unwrap() = Some(Live::new(base));
    // Content: reconcile all of home once (cheap when nothing changed), then
    // follow along with the name index's changes.
    let _ = shared.content_tx.send((Vec::new(), vec![shared.home.as_bytes().to_vec()]));
    let s3 = shared.clone();
    std::thread::spawn(move || content_loop(&s3, crx));
    apply_loop(&shared, rx);
}

fn content_loop(shared: &Shared, rx: Receiver<(Vec<Vec<u8>>, Vec<Vec<u8>>)>) {
    // Indexing file contents is background work: utility QoS keeps it off
    // the user's way (lower CPU priority and IO tier).
    unsafe { libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_UTILITY, 0) };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .start_handler(|_| unsafe {
            libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_UTILITY, 0);
        })
        .build()
        .unwrap();
    let home = shared.home.as_bytes().to_vec();
    while let Ok((mut dirs, mut trees)) = rx.recv() {
        while let Ok((d, t)) = rx.try_recv() {
            dirs.extend(d);
            trees.extend(t);
        }
        let t = Instant::now();
        let wants = {
            let g = shared.live.read().unwrap();
            let Some(live) = g.as_ref() else { continue };
            content::wants(live, &home, &dirs, &trees)
        };
        let todo = shared.content.write().unwrap().diff(wants);
        if todo.len() == 0 {
            continue;
        }
        let n = todo.len();
        shared.content_pending.store(n, Ordering::Relaxed);
        for batch in todo.batches() {
            let (dir, id) = {
                let mut c = shared.content.write().unwrap();
                (c.dir(), c.alloc_id())
            };
            let len = batch.len();
            if let Some(seg) = pool.install(|| content::build_segment(&dir, id, &todo, batch)) {
                shared.content.write().unwrap().push(seg);
            }
            shared.content_pending.fetch_sub(len, Ordering::Relaxed);
        }
        drop(todo);
        // Keep the segment count small: merge size tiers of 8.
        loop {
            let plan = shared.content.read().unwrap().merge_plan();
            let Some(ids) = plan else { break };
            let (dir, id) = {
                let mut c = shared.content.write().unwrap();
                (c.dir(), c.alloc_id())
            };
            let merged = {
                let c = shared.content.read().unwrap();
                pool.install(|| Content::merge(&dir, id, &c.segments(&ids)))
            };
            match merged {
                Some(seg) => shared.content.write().unwrap().replace(&ids, seg),
                None => break,
            }
        }
        if n > 100 {
            log(format!("content: indexed {n} files in {:.2?}", t.elapsed()));
        }
        release_memory();
    }
}

/// The system TCC database is readable only with Full Disk Access, and
/// trying without it fails immediately (no prompt).
fn has_full_disk_access() -> bool {
    std::fs::File::open("/Library/Application Support/com.apple.TCC/TCC.db").is_ok()
}

fn full_build(shared: &Shared, event_id: u64) -> Index {
    let t = Instant::now();
    let (ls, _) = walk::scan(b"/", SCAN_THREADS);
    let idx = Index::build(ls, event_id, shared.home.as_bytes());
    let path = shared.dir.join("index.bin");
    idx.save(&path).expect("save index");
    log(format!("indexed {} entries in {:.2?}", idx.n, t.elapsed()));
    release_memory();
    // Re-map from the file so the index is clean, evictable page cache
    // rather than anonymous memory.
    Index::load(&path).unwrap_or(idx)
}

unsafe extern "C" {
    fn malloc_zone_pressure_relief(zone: *mut std::ffi::c_void, goal: usize) -> usize;
}

/// Hand freed allocator memory back to the OS after big transient work
/// (index builds, content batches) instead of letting malloc cache it.
fn release_memory() {
    unsafe { malloc_zone_pressure_relief(std::ptr::null_mut(), 0) };
}

fn compact(shared: &Shared) {
    let t = Instant::now();
    let (ls, eid) = {
        let g = shared.live.read().unwrap();
        let live = g.as_ref().unwrap();
        (live.to_listings(), live.event_id)
    };
    let idx = Index::build(ls, eid, shared.home.as_bytes());
    let path = shared.dir.join("index.bin");
    if let Err(e) = idx.save(&path) {
        log(format!("save failed: {e}"));
    }
    let idx = Index::load(&path).unwrap_or(idx);
    let n = idx.n;
    *shared.live.write().unwrap() = Some(Live::new(idx));
    release_memory();
    log(format!("compacted to {n} entries in {:.2?}", t.elapsed()));
}

fn apply_loop(shared: &Shared, rx: Receiver<Vec<fsevents::Event>>) {
    let mut last_save = Instant::now();
    loop {
        let mut events = match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(b) => b,
            Err(RecvTimeoutError::Timeout) => Vec::new(),
            Err(RecvTimeoutError::Disconnected) => return,
        };
        while let Ok(b) = rx.try_recv() {
            events.extend(b);
        }
        if !events.is_empty() {
            let mut dirs: HashMap<Vec<u8>, bool> = HashMap::new();
            let mut max_id = 0;
            for e in events {
                max_id = max_id.max(e.id);
                if e.flags & HISTORY_DONE != 0 {
                    log("replay done");
                    continue;
                }
                let mut p = e.path;
                while p.len() > 1 && p.last() == Some(&b'/') {
                    p.pop();
                }
                *dirs.entry(p).or_default() |= e.flags & MUST_SCAN_SUBDIRS != 0;
            }
            let mut rebuild = false;
            let mut trees = Vec::new();
            {
                let mut g = shared.live.write().unwrap();
                let live = g.as_mut().unwrap();
                for (p, recursive) in &dirs {
                    if let Applied::Rebuild = live.apply_dir(p, *recursive) {
                        rebuild = true;
                    }
                }
                live.event_id = live.event_id.max(max_id);
                trees.append(&mut live.trees);
            }
            let (rec, flat): (Vec<_>, Vec<_>) = dirs.into_iter().partition(|(_, r)| *r);
            trees.extend(rec.into_iter().map(|(p, _)| p));
            let _ = shared.content_tx.send((flat.into_iter().map(|(p, _)| p).collect(), trees));
            if rebuild {
                log("history lost at /, rescanning");
                let id = unsafe { fsevents::FSEventsGetCurrentEventId() };
                let base = full_build(shared, id);
                *shared.live.write().unwrap() = Some(Live::new(base));
                let _ = shared.content_tx.send((Vec::new(), vec![shared.home.as_bytes().to_vec()]));
                last_save = Instant::now();
                continue;
            }
        }
        let (pending, stale) = {
            let g = shared.live.read().unwrap();
            let live = g.as_ref().unwrap();
            (live.over.len() + live.dead_count, live.event_id != live.base.event_id)
        };
        let asked = shared.save_requested.swap(false, Ordering::Relaxed);
        if asked || pending > COMPACT_PENDING || (stale && last_save.elapsed() > COMPACT_EVERY) {
            compact(shared);
            last_save = Instant::now();
        }
    }
}

fn handle(conn: UnixStream, shared: &Shared) {
    let Ok(r) = conn.try_clone() else { return };
    let mut w = std::io::BufWriter::new(conn);
    for line in BufReader::new(r).lines() {
        let Ok(line) = line else { return };
        if line.trim().is_empty() {
            continue;
        }
        let resp = respond(&line, shared);
        if writeln!(w, "{resp}").and_then(|_| w.flush()).is_err() {
            return;
        }
    }
}

fn respond(line: &str, shared: &Shared) -> Value {
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return json!({"ok": false, "error": format!("bad json: {e}")}),
    };
    let id = v.get("id").cloned().unwrap_or(Value::Null);
    let mut out = match run(&v, shared) {
        Ok(r) => r,
        Err(e) => json!({"ok": false, "error": e}),
    };
    out["id"] = id;
    out
}

fn run(v: &Value, shared: &Shared) -> Result<Value, String> {
    let op = v.get("op").and_then(Value::as_str).unwrap_or("search");
    if op == "ping" {
        return Ok(json!({"ok": true}));
    }
    if op == "save" {
        shared.save_requested.store(true, Ordering::Relaxed);
        let _ = shared.wake.send(Vec::new());
        return Ok(json!({"ok": true, "scheduled": true}));
    }
    // Content search reads files, which can be slow; it must not sit on the
    // name-index lock (a waiting writer would stall every other query).
    let is_grep = op == "grep"
        || (op == "search"
            && v.get("q").and_then(Value::as_str).is_some_and(|q| ["grep:", "regex:", "sym:", "content:", "symbol:"].iter().any(|k| q.contains(k))));
    if is_grep {
        return grep(v, shared);
    }
    let g = shared.live.read().unwrap();
    let Some(live) = g.as_ref() else { return Err("indexing (first run scans the whole disk, ~20s)".into()) };
    match op {
        "status" => Ok(json!({
            "ok": true,
            "entries": live.base.n,
            "dirs": live.base.d,
            "overlay": live.over.len(),
            "removed": live.dead_count,
            "event_id": live.event_id,
            "index_bytes": live.base.bytes(),
            "content_docs": shared.content.read().unwrap().docs(),
            "content_segments": shared.content.read().unwrap().segs.len(),
            "content_bytes": shared.content.read().unwrap().bytes(),
            "content_pending": shared.content_pending.load(Ordering::Relaxed),
            "full_disk_access": walk::SKIP.get().is_none(),
        })),
        "search" => {
            let q = parse_request(v, &shared.home)?;
            let t = Instant::now();
            let hits = Searcher { live }.search(&q);
            let took = t.elapsed().as_micros() as u64;
            let mut p = Vec::new();
            let hits: Vec<Value> = hits
                .iter()
                .map(|h| {
                    let (path, kind, size, mtime) = match &h.over {
                        Some(path) => {
                            let o = live.over[path];
                            (path.clone(), o.kind, o.size, o.mtime)
                        }
                        None => {
                            let i = h.idx as usize;
                            live.base.path(i, &mut p);
                            (p.clone(), live.base.kind()[i], live.base.size_of(i), live.base.mtime()[i])
                        }
                    };
                    json!({
                        "path": String::from_utf8_lossy(&path),
                        "kind": kind_name(kind),
                        "size": size,
                        "mtime": mtime,
                        "score": h.score,
                    })
                })
                .collect();
            Ok(json!({"ok": true, "took_us": took, "hits": hits}))
        }
        _ => Err(format!("unknown op {op}")),
    }
}

/// Content search. The pattern comes from `pattern` (+ `mode`) or from a
/// `grep:`/`regex:`/`sym:` filter in `q`; the rest of the query narrows
/// which files are read.
fn grep(v: &Value, shared: &Shared) -> Result<Value, String> {
    let mut q = parse_request(v, &shared.home)?;
    let mode = match v.get("mode").and_then(Value::as_str) {
        Some("regex") => GrepMode::Regex,
        Some("symbol") => GrepMode::Symbol,
        Some("literal") => GrepMode::Literal,
        Some(m) => return Err(format!("unknown mode {m}")),
        None => q.grep_mode,
    };
    let pattern = v.get("pattern").and_then(Value::as_str).map(str::to_string).or(q.grep.take()).ok_or("grep needs a pattern")?;
    let mut g = Grep::new(&pattern, mode)?;
    if let Some(n) = v.get("per_file").and_then(Value::as_u64) {
        g.max_per_file = n as usize;
    }
    if let Some(ms) = v.get("budget_ms").and_then(Value::as_u64) {
        g.budget = (ms > 0).then(|| Duration::from_millis(ms));
    }
    let t = Instant::now();
    let home = shared.home.as_bytes();
    let indexed = q.scope.as_ref().is_none_or(|s| content::in_scope(s, home));
    let r = if indexed {
        shared.content.read().unwrap().search(&g, &q)
    } else {
        // Pick files under the lock, read them after releasing it.
        let paths = {
            let g = shared.live.read().unwrap();
            let Some(live) = g.as_ref() else { return Err("indexing".into()) };
            content::scan_paths(live, q.clone_for_scan())
        };
        content::verify_owned(&g, paths, q.limit)
    };
    let files: Vec<Value> = r
        .files
        .iter()
        .map(|f| {
            json!({
                "path": String::from_utf8_lossy(&f.path),
                "matches": f.lines.iter().map(|(n, t)| json!({"line": n, "text": t})).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(json!({
        "ok": true,
        "took_us": t.elapsed().as_micros() as u64,
        "source": if indexed { "index" } else { "scan" },
        "candidates": r.candidates,
        "read": r.read,
        "complete": r.complete,
        "indexing": shared.content_pending.load(Ordering::Relaxed),
        "files": files,
    }))
}

/// `q` is the query language; any filter key may also be given as its own
/// JSON field (`{"q": "main", "ext": "rs", "in": "~/Developer"}`).
fn parse_request(v: &Value, home: &str) -> Result<Query, String> {
    let mut q = Query::parse(v.get("q").and_then(Value::as_str).unwrap_or(""), home)?;
    if let Some(obj) = v.as_object() {
        for (k, val) in obj {
            if k == "limit" {
                q.limit = val.as_u64().ok_or("limit must be a number")? as usize;
            } else if is_filter(k) {
                let s = match val {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                q.filter(k, &s, home)?;
            }
        }
    }
    Ok(q)
}

fn kind_name(k: u8) -> &'static str {
    match k & 3 {
        KIND_FILE => "file",
        KIND_DIR => "dir",
        KIND_LINK => "link",
        _ => "other",
    }
}

/// Connect to the daemon, starting it if it isn't running.
pub fn connect(dir: &Path) -> std::io::Result<UnixStream> {
    let sock = socket_path(dir);
    if let Ok(s) = UnixStream::connect(&sock) {
        return Ok(s);
    }
    let log = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("daemon.log"))?;
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    // Own session: closing the terminal that started it doesn't kill it.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd.arg("serve")
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()?;
    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(30));
        if let Ok(s) = UnixStream::connect(&sock) {
            return Ok(s);
        }
    }
    UnixStream::connect(&sock)
}
