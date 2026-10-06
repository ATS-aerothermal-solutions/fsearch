//! The engine: owns the live name index, follows FSEvents, keeps the content
//! index current, and answers searches. The daemon runs one; so can any app
//! that links this crate.

use crate::content::{self, Content, Grep, GrepResult};
use crate::fsevents::{self, HISTORY_DONE, MUST_SCAN_SUBDIRS};
use crate::index::Index;
use crate::live::{Applied, Live};
use crate::query::{Query, Searcher};
use crate::walk;
use std::collections::HashMap;
use std::os::unix::ffi::OsStrExt;
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
const CONTENT_QUIET: Duration = Duration::from_secs(2);
const CONTENT_MAX_WAIT: Duration = Duration::from_secs(300);

pub struct Options {
    /// Where the index lives (`index.bin`, `content/`).
    pub dir: PathBuf,
    pub home: String,
    /// Folders never to open. `None` decides from Full Disk Access: without
    /// it, the consent-gated folders are skipped, since opening one pops a
    /// privacy prompt and blocks until someone answers it.
    pub skip: Option<Vec<PathBuf>>,
}

/// One name-search result.
pub struct Found {
    pub path: PathBuf,
    /// `walk::KIND_*` in the low 2 bits, `walk::FLAG_*` above.
    pub kind: u8,
    pub size: u64,
    pub mtime: u32,
    pub score: i32,
}

pub struct Status {
    pub ready: bool,
    pub entries: usize,
    pub dirs: usize,
    pub overlay: usize,
    pub removed: usize,
    pub event_id: u64,
    pub index_bytes: usize,
    pub content_docs: usize,
    pub content_segments: usize,
    pub content_bytes: usize,
    pub content_pending: usize,
    pub full_disk_access: bool,
}

#[derive(Clone)]
pub struct Engine {
    s: Arc<Shared>,
}

struct Shared {
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
    _lock: std::fs::File,
}

fn log(msg: impl AsRef<str>) {
    eprintln!("{} {}", crate::query::now_secs(), msg.as_ref());
}

/// Never let indexing download iCloud placeholders: on the calling thread,
/// opening or listing a dataless file fails fast instead of materializing it.
pub fn no_materialize() {
    unsafe extern "C" {
        fn setiopolicy_np(iotype: i32, scope: i32, policy: i32) -> i32;
    }
    // IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_THREAD, OFF
    unsafe { setiopolicy_np(3, 1, 1) };
}

fn spawn(name: &str, f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            no_materialize();
            f()
        })
        .expect("spawn");
}

impl Engine {
    /// Start indexing in the background and return at once; searches answer
    /// `Err` until the index is loaded (or, on the very first run, built).
    pub fn start(opts: Options) -> Result<Engine, String> {
        std::fs::create_dir_all(&opts.dir).map_err(|e| e.to_string())?;
        // One writer per index: a second one would race index writes. The
        // lock dies with the process.
        let lock = std::fs::File::create(opts.dir.join("daemon.lock")).map_err(|e| e.to_string())?;
        if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("another fsearch engine owns this index".into());
        }
        let skip: Vec<Vec<u8>> = match opts.skip {
            Some(v) => v.into_iter().map(|p| p.as_os_str().as_bytes().to_vec()).collect(),
            None if has_full_disk_access() && std::env::var_os("FSEARCH_RESTRICT").is_none() => Vec::new(),
            None => {
                log("no Full Disk Access: skipping consent-gated folders (grant it to fsearch to index everything)");
                gated(&opts.home)
            }
        };
        if !skip.is_empty() {
            let _ = walk::SKIP.set(skip);
        }
        let dir = opts.dir;
        let base = Index::load(&dir.join("index.bin"));
        // Watch before scanning so nothing that changes mid-scan is missed;
        // replaying it afterwards is harmless because diffs are idempotent.
        let since = match &base {
            Some(b) if b.event_id != 0 => b.event_id,
            _ => unsafe { fsevents::FSEventsGetCurrentEventId() },
        };
        let (tx, rx) = std::sync::mpsc::channel();
        fsevents::watch(since, 0.1, tx.clone());
        let (ctx, crx) = std::sync::mpsc::channel();
        let shared = Arc::new(Shared {
            live: RwLock::new(None),
            content: RwLock::new(Content::open(dir.join("content"))),
            home: opts.home,
            dir,
            wake: tx,
            save_requested: AtomicBool::new(false),
            content_tx: ctx,
            content_pending: AtomicUsize::new(0),
            _lock: lock,
        });
        let s = shared.clone();
        spawn("fsearch-apply", move || {
            let base = match base {
                Some(b) => {
                    log(format!("loaded {} entries, replaying events since {}", b.n, b.event_id));
                    b
                }
                None => full_build(&s, since),
            };
            *s.live.write().unwrap() = Some(Live::new(base));
            // Content: reconcile all of home once (cheap when nothing
            // changed), then follow along with the name index's changes.
            let _ = s.content_tx.send((Vec::new(), vec![s.home.as_bytes().to_vec()]));
            let s3 = s.clone();
            spawn("fsearch-content", move || content_loop(&s3, crx));
            apply_loop(&s, rx);
        });
        Ok(Engine { s: shared })
    }

    pub fn home(&self) -> &str {
        &self.s.home
    }

    /// Name search.
    pub fn search(&self, q: &Query) -> Result<Vec<Found>, String> {
        let g = self.s.live.read().unwrap();
        let Some(live) = g.as_ref() else { return Err(INDEXING.into()) };
        let mut p = Vec::new();
        Ok(Searcher { live }
            .search(q)
            .into_iter()
            .map(|h| {
                let (kind, size, mtime) = match &h.over {
                    Some(path) => {
                        let o = live.over[path];
                        p = path.clone();
                        (o.kind, o.size, o.mtime)
                    }
                    None => {
                        let i = h.idx as usize;
                        live.base.path(i, &mut p);
                        (live.base.kind()[i], live.base.size_of(i), live.base.mtime()[i])
                    }
                };
                Found { path: PathBuf::from(std::ffi::OsStr::from_bytes(&p)), kind, size, mtime, score: h.score }
            })
            .collect())
    }

    /// Content search: `g` is the pattern, `q` narrows which files are read.
    /// The bool says whether the content index answered (false: files were
    /// picked from the name index and read, for folders it doesn't cover).
    pub fn grep(&self, q: &Query, g: &Grep) -> Result<(GrepResult, bool), String> {
        let home = self.s.home.as_bytes();
        let indexed = q.scope.as_ref().is_none_or(|s| content::in_scope(s, home));
        if indexed {
            return Ok((self.s.content.read().unwrap().search(g, q), true));
        }
        // Pick files under the lock, read them after releasing it: reading can
        // be slow and a waiting writer would stall every other query.
        let paths = {
            let l = self.s.live.read().unwrap();
            let Some(live) = l.as_ref() else { return Err(INDEXING.into()) };
            content::scan_paths(live, q.clone_for_scan())
        };
        Ok((content::verify_owned(g, paths, q.limit), false))
    }

    pub fn status(&self) -> Status {
        let l = self.s.live.read().unwrap();
        let c = self.s.content.read().unwrap();
        Status {
            ready: l.is_some(),
            entries: l.as_ref().map_or(0, |l| l.base.n),
            dirs: l.as_ref().map_or(0, |l| l.base.d),
            overlay: l.as_ref().map_or(0, |l| l.over.len()),
            removed: l.as_ref().map_or(0, |l| l.dead_count),
            event_id: l.as_ref().map_or(0, |l| l.event_id),
            index_bytes: l.as_ref().map_or(0, |l| l.base.bytes()),
            content_docs: c.docs(),
            content_segments: c.segs.len(),
            content_bytes: c.bytes(),
            content_pending: self.s.content_pending.load(Ordering::Relaxed),
            full_disk_access: walk::SKIP.get().is_none(),
        }
    }

    /// Compact and save the name index soon (on the background thread).
    pub fn save(&self) {
        self.s.save_requested.store(true, Ordering::Relaxed);
        let _ = self.s.wake.send(Vec::new());
    }
}

const INDEXING: &str = "indexing (first run scans the whole disk, ~20s)";

/// Folders macOS guards with a consent prompt (or that hold other volumes).
pub fn gated(home: &str) -> Vec<Vec<u8>> {
    [
        format!("{home}/Desktop"),
        format!("{home}/Documents"),
        format!("{home}/Downloads"),
        format!("{home}/Library/Mobile Documents"),
        format!("{home}/Library/Containers"),
        format!("{home}/Library/Group Containers"),
        format!("{home}/Library/CloudStorage"),
        format!("{home}/Pictures/Photos Library.photoslibrary"),
        "/Volumes".to_string(),
    ]
    .into_iter()
    .map(String::into_bytes)
    .collect()
}

/// The system TCC database is readable only with Full Disk Access, and
/// trying without it fails immediately (no prompt).
pub fn has_full_disk_access() -> bool {
    std::fs::File::open("/Library/Application Support/com.apple.TCC/TCC.db").is_ok()
}

fn content_loop(shared: &Shared, rx: Receiver<(Vec<Vec<u8>>, Vec<Vec<u8>>)>) {
    // Indexing file contents is background work: utility QoS keeps it off
    // the user's way (lower CPU priority and IO tier).
    unsafe { libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_UTILITY, 0) };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .start_handler(|_| unsafe {
            libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_UTILITY, 0);
            no_materialize();
        })
        .build()
        .unwrap();
    let home = shared.home.as_bytes().to_vec();
    // Per-folder debounce: a folder is processed 2s after its last change,
    // or 5 min after its first pending one if it never goes quiet. A file you
    // save lands in ~2s; files apps rewrite every second (state, logs) cost
    // one reindex per 5 min instead of one per event batch.
    let mut pending: HashMap<(Vec<u8>, bool), (Instant, Instant)> = HashMap::new();
    loop {
        let wait = if pending.is_empty() { Duration::from_secs(3600) } else { Duration::from_millis(250) };
        match rx.recv_timeout(wait) {
            Ok((d, t)) => {
                let now = Instant::now();
                for key in d.into_iter().map(|p| (p, false)).chain(t.into_iter().map(|p| (p, true))) {
                    // Most of the disk's churn (Library, caches) is outside the indexed area.
                    if content::in_scope(&key.0, &home) || (key.1 && home.starts_with(&key.0)) {
                        pending.entry(key).and_modify(|e| e.1 = now).or_insert((now, now));
                    }
                }
                while let Ok((d, t)) = rx.try_recv() {
                    for key in d.into_iter().map(|p| (p, false)).chain(t.into_iter().map(|p| (p, true))) {
                        if content::in_scope(&key.0, &home) || (key.1 && home.starts_with(&key.0)) {
                            pending.entry(key).and_modify(|e| e.1 = now).or_insert((now, now));
                        }
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        let ripe: Vec<(Vec<u8>, bool)> = pending
            .iter()
            .filter(|(_, (first, last))| last.elapsed() >= CONTENT_QUIET || first.elapsed() >= CONTENT_MAX_WAIT)
            .map(|(k, _)| k.clone())
            .collect();
        if ripe.is_empty() {
            continue;
        }
        let (mut dirs, mut trees) = (Vec::<Vec<u8>>::new(), Vec::<Vec<u8>>::new());
        for k in ripe {
            pending.remove(&k);
            if k.1 { trees.push(k.0) } else { dirs.push(k.0) }
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

fn full_build(shared: &Shared, event_id: u64) -> Index {
    let t = Instant::now();
    let (ls, _) = walk::scan(b"/", SCAN_THREADS);
    let idx = Index::build(ls, event_id, shared.home.as_bytes());
    let path = shared.dir.join("index.bin");
    if let Err(e) = idx.save(&path) {
        log(format!("save failed: {e}"));
    }
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

/// Default data dir: `~/Library/Application Support/FSearch`.
pub fn default_dir(home: &str) -> PathBuf {
    Path::new(home).join("Library/Application Support/FSearch")
}
