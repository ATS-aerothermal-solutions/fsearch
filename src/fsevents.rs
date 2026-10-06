//! Whole-disk FSEvents stream, directory granularity, replayable by event id.

use std::ffi::{CStr, c_void};
use std::sync::mpsc::Sender;

pub const MUST_SCAN_SUBDIRS: u32 = 0x1;
pub const HISTORY_DONE: u32 = 0x10;
const CREATE_FLAG_IGNORE_SELF: u32 = 0x8;
const CREATE_FLAG_NO_DEFER: u32 = 0x2;

pub struct Event {
    pub path: Vec<u8>,
    pub flags: u32,
    pub id: u64,
}

#[repr(C)]
struct Context {
    version: isize,
    info: *mut c_void,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
}

type Callback = extern "C" fn(*mut c_void, *mut c_void, usize, *mut c_void, *const u32, *const u64);

#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn FSEventStreamCreate(
        alloc: *const c_void,
        cb: Callback,
        ctx: *const Context,
        paths: *const c_void,
        since: u64,
        latency: f64,
        flags: u32,
    ) -> *mut c_void;
    fn FSEventStreamSetDispatchQueue(s: *mut c_void, q: *mut c_void);
    fn FSEventStreamStart(s: *mut c_void) -> u8;
    pub fn FSEventsGetCurrentEventId() -> u64;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithCString(alloc: *const c_void, s: *const i8, enc: u32) -> *const c_void;
    fn CFArrayCreate(alloc: *const c_void, vals: *const *const c_void, n: isize, cbs: *const c_void) -> *const c_void;
    static kCFTypeArrayCallBacks: c_void;
}

unsafe extern "C" {
    fn dispatch_queue_create(label: *const i8, attr: *const c_void) -> *mut c_void;
}

extern "C" fn on_events(_s: *mut c_void, info: *mut c_void, n: usize, paths: *mut c_void, flags: *const u32, ids: *const u64) {
    let tx = unsafe { &*(info as *const Sender<Vec<Event>>) };
    let paths = paths as *const *const i8;
    let batch = (0..n)
        .map(|i| unsafe {
            Event { path: CStr::from_ptr(*paths.add(i)).to_bytes().to_vec(), flags: *flags.add(i), id: *ids.add(i) }
        })
        .collect();
    let _ = tx.send(batch);
}

/// Start watching `/` from `since` (an event id, or SINCE_NOW). Batches of
/// directory-level events arrive on `tx`; the stream lives for the process.
pub fn watch(since: u64, latency: f64, tx: Sender<Vec<Event>>) {
    unsafe {
        let root = CFStringCreateWithCString(std::ptr::null(), c"/".as_ptr(), 0x0800_0100);
        let arr = CFArrayCreate(std::ptr::null(), &root, 1, &kCFTypeArrayCallBacks as *const c_void);
        let ctx = Context {
            version: 0,
            info: Box::into_raw(Box::new(tx)) as *mut c_void,
            retain: std::ptr::null(),
            release: std::ptr::null(),
            copy_description: std::ptr::null(),
        };
        let s = FSEventStreamCreate(std::ptr::null(), on_events, &ctx, arr, since, latency, CREATE_FLAG_IGNORE_SELF | CREATE_FLAG_NO_DEFER);
        let q = dispatch_queue_create(c"fsearch.fsevents".as_ptr(), std::ptr::null());
        FSEventStreamSetDispatchQueue(s, q);
        FSEventStreamStart(s);
    }
}
