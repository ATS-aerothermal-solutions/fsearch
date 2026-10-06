//! Name search: parse a query, scan the index in parallel, rank, top-k.

use crate::index::char_bit;
use crate::live::Live;
use crate::walk::{FLAG_HIDDEN, KIND_DIR, KIND_FILE, KIND_LINK};
use rayon::prelude::*;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Mode {
    Fuzzy,
    Exact,
    Prefix,
    Suffix,
}

#[derive(Debug)]
pub struct Token {
    pub text: Vec<u8>,
    pub mask: u64,
    pub mode: Mode,
    pub negate: bool,
}

#[derive(Default)]
pub struct Query {
    pub tokens: Vec<Token>,
    pub kind: Option<u8>,
    pub exts: Vec<Vec<u8>>,
    pub scope: Option<Vec<u8>>,
    pub size: (u64, u64),
    pub mtime: (u32, u32),
    pub name_re: Option<regex::bytes::Regex>,
    pub path_re: Option<regex::bytes::Regex>,
    pub limit: usize,
    /// Content search: handled by the content layer, carried here so one
    /// query string can say everything.
    pub grep: Option<String>,
    pub grep_mode: GrepMode,
}

#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub enum GrepMode {
    #[default]
    Literal,
    Regex,
    Symbol,
}

pub struct Hit {
    pub score: i32,
    /// Base entry, or u32::MAX for an overlay entry (then `over` is its path).
    pub idx: u32,
    pub over: Option<Vec<u8>>,
}

const TYPES: &[(&str, &[&str])] = &[
    ("image", &["png", "jpg", "jpeg", "gif", "heic", "heif", "webp", "tiff", "tif", "bmp", "svg", "raw", "cr2", "cr3", "nef", "arw", "dng", "psd", "ico", "icns", "avif", "jxl"]),
    ("video", &["mp4", "mov", "m4v", "mkv", "avi", "webm", "wmv", "flv", "mpg", "mpeg", "3gp", "hevc"]),
    ("audio", &["mp3", "m4a", "aac", "wav", "flac", "aiff", "aif", "ogg", "opus", "alac", "caf", "mid", "midi", "m4r"]),
    ("doc", &["pdf", "doc", "docx", "pages", "txt", "md", "rtf", "odt", "key", "ppt", "pptx", "numbers", "xls", "xlsx", "csv", "epub", "tex"]),
    ("code", &["rs", "c", "h", "cc", "cpp", "hpp", "m", "mm", "swift", "go", "py", "js", "mjs", "cjs", "ts", "tsx", "jsx", "java", "kt", "rb", "php", "cs", "sh", "zsh", "bash", "fish", "lua", "sql", "html", "css", "scss", "json", "yaml", "yml", "toml", "xml", "vue", "svelte", "zig", "nim", "hs", "ml", "ex", "exs", "erl", "clj", "dart", "r", "jl", "metal", "glsl", "wgsl", "proto", "graphql", "nix"]),
    ("archive", &["zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "dmg", "pkg", "iso", "zst", "lz4", "xip"]),
    ("font", &["ttf", "otf", "woff", "woff2", "ttc", "dfont"]),
];

impl Query {
    /// Parse the human query language. Plain words are fuzzy tokens;
    /// `'x` exact, `^x` prefix, `x$` suffix, `!x` negate; filters are
    /// `ext: type: kind: in: size: mtime: re: path: limit: grep: regex: sym:`.
    pub fn parse(s: &str, home: &str) -> Result<Query, String> {
        let mut q = Query { size: (0, u64::MAX), mtime: (0, u32::MAX), limit: 50, ..Default::default() };
        for word in split_words(s) {
            if let Some((k, v)) = word.split_once(':').filter(|(k, _)| is_filter(k)) {
                q.filter(k, v, home)?;
                continue;
            }
            for piece in word.split('/').filter(|p| !p.is_empty()) {
                q.push_token(piece);
            }
        }
        Ok(q)
    }

    pub fn push_token(&mut self, w: &str) {
        let (mut t, mut negate, mut mode) = (w, false, Mode::Fuzzy);
        if let Some(r) = t.strip_prefix('!') {
            (t, negate, mode) = (r, true, Mode::Exact);
        }
        if let Some(r) = t.strip_prefix('\'') {
            (t, mode) = (r, Mode::Exact);
        } else if let Some(r) = t.strip_prefix('^') {
            (t, mode) = (r, Mode::Prefix);
        } else if let Some(r) = t.strip_suffix('$') {
            (t, mode) = (r, Mode::Suffix);
        }
        // Positive tokens are tracked in a u8 bitset.
        if t.is_empty() || (!negate && self.tokens.iter().filter(|t| !t.negate).count() >= 8) {
            return;
        }
        let text: Vec<u8> = t.bytes().map(|b| b.to_ascii_lowercase()).collect();
        let mask = text.iter().fold(0, |m, &b| m | char_bit(b));
        self.tokens.push(Token { text, mask, mode, negate });
    }

    pub fn filter(&mut self, k: &str, v: &str, home: &str) -> Result<(), String> {
        match k {
            "ext" => self.exts.extend(v.split(',').map(|e| e.trim_start_matches('.').to_ascii_lowercase().into_bytes())),
            "type" => {
                for t in v.split(',') {
                    if t == "app" {
                        self.kind = Some(KIND_DIR);
                        self.exts.push(b"app".to_vec());
                        continue;
                    }
                    let (_, exts) = TYPES.iter().find(|(n, _)| *n == t).ok_or(format!("unknown type {t}"))?;
                    self.exts.extend(exts.iter().map(|e| e.as_bytes().to_vec()));
                }
            }
            "kind" => {
                self.kind = Some(match v {
                    "file" | "f" => KIND_FILE,
                    "dir" | "folder" | "d" => KIND_DIR,
                    "link" | "symlink" | "l" => KIND_LINK,
                    _ => return Err(format!("unknown kind {v}")),
                })
            }
            "in" => {
                let p = v.strip_prefix('~').map_or(v.to_string(), |r| format!("{home}{r}"));
                // The index holds real paths: /etc is /private/etc.
                let p = std::fs::canonicalize(&p).map_or(p, |c| c.to_string_lossy().into_owned());
                self.scope = Some(p.trim_end_matches('/').as_bytes().to_vec());
            }
            "size" => self.size = range(v, parse_size)?,
            "mtime" | "modified" => {
                // mtime:<7d means "modified within the last 7 days".
                let now = now_secs();
                let (lo, hi) = range(v, parse_age)?;
                self.mtime = (now.saturating_sub(hi.min(now as u64) as u32), now.saturating_sub(lo as u32));
                if hi == u64::MAX {
                    self.mtime.0 = 0;
                }
            }
            "re" => self.name_re = Some(regex::bytes::Regex::new(&format!("(?i){v}")).map_err(|e| e.to_string())?),
            "path" => self.path_re = Some(regex::bytes::Regex::new(&format!("(?i){v}")).map_err(|e| e.to_string())?),
            "limit" => self.limit = v.parse().map_err(|_| "bad limit")?,
            "grep" | "content" => (self.grep, self.grep_mode) = (Some(v.to_string()), GrepMode::Literal),
            "regex" => (self.grep, self.grep_mode) = (Some(v.to_string()), GrepMode::Regex),
            "sym" | "symbol" => (self.grep, self.grep_mode) = (Some(v.to_string()), GrepMode::Symbol),
            _ => unreachable!(),
        }
        Ok(())
    }
}

impl Query {
    /// The parts of a query that pick files for a content scan.
    pub fn clone_for_scan(&self) -> Query {
        Query {
            tokens: self.tokens.iter().map(|t| Token { text: t.text.clone(), mask: t.mask, mode: t.mode, negate: t.negate }).collect(),
            kind: self.kind,
            exts: self.exts.clone(),
            scope: self.scope.clone(),
            size: self.size,
            mtime: self.mtime,
            name_re: self.name_re.clone(),
            path_re: self.path_re.clone(),
            limit: self.limit,
            grep: None,
            grep_mode: self.grep_mode,
        }
    }

    /// Does a full path pass every filter and token? Returns the match score.
    /// Used where there is no dir memo: the overlay and content-search docs.
    pub fn match_path(&self, path: &[u8], kind: u8, size: u64, mtime: u32) -> Option<i32> {
        if let Some(s) = &self.scope {
            if !(path.starts_with(s) && path.get(s.len()) == Some(&b'/')) {
                return None;
            }
        }
        let cut = path.iter().rposition(|&b| b == b'/').unwrap_or(0);
        let name = &path[cut + 1..];
        if name.is_empty()
            || self.kind.is_some_and(|k| kind & 3 != k)
            || (!self.exts.is_empty() && !ext_ok(name, &self.exts))
            || size < self.size.0
            || size > self.size.1
            || mtime < self.mtime.0
            || mtime > self.mtime.1
        {
            return None;
        }
        // A hit needs some token in its own name; most overlay paths fail
        // here, before the path is split into folders.
        let mut pos = self.tokens.iter().filter(|t| !t.negate).peekable();
        let m = crate::index::char_mask(name);
        if pos.peek().is_some() && !pos.any(|t| m & t.mask == t.mask && token_score(name, t).is_some()) {
            return None;
        }
        let dirs: Vec<&[u8]> = path[..cut].split(|&b| b == b'/').filter(|c| !c.is_empty()).collect();
        if self.tokens.iter().any(|t| t.negate && (token_matches(name, t) || dirs.iter().any(|d| token_matches(d, t)))) {
            return None;
        }
        let pos: Vec<&Token> = self.tokens.iter().filter(|t| !t.negate).collect();
        let all = (1u32 << pos.len()) - 1;
        let (mut got, mut inherited, mut score) = (0u32, 0u32, 0i32);
        for (t, tok) in pos.iter().enumerate() {
            if let Some(s) = token_score(name, tok) {
                got |= 1 << t;
                score += s;
            } else if let Some(s) = dirs.iter().filter_map(|d| token_score(d, tok)).max() {
                inherited |= 1 << t;
                score += s * 3 / 4;
            }
        }
        if !pos.is_empty() && (got == 0 || (got | inherited) != all) {
            return None;
        }
        if self.name_re.as_ref().is_some_and(|re| !re.is_match(name)) || self.path_re.as_ref().is_some_and(|re| !re.is_match(path)) {
            return None;
        }
        Some(score)
    }
}

pub fn is_filter(k: &str) -> bool {
    matches!(
        k,
        "ext" | "type" | "kind" | "in" | "size" | "mtime" | "modified" | "re" | "path" | "limit" | "grep" | "content" | "regex" | "sym" | "symbol"
    )
}

/// Split on spaces, keeping "double quoted" runs together.
fn split_words(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut quoted) = (Vec::new(), String::new(), false);
    for c in s.chars() {
        match c {
            '"' => quoted = !quoted,
            ' ' if !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn range(v: &str, p: fn(&str) -> Option<u64>) -> Result<(u64, u64), String> {
    let bad = || format!("bad range {v}");
    if let Some(r) = v.strip_prefix(">=").or(v.strip_prefix('>')) {
        return Ok((p(r).ok_or_else(bad)?, u64::MAX));
    }
    if let Some(r) = v.strip_prefix("<=").or(v.strip_prefix('<')) {
        return Ok((0, p(r).ok_or_else(bad)?));
    }
    if let Some((a, b)) = v.split_once("..") {
        return Ok((p(a).ok_or_else(bad)?, p(b).ok_or_else(bad)?));
    }
    let x = p(v).ok_or_else(bad)?;
    Ok((x, x))
}

fn split_unit(s: &str) -> (f64, String) {
    let i = s.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(s.len());
    (s[..i].parse().unwrap_or(f64::NAN), s[i..].to_ascii_lowercase())
}

fn parse_size(s: &str) -> Option<u64> {
    let (n, u) = split_unit(s);
    let m = match u.as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1e3,
        "m" | "mb" => 1e6,
        "g" | "gb" => 1e9,
        "t" | "tb" => 1e12,
        _ => return None,
    };
    (!n.is_nan()).then(|| (n * m) as u64)
}

fn parse_age(s: &str) -> Option<u64> {
    let (n, u) = split_unit(s);
    let m = match u.as_str() {
        "s" => 1.0,
        "m" | "min" => 60.0,
        "h" => 3600.0,
        "" | "d" => 86400.0,
        "w" => 604800.0,
        "mo" => 2592000.0,
        "y" => 31536000.0,
        _ => return None,
    };
    (!n.is_nan()).then(|| (n * m) as u64)
}

pub fn now_secs() -> u32 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as u32)
}

#[inline(always)]
fn fold(b: u8) -> u8 {
    b | (((b.wrapping_sub(b'A') < 26) as u8) << 5)
}

#[inline(always)]
fn is_subseq(name: &[u8], q: &[u8]) -> bool {
    let mut j = 0;
    for &b in name {
        if fold(b) == q[j] {
            j += 1;
            if j == q.len() {
                return true;
            }
        }
    }
    false
}

fn find_ci(name: &[u8], q: &[u8]) -> Option<usize> {
    if q.len() > name.len() {
        return None;
    }
    (0..=name.len() - q.len()).find(|&i| name[i..i + q.len()].iter().zip(q).all(|(&a, &b)| fold(a) == b))
}

#[derive(Clone, Copy, PartialEq)]
enum Class {
    Lower,
    Upper,
    Digit,
    Delim,
    Other,
}

#[inline(always)]
fn class(b: u8) -> Class {
    match b {
        b'a'..=b'z' => Class::Lower,
        b'A'..=b'Z' => Class::Upper,
        b'0'..=b'9' => Class::Digit,
        b' ' | b'_' | b'-' | b'.' | b'/' | b'(' | b')' | b'[' | b']' | b',' | b'+' | b'@' => Class::Delim,
        _ => Class::Other,
    }
}

const SCORE_MATCH: i32 = 16;
const GAP_START: i32 = -3;
const GAP_EXT: i32 = -1;
const BONUS_BOUNDARY: i32 = 8;
const BONUS_CAMEL: i32 = 7;
const BONUS_CONSEC: i32 = 4;

#[inline(always)]
fn bonus(prev: Class, cur: Class) -> i32 {
    match (prev, cur) {
        (Class::Delim, c) if c != Class::Delim => BONUS_BOUNDARY,
        (Class::Lower, Class::Upper) | (Class::Lower | Class::Upper, Class::Digit) => BONUS_CAMEL,
        _ => 0,
    }
}

/// fzf-v1 style: leftmost-ending match, shrunk from the right, then scored
/// with boundary/camel/consecutive bonuses. Returns None when no match.
pub fn fuzzy_score(name: &[u8], q: &[u8]) -> Option<i32> {
    // Leftmost-ending match: jump to each query byte in turn (memchr is
    // SIMD; most names fail on the first or second byte).
    let mut end = 0;
    let mut from = 0;
    for &c in q {
        end = from + find_folded(&name[from..], c)?;
        from = end + 1;
    }
    if q.len() == 1 {
        return Some(single_score(name, end));
    }
    // Shrink from the right: the latest start that still ends at `end`.
    let mut start = end + 1;
    for &c in q.iter().rev() {
        start = rfind_folded(&name[..start], c)?;
    }
    // Score the greedy match from `start`, jumping between matched bytes:
    // each gap costs GAP_START then GAP_EXT per byte, a run of consecutive
    // matches carries its strongest boundary bonus along.
    let mut score = 0;
    let (mut at, mut first_bonus) = (start, 0);
    for (k, &c) in q.iter().enumerate() {
        let mut run = false;
        if k > 0 {
            let last = at;
            at = last + 1 + find_folded(&name[last + 1..=end], c)?;
            run = at == last + 1;
            if !run {
                score += GAP_START + (at - last - 2) as i32 * GAP_EXT;
            }
        }
        let prev = if at == 0 { Class::Delim } else { class(name[at - 1]) };
        let mut b = bonus(prev, class(name[at]));
        if run {
            if b >= BONUS_BOUNDARY && b > first_bonus {
                first_bonus = b;
            }
            b = b.max(first_bonus).max(BONUS_CONSEC);
        } else {
            first_bonus = b;
        }
        score += SCORE_MATCH + if k == 0 { b * 2 } else { b };
    }
    // Whole-name and stem matches are what people mean most of the time. A
    // leading dot doesn't count: "zshrc" means ~/.zshrc.
    let off = (name.len() > 1 && name[0] == b'.') as usize;
    let stem = name.iter().rposition(|&b| b == b'.').filter(|&p| p > off).unwrap_or(name.len());
    let contiguous = end + 1 - start == q.len();
    if start == off && contiguous && end + 1 == name.len() {
        score += 100;
    } else if start == off && contiguous && end + 1 == stem {
        score += 80;
    } else if start == off && contiguous {
        score += 30;
    }
    Some(score - (name.len() as i32).min(80) / 3)
}

/// First byte of `s` that folds to `c` (an already-lowercased query byte).
#[inline(always)]
fn find_folded(s: &[u8], c: u8) -> Option<usize> {
    if c.is_ascii_lowercase() { memchr::memchr2(c, c - 32, s) } else { memchr::memchr(c, s) }
}

/// Last byte of `s` that folds to `c`.
#[inline(always)]
fn rfind_folded(s: &[u8], c: u8) -> Option<usize> {
    if c.is_ascii_lowercase() { memchr::memrchr2(c, c - 32, s) } else { memchr::memrchr(c, s) }
}

/// `fuzzy_score` for a one-byte query matched at `i`: the general scoring
/// loop collapses to one step.
#[inline]
fn single_score(name: &[u8], i: usize) -> i32 {
    let prev = if i == 0 { Class::Delim } else { class(name[i - 1]) };
    let mut score = SCORE_MATCH + bonus(prev, class(name[i])) * 2;
    let off = (name.len() > 1 && name[0] == b'.') as usize;
    if i == off {
        let stem = name.iter().rposition(|&b| b == b'.').filter(|&p| p > off).unwrap_or(name.len());
        score += if i + 1 == name.len() {
            100
        } else if i + 1 == stem {
            80
        } else {
            30
        };
    }
    score - (name.len() as i32).min(80) / 3
}

/// Score a token against a name, honoring its mode.
#[inline]
fn token_score(name: &[u8], t: &Token) -> Option<i32> {
    match t.mode {
        Mode::Fuzzy => fuzzy_score(name, &t.text),
        Mode::Exact => find_ci(name, &t.text).map(|p| 40 + if p == 0 { 30 } else { 0 } - (name.len() as i32).min(80) / 3),
        Mode::Prefix => (name.len() >= t.text.len() && name.iter().zip(&t.text).all(|(&a, &b)| fold(a) == b))
            .then(|| 60 - (name.len() as i32).min(80) / 3),
        Mode::Suffix => (name.len() >= t.text.len() && name[name.len() - t.text.len()..].iter().zip(&t.text).all(|(&a, &b)| fold(a) == b))
            .then(|| 50 - (name.len() as i32).min(80) / 3),
    }
}

#[inline]
fn token_matches(name: &[u8], t: &Token) -> bool {
    match t.mode {
        Mode::Fuzzy => is_subseq(name, &t.text),
        _ => token_score(name, t).is_some(),
    }
}

/// Top k by (score, then lower entry index): a total order, so the result
/// does not depend on which thread saw which entry first.
struct TopK {
    k: usize,
    heap: BinaryHeap<Reverse<u64>>,
}

#[inline(always)]
fn key(score: i32, i: u32) -> u64 {
    (((score as i64 - i32::MIN as i64) as u64) << 32) | (!i) as u64
}

impl TopK {
    fn new(k: usize) -> TopK {
        TopK { k, heap: BinaryHeap::with_capacity(k + 1) }
    }
    /// Keys at or below this cannot get in.
    #[inline]
    fn floor(&self) -> u64 {
        if self.heap.len() < self.k { 0 } else { self.heap.peek().map_or(u64::MAX, |r| r.0) }
    }
    #[inline]
    fn push(&mut self, key: u64) {
        if self.heap.len() < self.k {
            self.heap.push(Reverse(key));
        } else if key > self.floor() {
            self.heap.pop();
            self.heap.push(Reverse(key));
        }
    }
}

/// Top `k` over `0..n` items: a few contiguous pieces per thread, each with
/// its own heap, then one selection over their survivors (merging heaps
/// pairwise costs more than the scan when `k` is large).
fn top_k(n: usize, k: usize, visit: impl Fn(std::ops::Range<usize>, &mut TopK) + Sync) -> Vec<Hit> {
    let pieces = (rayon::current_num_threads() * 4).min(n.max(1));
    let step = n.div_ceil(pieces).max(1);
    let mut keys: Vec<u64> = (0..pieces)
        .into_par_iter()
        .map(|p| {
            let mut top = TopK::new(k);
            visit((p * step).min(n)..((p + 1) * step).min(n), &mut top);
            top.heap.into_iter().map(|Reverse(x)| x).collect::<Vec<_>>()
        })
        .flatten_iter()
        .collect();
    if keys.len() > k {
        if k == 0 {
            return Vec::new();
        }
        keys.select_nth_unstable_by(k - 1, |a, b| b.cmp(a));
        keys.truncate(k);
    }
    keys.into_iter().map(|x| Hit { score: ((x >> 32) as i64 + i32::MIN as i64) as i32, idx: !(x as u32), over: None }).collect()
}

fn ext_ok(name: &[u8], exts: &[Vec<u8>]) -> bool {
    let Some(dot) = name.iter().rposition(|&b| b == b'.') else { return false };
    let e = &name[dot + 1..];
    exts.iter().any(|x| x.len() == e.len() && x.iter().zip(e).all(|(&a, &b)| a == fold(b)))
}

/// Below this many entries carrying a matching name, a query visits just
/// those entries (via the name -> entries list) instead of every entry.
const SELECTIVE: usize = 60_000;
/// Name ids per parallel chunk when scoring names.
const NAME_CHUNK: usize = 1 << 15;

pub struct Searcher<'a> {
    pub live: &'a Live,
}

impl Searcher<'_> {
    /// Entry range to scan, from the `in:` scope.
    pub fn scope_range(&self, q: &Query) -> Option<(usize, usize)> {
        let idx = &self.live.base;
        let Some(scope) = &q.scope else { return Some((1, idx.n)) };
        let e = idx.lookup(scope)?;
        let d = idx.dir_of(e)? as usize;
        Some((idx.dir_start()[d] as usize, idx.dir_end()[d] as usize))
    }

    pub fn search(&self, q: &Query) -> Vec<Hit> {
        let mut hits = self.search_base(q);
        hits.extend(self.search_overlay(q));
        hits.sort_by(|a, b| b.score.cmp(&a.score).then(a.idx.cmp(&b.idx)));
        hits.truncate(q.limit);
        hits
    }

    fn search_base(&self, q: &Query) -> Vec<Hit> {
        let Some((lo, hi)) = self.scope_range(q) else { return Vec::new() };
        let pos: Vec<&Token> = q.tokens.iter().filter(|t| !t.negate).collect();
        let neg: Vec<&Token> = q.tokens.iter().filter(|t| t.negate).collect();
        // Step 1: every name-only predicate, once per distinct name (~2M)
        // rather than once per entry (~7.5M); reused while you type.
        let scored = self.names(q, &pos, &neg);
        let s = Scan { q, live: self.live, names: &scored.names, npos: pos.len(), need_dirs: pos.len() > 1 || !neg.is_empty(), now: now_secs() };
        // Step 2: score entries. Few candidates: just the entries carrying a
        // matching name. Many: one sequential pass over every entry.
        if scored.names.ok_entries <= SELECTIVE && !FULL_PASS.load(std::sync::atomic::Ordering::Relaxed) {
            return s.selective(lo, hi);
        }
        let memo = if s.need_dirs { Some(scored.memo.get_or_init(|| self.dir_tokens(&scored.names))) } else { None };
        s.full(lo, hi, memo.map(|m| m.as_slice()))
    }

    /// The name table for this query: cached for a repeat of the last one
    /// (the second, longer page of results), narrowed from the last one when
    /// this query only extends it (typing), else scored from scratch.
    fn names(&self, q: &Query, pos: &[&Token], neg: &[&Token]) -> std::sync::Arc<Scored> {
        let key = NameKey::of(q);
        let prev = self.live.names_cache.0.lock().unwrap().clone();
        if let Some(p) = &prev {
            if p.key == key {
                return p.clone();
            }
        }
        let from = prev.as_ref().filter(|p| key.narrows(&p.key)).map(|p| &p.names);
        let scored = std::sync::Arc::new(Scored { at: std::time::Instant::now(), key, names: self.score_names(q, pos, neg, from), memo: std::sync::OnceLock::new() });
        *self.live.names_cache.0.lock().unwrap() = Some(scored.clone());
        scored
    }

    /// Score distinct names against the query's name-only predicates: every
    /// name, or only the ones `from` matched. Matches come back sparse (plus
    /// a 256 KB membership bitset), so a selective query never touches a
    /// table the size of the name count.
    fn score_names(&self, q: &Query, pos: &[&Token], neg: &[&Token], from: Option<&NameTable>) -> NameTable {
        let idx = &self.live.base;
        let mask = idx.name_mask();
        let ne_off = idx.name_ents_off();
        let score_one = |k: usize, ok_entries: &mut usize| -> Option<NameHit> {
            let m = mask[k];
            if !(pos.is_empty() || pos.iter().any(|t| m & t.mask == t.mask)) && neg.is_empty() {
                return None;
            }
            let name = idx.uname(k as u32);
            let mut h = NameHit { score: 0, bits: 0, flags: name_flags(name), best: [0; 4] };
            for (t, tok) in pos.iter().enumerate() {
                if m & tok.mask == tok.mask {
                    if let Some(s) = token_score(name, tok) {
                        h.bits |= 1 << t;
                        let s16 = s.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
                        h.score = h.score.saturating_add(s16);
                        if t < 4 {
                            h.best[t] = s16.max(0);
                        }
                    }
                }
            }
            if neg.iter().any(|t| token_matches(name, t)) {
                h.flags |= NF_NEG;
            }
            // As a file match it must hit a token and pass name filters;
            // as a folder on someone's path, the raw token bits matter.
            let ok = (pos.is_empty() || h.bits != 0)
                && h.flags & NF_NEG == 0
                && (q.exts.is_empty() || ext_ok(name, &q.exts))
                && q.name_re.as_ref().is_none_or(|re| re.is_match(name));
            if ok {
                h.flags |= NF_OK;
                *ok_entries += (ne_off[k + 1] - ne_off[k]) as usize;
            }
            (ok || h.bits != 0 || h.flags & NF_NEG != 0).then_some(h)
        };
        // Each chunk of name ids writes its own slice of the bitset and of a
        // reused dense table. Slots without their bit set are never read, so
        // the table is never cleared (and never page-faulted in again).
        let mut bits = vec![0u64; idx.u.div_ceil(64)];
        let mut dense = DENSE_POOL.lock().unwrap().pop().filter(|d| d.len() == idx.u).unwrap_or_else(|| vec![NameHit::NONE; idx.u]);
        let counts: Vec<(usize, usize)> = dense
            .par_chunks_mut(NAME_CHUNK)
            .zip(bits.par_chunks_mut(NAME_CHUNK / 64))
            .enumerate()
            .map(|(c, (slots, words))| {
                let (a, b) = (c * NAME_CHUNK, ((c + 1) * NAME_CHUNK).min(idx.u));
                let (mut n, mut ok) = (0usize, 0usize);
                let mut put = |k: usize, h: NameHit| {
                    slots[k - a] = h;
                    words[(k - a) >> 6] |= 1 << (k & 63);
                    n += 1;
                };
                match from {
                    Some(f) => {
                        for w in a / 64..b.div_ceil(64) {
                            let mut m = f.bits[w];
                            while m != 0 {
                                let k = w * 64 + m.trailing_zeros() as usize;
                                if let Some(h) = score_one(k, &mut ok) {
                                    put(k, h);
                                }
                                m &= m - 1;
                            }
                        }
                    }
                    None => {
                        for k in a..b {
                            if let Some(h) = score_one(k, &mut ok) {
                                put(k, h);
                            }
                        }
                    }
                }
                (n, ok)
            })
            .collect();
        let ok_entries = counts.iter().map(|c| c.1).sum();
        let total: usize = counts.iter().map(|c| c.0).sum();
        let mut t = NameTable { bits, sparse: Vec::new(), dense: Some(dense), ok_entries };
        if total <= 1 << 16 {
            // Few matches: keep a compact copy and give the big table back.
            t.sparse = t.iter().collect();
            DENSE_POOL.lock().unwrap().push(t.dense.take().unwrap());
        }
        t
    }

    /// The overlay is small (entries added since the last compaction), so a
    /// straight scan with path components standing in for the dir memo.
    fn search_overlay(&self, q: &Query) -> Vec<Hit> {
        let idx = &self.live.base;
        let now = now_secs();
        let mut out = Vec::new();
        for (path, o) in &self.live.over {
            let Some(mut score) = q.match_path(path, o.kind, o.size, o.mtime) else { continue };
            let cut = path.iter().rposition(|&b| b == b'/').unwrap_or(0);
            // Prior of the nearest ancestor the base knows about.
            let mut prior = 0;
            let mut up = &path[..cut];
            while !up.is_empty() {
                if let Some(d) = idx.lookup(up).and_then(|e| idx.dir_of(e)) {
                    prior = idx.dir_prior()[d as usize] as i32;
                    break;
                }
                up = &up[..up.iter().rposition(|&b| b == b'/').unwrap_or(0)];
            }
            score += prior + rank_tweaks(name_flags(&path[cut + 1..]), o.kind, o.mtime, now);
            out.push(Hit { score, idx: u32::MAX, over: Some(path.clone()) });
        }
        out
    }

    /// For each dir: which tokens its name or an ancestor's matches, with the
    /// best score per token (first 4); bits == u32::MAX if a negated token does.
    fn dir_tokens(&self, names: &NameTable) -> Vec<DirMemo> {
        let idx = &self.live.base;
        let de = idx.dir_entry();
        let en = idx.ent_name();
        let mut out = MEMO_POOL.lock().unwrap().pop().unwrap_or_default();
        out.clear();
        out.resize(idx.d, DirMemo::default());
        out.par_iter_mut().enumerate().with_min_len(1 << 12).for_each(|(k, slot)| {
            if k > 0 {
                *slot = DirMemo::own(names, en[de[k] as usize]);
            }
        });
        // Fold ancestors in, parents first. A dir's descendants are one
        // contiguous id range, so the children of huge dirs go one by one,
        // then every small subtree in parallel.
        let dp = idx.dir_parent();
        let plan = idx.memo_plan();
        for &k in &plan.upper {
            out[k as usize] = out[k as usize].under(out[dp[k as usize] as usize]);
        }
        let roots: Vec<(u32, DirMemo)> = plan.chunks.iter().map(|(c, _)| (*c, out[*c as usize])).collect();
        let mut slices = Vec::with_capacity(plan.chunks.len());
        let mut rest: &mut [DirMemo] = &mut out;
        let mut at = 0usize;
        for (_, r) in &plan.chunks {
            let (_, tail) = std::mem::take(&mut rest).split_at_mut(r.start as usize - at);
            let (mine, tail) = tail.split_at_mut((r.end - r.start) as usize);
            slices.push(mine);
            rest = tail;
            at = r.end as usize;
        }
        slices.into_par_iter().zip(&plan.chunks).zip(roots).for_each(|((slice, (_, r)), (c, root))| {
            let a = r.start as usize;
            for k in a..r.end as usize {
                let p = dp[k];
                let pm = if p == c { root } else { slice[p as usize - a] };
                slice[k - a] = slice[k - a].under(pm);
            }
        });
        out
    }
}

/// Debug switch: always take the full pass (for checking the selective one).
pub static FULL_PASS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// One query's entry scoring, shared by the two strategies.
struct Scan<'a> {
    q: &'a Query,
    live: &'a Live,
    names: &'a NameTable,
    npos: usize,
    need_dirs: bool,
    now: u32,
}

impl Scan<'_> {
    /// Score entry `i` whose name scored `nh`, given its parent's memo.
    /// `None` if it fails a filter or cannot beat `floor`.
    #[inline(always)]
    fn score(&self, i: usize, nh: NameHit, memo: DirMemo, floor: u64, pbuf: &mut Vec<u8>) -> Option<u64> {
        let idx = &self.live.base;
        let q = self.q;
        let k = idx.kind()[i];
        if q.kind.is_some_and(|want| k & 3 != want) {
            return None;
        }
        if q.size != (0, u64::MAX) {
            let sz = crate::index::dec_size(idx.size_raw()[i]);
            if sz < q.size.0 || sz > q.size.1 {
                return None;
            }
        }
        let mtime = idx.mtime()[i];
        if q.mtime != (0, u32::MAX) && (mtime < q.mtime.0 || mtime > q.mtime.1) {
            return None;
        }
        let mut score = nh.score as i32;
        if self.need_dirs {
            let all = (1u32 << self.npos) - 1;
            if memo.bits == u32::MAX || (nh.bits as u32 | memo.bits) & all != all {
                return None;
            }
            for t in 0..self.npos {
                if nh.bits & (1 << t) == 0 {
                    // Matched by a folder on the path instead.
                    score += memo.best.get(t).map_or(6, |&b| b as i32 * 3 / 4);
                }
            }
        }
        if self.live.is_dead(i as u32) {
            return None;
        }
        let p = idx.parent()[i] as usize;
        score += idx.dir_prior()[p] as i32 + rank_tweaks(nh.flags, k, mtime, self.now);
        let key = key(score, i as u32);
        if key <= floor {
            return None;
        }
        if let Some(re) = &q.path_re {
            idx.path(i, pbuf);
            if !re.is_match(pbuf) {
                return None;
            }
        }
        Some(key)
    }

    /// One sequential pass over every entry in `lo..hi`.
    fn full(&self, lo: usize, hi: usize, memo: Option<&[DirMemo]>) -> Vec<Hit> {
        let idx = &self.live.base;
        let (ent_name, parent) = (idx.ent_name(), idx.parent());
        top_k(hi - lo, self.q.limit, |r, top| {
            let mut pbuf = Vec::new();
            for i in lo + r.start..lo + r.end {
                let Some(nh) = self.names.get(ent_name[i]).filter(|h| h.flags & NF_OK != 0) else { continue };
                let m = memo.map_or(DirMemo::default(), |m| m[parent[i] as usize]);
                if let Some(k) = self.score(i, nh, m, top.floor(), &mut pbuf) {
                    top.push(k);
                }
            }
        })
    }

    /// Visit only the entries carrying a matching name; folder tokens are
    /// checked by walking each candidate's ancestors (memoized per piece).
    fn selective(&self, lo: usize, hi: usize) -> Vec<Hit> {
        let idx = &self.live.base;
        let (ne_off, ne, parent) = (idx.name_ents_off(), idx.name_ents(), idx.parent());
        let ok: Vec<(u32, NameHit)> = self.names.iter().filter(|(_, h)| h.flags & NF_OK != 0).collect();
        top_k(ok.len(), self.q.limit, |r, top| {
            let (mut pbuf, mut memo) = (Vec::new(), HashMap::<u32, DirMemo, crate::index::Fx>::default());
            for &(id, nh) in &ok[r] {
                for &e in &ne[ne_off[id as usize] as usize..ne_off[id as usize + 1] as usize] {
                    let i = e as usize;
                    if i < lo || i >= hi {
                        continue;
                    }
                    let m = if self.need_dirs { self.memo_of(parent[i], &mut memo) } else { DirMemo::default() };
                    if let Some(k) = self.score(i, nh, m, top.floor(), &mut pbuf) {
                        top.push(k);
                    }
                }
            }
        })
    }

    /// The dir memo of `d` (see `dir_tokens`), from its ancestor chain.
    fn memo_of(&self, d: u32, cache: &mut HashMap<u32, DirMemo, crate::index::Fx>) -> DirMemo {
        let idx = &self.live.base;
        let (de, en, dp) = (idx.dir_entry(), idx.ent_name(), idx.dir_parent());
        let mut chain = Vec::new();
        let mut k = d;
        let mut acc = loop {
            if k == 0 {
                break DirMemo::default();
            }
            if let Some(&m) = cache.get(&k) {
                break m;
            }
            chain.push(k);
            k = dp[k as usize];
        };
        for &k in chain.iter().rev() {
            acc = DirMemo::own(self.names, en[de[k as usize] as usize]).under(acc);
            cache.insert(k, acc);
        }
        acc
    }
}

/// The dir memo is ~13 MB; reusing it saves a page-fault storm per query.
static MEMO_POOL: std::sync::Mutex<Vec<Vec<DirMemo>>> = std::sync::Mutex::new(Vec::new());

/// What the name table depends on: two queries with the same key score
/// every name the same.
#[derive(PartialEq)]
struct NameKey {
    tokens: Vec<(Vec<u8>, Mode, bool)>,
    exts: Vec<Vec<u8>>,
    name_re: Option<String>,
}

impl NameKey {
    fn of(q: &Query) -> NameKey {
        NameKey {
            tokens: q.tokens.iter().map(|t| (t.text.clone(), t.mode, t.negate)).collect(),
            exts: q.exts.clone(),
            name_re: q.name_re.as_ref().map(|r| r.as_str().to_string()),
        }
    }

    /// Can only match names `prev` matched: same filters, same tokens, each
    /// positive token the same or longer in a way that only narrows it.
    fn narrows(&self, prev: &NameKey) -> bool {
        self.exts == prev.exts
            && self.name_re == prev.name_re
            && self.tokens.len() == prev.tokens.len()
            && self.tokens.iter().any(|t| !t.2)
            && self.tokens.iter().zip(&prev.tokens).all(|(a, b)| {
                a.1 == b.1
                    && a.2 == b.2
                    && if a.2 {
                        a.0 == b.0
                    } else if a.1 == Mode::Suffix {
                        a.0.ends_with(&b.0)
                    } else {
                        a.0.starts_with(&b.0)
                    }
            })
    }
}

/// The last query's name table (and dir memo, built on first use).
pub struct Scored {
    at: std::time::Instant,
    key: NameKey,
    names: NameTable,
    memo: std::sync::OnceLock<Vec<DirMemo>>,
}

impl Drop for Scored {
    fn drop(&mut self) {
        if let Some(v) = self.memo.take() {
            let mut pool = MEMO_POOL.lock().unwrap();
            if pool.is_empty() {
                pool.push(v);
            }
        }
    }
}

/// Lives with the index it was scored against (`Live`).
#[derive(Default)]
pub struct NameCache(std::sync::Mutex<Option<std::sync::Arc<Scored>>>);

impl NameCache {
    /// Drop the cached table and spare buffers once searching has stopped:
    /// tens of MB after a broad query, worth keeping only while typing.
    pub fn trim_if_idle(&self, idle: std::time::Duration) {
        let mut g = self.0.lock().unwrap();
        if g.as_ref().is_some_and(|s| s.at.elapsed() > idle) {
            *g = None;
            drop(g);
            trim_pools();
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct DirMemo {
    bits: u32,
    best: [i16; 4],
}

impl DirMemo {
    /// A dir's own name's contribution.
    #[inline]
    fn own(names: &NameTable, name: u32) -> DirMemo {
        match names.get(name) {
            Some(h) if h.flags & NF_NEG != 0 => DirMemo { bits: u32::MAX, best: [0; 4] },
            Some(h) => DirMemo { bits: h.bits as u32, best: h.best },
            None => DirMemo::default(),
        }
    }

    /// This dir's memo with its parent's folded in.
    #[inline]
    fn under(self, p: DirMemo) -> DirMemo {
        if p.bits == u32::MAX || self.bits == u32::MAX {
            return DirMemo { bits: u32::MAX, best: self.best };
        }
        let mut best = self.best;
        for t in 0..4 {
            best[t] = best[t].max(p.best[t]);
        }
        DirMemo { bits: self.bits | p.bits, best }
    }
}

/// Spare dense name tables (24 MB each on this disk), so a broad query
/// doesn't page-fault a fresh one in.
static DENSE_POOL: std::sync::Mutex<Vec<Vec<NameHit>>> = std::sync::Mutex::new(Vec::new());

/// Free the spare buffers searches keep for speed (after a quiet spell).
pub fn trim_pools() {
    DENSE_POOL.lock().unwrap().clear();
    MEMO_POOL.lock().unwrap().clear();
}

impl Drop for NameTable {
    fn drop(&mut self) {
        if let Some(d) = self.dense.take() {
            let mut pool = DENSE_POOL.lock().unwrap();
            if pool.len() < 2 {
                pool.push(d);
            }
        }
    }
}

struct NameTable {
    bits: Vec<u64>,
    sparse: Vec<(u32, NameHit)>,
    dense: Option<Vec<NameHit>>,
    /// Entries carrying a name that passes as a match (NF_OK).
    ok_entries: usize,
}

impl NameTable {
    #[inline(always)]
    fn get(&self, id: u32) -> Option<NameHit> {
        if self.bits[id as usize >> 6] & (1 << (id & 63)) == 0 {
            return None;
        }
        match &self.dense {
            Some(d) => Some(d[id as usize]),
            None => self.sparse.binary_search_by_key(&id, |e| e.0).ok().map(|k| self.sparse[k].1),
        }
    }

    /// Every name in the table, ascending.
    fn iter(&self) -> Box<dyn Iterator<Item = (u32, NameHit)> + '_> {
        match &self.dense {
            None => Box::new(self.sparse.iter().copied()),
            Some(d) => Box::new(self.bits.iter().enumerate().flat_map(move |(w, &b)| {
                let mut b = b;
                std::iter::from_fn(move || {
                    (b != 0).then(|| {
                        let id = w as u32 * 64 + b.trailing_zeros();
                        b &= b - 1;
                        (id, d[id as usize])
                    })
                })
            })),
        }
    }
}

#[derive(Clone, Copy)]
struct NameHit {
    score: i16,
    /// Which positive tokens the name matched.
    bits: u8,
    flags: u8,
    /// Per-token score, first 4 tokens (for the folder memo).
    best: [i16; 4],
}

impl NameHit {
    const NONE: NameHit = NameHit { score: 0, bits: 0, flags: 0, best: [0; 4] };
}

const NF_OK: u8 = 1;
const NF_DOT: u8 = 2;
const NF_NEG: u8 = 8;
const NF_APP: u8 = 4;

fn name_flags(name: &[u8]) -> u8 {
    let mut f = 0;
    if name.first() == Some(&b'.') {
        f |= NF_DOT;
    }
    if name.ends_with(b".app") {
        f |= NF_APP;
    }
    f
}

/// Small per-entry nudges on top of match quality and the location prior.
#[inline]
fn rank_tweaks(flags: u8, kind: u8, mtime: u32, now: u32) -> i32 {
    let mut s = 0;
    if flags & NF_DOT != 0 {
        s -= 8;
    }
    if kind & FLAG_HIDDEN != 0 {
        s -= 8;
    }
    // Apps are dirs, or symlinks into the cryptex (/Applications/Safari.app).
    if matches!(kind & 3, KIND_DIR | KIND_LINK) && flags & NF_APP != 0 {
        s += 25;
    }
    let age = now.saturating_sub(mtime);
    s += match age {
        0..=86_400 => 10,
        86_401..=604_800 => 7,
        604_801..=2_592_000 => 4,
        2_592_001..=31_536_000 => 1,
        _ => 0,
    };
    s
}
