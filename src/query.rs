//! Name search: parse a query, scan the index in parallel, rank, top-k.

use crate::index::char_bit;
use crate::live::Live;
use crate::walk::{FLAG_HIDDEN, KIND_DIR, KIND_FILE, KIND_LINK};
use rayon::prelude::*;
use std::cmp::Reverse;
use std::collections::BinaryHeap;

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
    let mut j = 0;
    let mut end = usize::MAX;
    for (i, &b) in name.iter().enumerate() {
        if fold(b) == q[j] {
            j += 1;
            if j == q.len() {
                end = i;
                break;
            }
        }
    }
    if end == usize::MAX {
        return None;
    }
    let mut start = end;
    let mut j = q.len();
    for i in (0..=end).rev() {
        if fold(name[i]) == q[j - 1] {
            j -= 1;
            if j == 0 {
                start = i;
                break;
            }
        }
    }
    let mut score = 0;
    let mut prev = if start == 0 { Class::Delim } else { class(name[start - 1]) };
    let (mut consec, mut first_bonus, mut in_gap, mut k) = (0, 0, false, 0);
    for i in start..=end {
        let c = class(name[i]);
        if k < q.len() && fold(name[i]) == q[k] {
            let mut b = bonus(prev, c);
            if consec == 0 {
                first_bonus = b;
            } else {
                if b >= BONUS_BOUNDARY && b > first_bonus {
                    first_bonus = b;
                }
                b = b.max(first_bonus).max(BONUS_CONSEC);
            }
            score += SCORE_MATCH + if k == 0 { b * 2 } else { b };
            consec += 1;
            in_gap = false;
            k += 1;
        } else {
            score += if in_gap { GAP_EXT } else { GAP_START };
            in_gap = true;
            consec = 0;
            first_bonus = 0;
        }
        prev = c;
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

struct TopK {
    k: usize,
    heap: BinaryHeap<Reverse<(i32, Reverse<u32>)>>,
}

impl TopK {
    fn new(k: usize) -> TopK {
        TopK { k, heap: BinaryHeap::with_capacity(k + 1) }
    }
    #[inline]
    fn floor(&self) -> i32 {
        if self.heap.len() < self.k { i32::MIN } else { self.heap.peek().unwrap().0.0 }
    }
    #[inline]
    fn push(&mut self, s: i32, i: u32) {
        if self.heap.len() < self.k {
            self.heap.push(Reverse((s, Reverse(i))));
        } else if s > self.floor() {
            self.heap.pop();
            self.heap.push(Reverse((s, Reverse(i))));
        }
    }
    fn merge(mut self, o: TopK) -> TopK {
        for Reverse((s, Reverse(i))) in o.heap {
            self.push(s, i);
        }
        self
    }
}

fn ext_ok(name: &[u8], exts: &[Vec<u8>]) -> bool {
    let Some(dot) = name.iter().rposition(|&b| b == b'.') else { return false };
    let e = &name[dot + 1..];
    exts.iter().any(|x| x.len() == e.len() && x.iter().zip(e).all(|(&a, &b)| a == fold(b)))
}

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
        let idx = &self.live.base;
        let Some((lo, hi)) = self.scope_range(q) else { return Vec::new() };
        let pos: Vec<&Token> = q.tokens.iter().filter(|t| !t.negate).collect();
        let neg: Vec<&Token> = q.tokens.iter().filter(|t| t.negate).collect();
        let all = (1u32 << pos.len()) - 1;
        // Step 1: every name-only predicate, once per distinct name (~2M)
        // rather than once per entry (~7.5M).
        let names = self.score_names(q, &pos, &neg);
        // Per-directory memo: which tokens some ancestor's name matches, and
        // whether any ancestor hits a negated token. One pass over ~1M dirs
        // replaces a parent-chain walk per file.
        let need_dirs = pos.len() > 1 || !neg.is_empty();
        let dir_tok: Vec<DirMemo> = if need_dirs { self.dir_tokens(&names) } else { Vec::new() };
        let dir_tok = Pooled(Some(dir_tok));
        let now = now_secs();
        let ent_name = idx.ent_name();
        let kind = idx.kind();
        let parent = idx.parent();
        let size = idx.size_raw();
        let mtime = idx.mtime();
        let prior = idx.dir_prior();
        let filt_size = q.size != (0, u64::MAX);
        let filt_mtime = q.mtime != (0, u32::MAX);

        // Step 2: one sequential pass over entries with a table lookup each.
        let chunk = 1 << 16;
        let nchunks = (hi - lo).div_ceil(chunk);
        let top = (0..nchunks)
            .into_par_iter()
            .fold(
                || (TopK::new(q.limit), Vec::<u8>::new()),
                |(mut top, mut pbuf), c| {
                    let a = lo + c * chunk;
                    let b = (a + chunk).min(hi);
                    for i in a..b {
                        let Some(nh) = names.get(ent_name[i]).filter(|h| h.flags & NF_OK != 0) else { continue };
                        let k = kind[i];
                        if q.kind.is_some_and(|want| k & 3 != want) {
                            continue;
                        }
                        if filt_size {
                            let sz = crate::index::dec_size(size[i]);
                            if sz < q.size.0 || sz > q.size.1 {
                                continue;
                            }
                        }
                        if filt_mtime && (mtime[i] < q.mtime.0 || mtime[i] > q.mtime.1) {
                            continue;
                        }
                        let p = parent[i] as usize;
                        let mut score = nh.score as i32;
                        if need_dirs {
                            let memo = dir_tok[p];
                            if memo.bits == u32::MAX || (nh.bits as u32 | memo.bits) & all != all {
                                continue;
                            }
                            for t in 0..pos.len() {
                                if nh.bits & (1 << t) == 0 {
                                    // Matched by a folder on the path instead.
                                    score += memo.best.get(t).map_or(6, |&b| b as i32 * 3 / 4);
                                }
                            }
                        }
                        if self.live.is_dead(i as u32) {
                            continue;
                        }
                        score += prior[p] as i32 + rank_tweaks(nh.flags, k, mtime[i], now);
                        if score <= top.floor() {
                            continue;
                        }
                        if let Some(re) = &q.path_re {
                            idx.path(i, &mut pbuf);
                            if !re.is_match(&pbuf) {
                                continue;
                            }
                        }
                        top.push(score, i as u32);
                    }
                    (top, pbuf)
                },
            )
            .map(|(t, _)| t)
            .reduce(|| TopK::new(q.limit), TopK::merge);
        top.heap.into_iter().map(|Reverse((score, Reverse(idx)))| Hit { idx, score, over: None }).collect()
    }

    /// Score every distinct name against the query's name-only predicates.
    /// Matches come back sparse (plus a 256 KB membership bitset), so a
    /// selective query never touches a table the size of the name count.
    fn score_names(&self, q: &Query, pos: &[&Token], neg: &[&Token]) -> NameTable {
        let idx = &self.live.base;
        let mask = idx.name_mask();
        let chunk = 1 << 15;
        let parts: Vec<Vec<(u32, NameHit)>> = (0..idx.u.div_ceil(chunk))
            .into_par_iter()
            .map(|c| {
                let mut out = Vec::new();
                for k in c * chunk..((c + 1) * chunk).min(idx.u) {
                    let m = mask[k];
                    if !(pos.is_empty() || pos.iter().any(|t| m & t.mask == t.mask)) && neg.is_empty() {
                        continue;
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
                    }
                    if ok || h.bits != 0 || h.flags & NF_NEG != 0 {
                        out.push((k as u32, h));
                    }
                }
                out
            })
            .collect();
        let mut t = NameTable { bits: vec![0u64; idx.u.div_ceil(64)], sparse: parts.concat(), dense: None };
        for &(id, _) in &t.sparse {
            t.bits[id as usize >> 6] |= 1 << (id & 63);
        }
        if t.sparse.len() > 1 << 16 {
            let mut d = vec![NameHit { score: 0, bits: 0, flags: 0, best: [0; 4] }; idx.u];
            for &(id, h) in &t.sparse {
                d[id as usize] = h;
            }
            t.dense = Some(d);
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
            if k == 0 {
                return;
            }
            if let Some(h) = names.get(en[de[k] as usize]) {
                *slot = if h.flags & NF_NEG != 0 { DirMemo { bits: u32::MAX, best: [0; 4] } } else { DirMemo { bits: h.bits as u32, best: h.best } };
            }
        });
        let dp = idx.dir_parent();
        for k in 1..idx.d {
            let p = out[dp[k] as usize];
            let me = &mut out[k];
            if p.bits == u32::MAX || me.bits == u32::MAX {
                me.bits = u32::MAX;
                continue;
            }
            me.bits |= p.bits;
            for t in 0..4 {
                me.best[t] = me.best[t].max(p.best[t]);
            }
        }
        out
    }
}

/// The dir memo is ~13 MB; reusing it saves a page-fault storm per query.
static MEMO_POOL: std::sync::Mutex<Vec<Vec<DirMemo>>> = std::sync::Mutex::new(Vec::new());

struct Pooled(Option<Vec<DirMemo>>);

impl std::ops::Deref for Pooled {
    type Target = Vec<DirMemo>;
    fn deref(&self) -> &Vec<DirMemo> {
        self.0.as_ref().unwrap()
    }
}

impl Drop for Pooled {
    fn drop(&mut self) {
        if let Some(v) = self.0.take().filter(|v| !v.is_empty()) {
            let mut pool = MEMO_POOL.lock().unwrap();
            if pool.is_empty() {
                pool.push(v);
            }
        }
    }
}

#[derive(Clone, Copy, Default)]
struct DirMemo {
    bits: u32,
    best: [i16; 4],
}

struct NameTable {
    bits: Vec<u64>,
    sparse: Vec<(u32, NameHit)>,
    dense: Option<Vec<NameHit>>,
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
