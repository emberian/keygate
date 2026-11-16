//! `EchoGuard`: a bounded multi-pattern response scrubber.
//!
//! An upstream that reflects the injected credential (error page, debug
//! echo, model output) should not get it past keygate, including when the
//! reflection straddles network chunks or is slightly altered.
//!
//! # What is matched
//!
//! For every guarded secret, and for a fixed set of re-encodings of it
//! (see [`variants`]), the guard trips on any [`WINDOW`]-byte substring of
//! the pattern (the whole pattern when it is shorter than that). So an echo
//! that drops or alters a trailing character, or quotes only the middle of a
//! key, still trips as long as 16 consecutive pattern bytes survive.
//!
//! # What is not matched
//!
//! This is defense in depth against *reflection*, not a proof that secret
//! bytes cannot leave. Fewer than `WINDOW` consecutive bytes pass (so a
//! cooperating upstream can leak a key 15 bytes at a time). Transformations
//! outside the variant list pass: base64 or hex of the key, case changes,
//! compression, encryption, spelling it out. Case is never folded, because
//! credentials are case-sensitive and folding would match unrelated text.
//!
//! # How
//!
//! One generalized suffix automaton over all patterns: `O(total bytes)`
//! states with sparse transitions. Its state plus the current match length
//! say how long a suffix of the stream is a substring of some pattern; that
//! suffix (at most `WINDOW - 1` bytes) is held back, everything before it is
//! released at once, and the guard trips when the length reaches a
//! pattern's window. The tables encode the secrets, so they are allocated
//! once at their final size and zeroed on drop. Total pattern bytes are
//! capped by [`MAX_GUARD_BYTES`].

use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

/// Secrets shorter than this are not guardable (they would match ordinary
/// traffic); `set` refuses them.
pub const MIN_SECRET_LEN: usize = 8;
/// Any this-many consecutive bytes of a pattern trip the guard.
pub const WINDOW: usize = 16;
/// Ceiling on the summed length of every pattern (secrets, retired secrets
/// and their variants). Bounds automaton memory and build time.
pub const MAX_GUARD_BYTES: usize = 64 * 1024;

const ALPHABET: usize = 95;
const NONE: u32 = u32::MAX;
const ROOT: u32 = 0;

/// Printable ASCII is the whole pattern alphabet; any other byte cannot be
/// part of a match and resets it.
fn class(byte: u8) -> Option<u8> {
    (0x20..0x7f).contains(&byte).then(|| byte - 0x20)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuardError {
    #[error("a guarded secret must be {MIN_SECRET_LEN}..=8192 bytes of printable ASCII")]
    Unguardable,
    #[error(
        "guard patterns would total {have} bytes (limit {max}); forget retired secrets or use shorter ones"
    )]
    TooLarge { have: usize, max: usize },
}

fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// The spellings of `secret` the guard looks for: the secret itself, then
/// each of these when it differs from the original:
///
/// - percent-encoding of every byte outside `[A-Za-z0-9-._~]`, with
///   uppercase and with lowercase hex digits;
/// - JSON string escaping of `"` and `\`;
/// - the same plus `\/` for `/` (PHP's default);
/// - the same plus `\u003c`, `\u003e`, `\u0026` for `<`, `>`, `&` (Go's
///   default).
///
/// A secret made only of `[A-Za-z0-9-._~]` has no variants.
pub fn variants(secret: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    let percent = |hex: &[u8; 16]| {
        let mut out = Zeroizing::new(Vec::with_capacity(secret.len() * 3));
        for &b in secret {
            if unreserved(b) {
                out.push(b);
            } else {
                out.extend_from_slice(&[b'%', hex[usize::from(b >> 4)], hex[usize::from(b & 15)]]);
            }
        }
        out
    };
    let json = |slash: bool, html: bool| {
        let mut out = Zeroizing::new(Vec::with_capacity(secret.len() * 6));
        for &b in secret {
            match b {
                b'"' => out.extend_from_slice(b"\\\""),
                b'\\' => out.extend_from_slice(b"\\\\"),
                b'/' if slash => out.extend_from_slice(b"\\/"),
                b'<' if html => out.extend_from_slice(b"\\u003c"),
                b'>' if html => out.extend_from_slice(b"\\u003e"),
                b'&' if html => out.extend_from_slice(b"\\u0026"),
                other => out.push(other),
            }
        }
        out
    };
    let mut all = vec![Zeroizing::new(secret.to_vec())];
    for candidate in [
        percent(HEX_UPPER),
        percent(HEX_LOWER),
        json(false, false),
        json(true, false),
        json(false, true),
    ] {
        if !all.iter().any(|seen| **seen == *candidate) {
            all.push(candidate);
        }
    }
    all
}

/// Pattern bytes `secret` costs against [`MAX_GUARD_BYTES`].
pub fn guard_cost(secret: &[u8]) -> usize {
    variants(secret).iter().map(|v| v.len()).sum()
}

pub struct EchoAutomaton {
    /// Longest substring length of each state.
    len: Vec<u32>,
    /// Suffix link of each state.
    link: Vec<u32>,
    /// Match length at which this state trips (255: never by itself).
    threshold: Vec<u8>,
    /// Some proper suffix class of this state is a whole tripping window.
    suffix_trips: Vec<bool>,
    /// `edge_*[first[s]..first[s + 1]]` are state `s`'s transitions, sorted
    /// by byte class.
    first: Vec<u32>,
    edge_class: Vec<u8>,
    edge_to: Vec<u32>,
    secrets: usize,
    pattern_bytes: usize,
}

/// Dense table used only while building; converted to sparse and zeroed.
struct Building {
    len: Vec<u32>,
    link: Vec<u32>,
    next: Vec<[u32; ALPHABET]>,
}

impl Building {
    fn state(&mut self, len: u32, link: u32, next: [u32; ALPHABET]) -> u32 {
        // Capacity was reserved for the worst case, so these never
        // reallocate and never strand a copy of the table in freed memory.
        debug_assert!(self.next.len() < self.next.capacity());
        self.len.push(len);
        self.link.push(link);
        self.next.push(next);
        (self.len.len() - 1) as u32
    }

    fn split(&mut self, mut p: u32, q: u32, c: usize) -> u32 {
        let clone = self.state(
            self.len[p as usize] + 1,
            self.link[q as usize],
            self.next[q as usize],
        );
        while p != NONE && self.next[p as usize][c] == q {
            self.next[p as usize][c] = clone;
            p = self.link[p as usize];
        }
        self.link[q as usize] = clone;
        clone
    }

    /// Generalized suffix-automaton extension from `last` by class `c`.
    fn extend(&mut self, last: u32, c: usize) -> u32 {
        let existing = self.next[last as usize][c];
        if existing != NONE {
            if self.len[existing as usize] == self.len[last as usize] + 1 {
                return existing;
            }
            return self.split(last, existing, c);
        }
        let cur = self.state(self.len[last as usize] + 1, NONE, [NONE; ALPHABET]);
        let mut p = last;
        while p != NONE && self.next[p as usize][c] == NONE {
            self.next[p as usize][c] = cur;
            p = self.link[p as usize];
        }
        self.link[cur as usize] = if p == NONE {
            ROOT
        } else {
            let q = self.next[p as usize][c];
            if self.len[q as usize] == self.len[p as usize] + 1 {
                q
            } else {
                self.split(p, q, c)
            }
        };
        cur
    }
}

impl Drop for Building {
    fn drop(&mut self) {
        self.len.zeroize();
        self.link.zeroize();
        for row in &mut self.next {
            row.zeroize();
        }
    }
}

impl EchoAutomaton {
    /// An automaton that guards nothing.
    pub fn empty() -> Self {
        EchoAutomaton::build([]).expect("no patterns is within every limit")
    }

    /// Guard `secrets` and their [`variants`]. Fails, changing nothing,
    /// when a secret is not guardable or the patterns exceed
    /// [`MAX_GUARD_BYTES`].
    pub fn build<'a>(secrets: impl IntoIterator<Item = &'a [u8]>) -> Result<Self, GuardError> {
        let mut patterns: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        let mut count = 0;
        let mut pattern_bytes = 0usize;
        for secret in secrets {
            if secret.len() < MIN_SECRET_LEN
                || secret.len() > 8192
                || secret.iter().any(|&b| class(b).is_none())
            {
                return Err(GuardError::Unguardable);
            }
            count += 1;
            for variant in variants(secret) {
                if patterns.iter().any(|seen| **seen == *variant) {
                    continue;
                }
                pattern_bytes += variant.len();
                if pattern_bytes > MAX_GUARD_BYTES {
                    return Err(GuardError::TooLarge {
                        have: pattern_bytes,
                        max: MAX_GUARD_BYTES,
                    });
                }
                patterns.push(variant);
            }
        }

        let capacity = 2 * pattern_bytes + 1;
        let mut b = Building {
            len: Vec::with_capacity(capacity),
            link: Vec::with_capacity(capacity),
            next: Vec::with_capacity(capacity),
        };
        b.state(0, NONE, [NONE; ALPHABET]);
        for pattern in &patterns {
            let mut last = ROOT;
            for &byte in pattern.iter() {
                last = b.extend(
                    last,
                    usize::from(class(byte).expect("patterns are printable")),
                );
            }
        }
        let states = b.len.len();

        // Every state is a set of substrings shared by the same patterns.
        // Its threshold is the smallest window among those patterns.
        let mut threshold = vec![u8::MAX; states];
        let mut stamp = vec![NONE; states];
        for (id, pattern) in patterns.iter().enumerate() {
            let window = pattern.len().min(WINDOW) as u8;
            let mut state = ROOT;
            for &byte in pattern.iter() {
                state = b.next[state as usize][usize::from(class(byte).expect("printable"))];
                let mut up = state;
                while up != ROOT && stamp[up as usize] != id as u32 {
                    stamp[up as usize] = id as u32;
                    threshold[up as usize] = threshold[up as usize].min(window);
                    up = b.link[up as usize];
                }
            }
        }

        // A state whose own longest string already reaches its threshold
        // trips whenever it is reached as a suffix of a longer match.
        let mut order: Vec<u32> = (1..states as u32).collect();
        order.sort_unstable_by_key(|&s| b.len[s as usize]);
        let mut whole_trips = vec![false; states];
        let mut suffix_trips = vec![false; states];
        for &s in &order {
            let parent = b.link[s as usize] as usize;
            suffix_trips[s as usize] = whole_trips[parent];
            whole_trips[s as usize] =
                suffix_trips[s as usize] || b.len[s as usize] >= u32::from(threshold[s as usize]);
        }
        whole_trips.zeroize();
        stamp.zeroize();
        order.zeroize();

        let edges: usize = b
            .next
            .iter()
            .map(|row| row.iter().filter(|&&to| to != NONE).count())
            .sum();
        let mut first = Vec::with_capacity(states + 1);
        let mut edge_class = Vec::with_capacity(edges);
        let mut edge_to = Vec::with_capacity(edges);
        for row in &b.next {
            first.push(edge_to.len() as u32);
            for (c, &to) in row.iter().enumerate() {
                if to != NONE {
                    edge_class.push(c as u8);
                    edge_to.push(to);
                }
            }
        }
        first.push(edge_to.len() as u32);

        Ok(EchoAutomaton {
            len: std::mem::take(&mut b.len),
            link: std::mem::take(&mut b.link),
            threshold,
            suffix_trips,
            first,
            edge_class,
            edge_to,
            secrets: count,
            pattern_bytes,
        })
    }

    /// True when no secret is guarded (every scan passes).
    pub fn is_empty(&self) -> bool {
        self.secrets == 0
    }

    /// Secrets guarded (not counting their variants).
    pub fn secrets(&self) -> usize {
        self.secrets
    }

    /// Summed length of every pattern, the quantity [`MAX_GUARD_BYTES`] caps.
    pub fn pattern_bytes(&self) -> usize {
        self.pattern_bytes
    }

    /// Heap bytes held by the tables.
    pub fn table_bytes(&self) -> usize {
        self.len.len() * (4 + 4 + 1 + 1) + self.first.len() * 4 + self.edge_to.len() * 5
    }

    fn edge(&self, state: u32, c: u8) -> Option<u32> {
        let range = self.first[state as usize] as usize..self.first[state as usize + 1] as usize;
        let at = self.edge_class[range.clone()].binary_search(&c).ok()?;
        Some(self.edge_to[range.start + at])
    }

    /// Consume one byte. Returns the new `(state, matched)` and whether the
    /// stream now ends in a tripping window.
    fn step(&self, mut state: u32, mut matched: u32, byte: u8) -> (u32, u32, bool) {
        let Some(c) = class(byte) else {
            return (ROOT, 0, false);
        };
        loop {
            if let Some(to) = self.edge(state, c) {
                state = to;
                matched += 1;
                break;
            }
            if state == ROOT {
                return (ROOT, 0, false);
            }
            state = self.link[state as usize];
            matched = self.len[state as usize];
        }
        let trips = matched >= u32::from(self.threshold[state as usize])
            || self.suffix_trips[state as usize];
        (state, matched, trips)
    }

    /// Whole-buffer scan, for response heads and buffered bodies.
    pub fn contains(&self, haystack: &[u8]) -> bool {
        let (mut state, mut matched) = (ROOT, 0);
        haystack.iter().any(|&byte| {
            let (s, m, trips) = self.step(state, matched, byte);
            state = s;
            matched = m;
            trips
        })
    }
}

impl Drop for EchoAutomaton {
    fn drop(&mut self) {
        self.len.zeroize();
        self.link.zeroize();
        self.threshold.zeroize();
        self.suffix_trips.zeroize();
        self.first.zeroize();
        self.edge_class.zeroize();
        self.edge_to.zeroize();
    }
}

/// The guard tripped: a guarded pattern window occurred in the stream.
#[derive(Debug, PartialEq, Eq)]
pub struct Withheld;

/// Streaming state for one response body.
pub struct EchoGuard {
    automaton: Arc<EchoAutomaton>,
    state: u32,
    matched: u32,
    /// The last `held_len` bytes of the stream, not yet released. Fixed
    /// size: it never reallocates, so no copy is left behind in the heap.
    held: [u8; WINDOW],
    held_len: usize,
    tripped: bool,
}

impl EchoGuard {
    pub fn new(automaton: Arc<EchoAutomaton>) -> Self {
        EchoGuard {
            automaton,
            state: ROOT,
            matched: 0,
            held: [0; WINDOW],
            held_len: 0,
            tripped: false,
        }
    }

    /// Bytes currently withheld pending the next chunk (always `< WINDOW`).
    pub fn held_len(&self) -> usize {
        self.held_len
    }

    /// Feed one chunk. Bytes that are now provably not part of a tripping
    /// window are appended to `out`. On a trip nothing from this chunk or
    /// the holdback is released, the buffers are zeroed, and every later
    /// call fails too.
    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> Result<(), Withheld> {
        if self.tripped {
            return Err(Withheld);
        }
        for &byte in chunk {
            let (state, matched, trips) = self.automaton.step(self.state, self.matched, byte);
            self.state = state;
            self.matched = matched;
            if trips {
                self.trip();
                return Err(Withheld);
            }
        }
        // `matched` is the longest suffix that could still grow into a
        // window; it is below every threshold, hence below WINDOW.
        let keep = self.matched as usize;
        debug_assert!(keep < WINDOW && keep <= self.held_len + chunk.len());
        let mut kept = [0u8; WINDOW];
        if keep <= chunk.len() {
            out.extend_from_slice(&self.held[..self.held_len]);
            out.extend_from_slice(&chunk[..chunk.len() - keep]);
            kept[..keep].copy_from_slice(&chunk[chunk.len() - keep..]);
        } else {
            let from_held = keep - chunk.len();
            let released = self.held_len - from_held;
            out.extend_from_slice(&self.held[..released]);
            kept[..from_held].copy_from_slice(&self.held[released..self.held_len]);
            kept[from_held..keep].copy_from_slice(chunk);
        }
        self.held = kept;
        self.held_len = keep;
        kept.zeroize();
        Ok(())
    }

    /// End of stream: the holdback is shorter than any window, so it is
    /// ordinary data and is released.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), Withheld> {
        if self.tripped {
            return Err(Withheld);
        }
        out.extend_from_slice(&self.held[..self.held_len]);
        self.held.zeroize();
        self.held_len = 0;
        self.state = ROOT;
        self.matched = 0;
        Ok(())
    }

    fn trip(&mut self) {
        self.tripped = true;
        self.held.zeroize();
        self.held_len = 0;
        self.state = ROOT;
        self.matched = 0;
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        self.held.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"sk-ant-secret12345";

    fn automaton(secrets: &[&[u8]]) -> Arc<EchoAutomaton> {
        Arc::new(EchoAutomaton::build(secrets.iter().copied()).unwrap())
    }

    /// Feed `chunks`; return what reached the caller and whether it tripped.
    fn run(secrets: &[&[u8]], chunks: &[&[u8]]) -> (Vec<u8>, bool) {
        let mut g = EchoGuard::new(automaton(secrets));
        let mut delivered = Vec::new();
        for chunk in chunks {
            if g.push(chunk, &mut delivered).is_err() {
                return (delivered, true);
            }
        }
        g.finish(&mut delivered).unwrap();
        (delivered, false)
    }

    /// #tooth: the spec's split, `"sk-ant-" | "secret1" | "2345"`, as 2 and 3 chunks.
    #[test]
    fn tooth_secret_split_across_two_and_three_chunks() {
        let (out, tripped) = run(&[SECRET], &[b"data: sk-ant-", b"secret12345 trailing"]);
        assert!(tripped);
        assert_eq!(out, b"data: ");

        let (out, tripped) = run(&[SECRET], &[b"data: sk-ant-", b"secret1", b"2345"]);
        assert!(tripped);
        assert_eq!(out, b"data: ");
    }

    /// #tooth: one byte per chunk; not a single secret byte is released.
    #[test]
    fn tooth_secret_split_into_single_bytes() {
        let stream = [b"hello ".as_slice(), SECRET, b" bye"].concat();
        let chunks: Vec<&[u8]> = stream.chunks(1).collect();
        let (out, tripped) = run(&[SECRET], &chunks);
        assert!(tripped);
        assert_eq!(out, b"hello ");
    }

    /// #tooth: every possible two-way split point of the secret is caught.
    #[test]
    fn tooth_every_split_point() {
        let stream = [b"xx".as_slice(), SECRET, b"yy"].concat();
        for cut in 0..=stream.len() {
            let (out, tripped) = run(&[SECRET], &[&stream[..cut], &stream[cut..]]);
            assert!(tripped, "cut at {cut}");
            assert!(
                out.len() <= 2 && b"xx".starts_with(&out),
                "cut at {cut}: leaked {out:?}"
            );
        }
    }

    /// #tooth: an echo that drops or alters characters still trips while 16
    /// consecutive secret bytes survive, wherever they sit in the secret.
    #[test]
    fn tooth_truncated_and_altered_echoes_trip() {
        let long: &[u8] = b"sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        let all_but_last = &long[..long.len() - 1];
        let mut last_altered = long.to_vec();
        *last_altered.last_mut().unwrap() = b'#';
        let mut first_altered = long.to_vec();
        first_altered[0] = b'#';
        for echo in [
            all_but_last,
            &last_altered,
            &first_altered,
            &long[10..26],
            &long[long.len() - 16..],
        ] {
            let stream = [b"key: ".as_slice(), echo, b" end"].concat();
            for width in [1, 3, 7, stream.len()] {
                let chunks: Vec<&[u8]> = stream.chunks(width).collect();
                let (out, tripped) = run(&[long], &chunks);
                assert!(tripped, "{:?} width {width}", String::from_utf8_lossy(echo));
                assert!(
                    b"key: #".starts_with(&out),
                    "leaked {:?}",
                    String::from_utf8_lossy(&out)
                );
            }
        }
    }

    /// The stated limit: fewer than WINDOW consecutive bytes are not a match.
    #[test]
    fn fragments_below_the_window_pass_in_full_and_in_order() {
        let long: &[u8] = b"sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        let stream = [
            b"a ".as_slice(),
            &long[..15],
            b" b ",
            &long[20..35],
            b" c ",
            &long[long.len() - 15..],
        ]
        .concat();
        for size in 1..stream.len() {
            let chunks: Vec<&[u8]> = stream.chunks(size).collect();
            let (out, tripped) = run(&[long], &chunks);
            assert!(!tripped, "chunk size {size}");
            assert_eq!(out, stream, "chunk size {size}");
        }
        // Case is not folded: credentials are case-sensitive.
        let (_, tripped) = run(&[long], &[&long.to_ascii_uppercase()]);
        assert!(!tripped);
    }

    #[test]
    fn holdback_is_only_the_matching_suffix_and_stays_below_the_window() {
        let mut g = EchoGuard::new(automaton(&[SECRET]));
        let mut out = Vec::new();
        g.push(b"abcdef sk-an", &mut out).unwrap();
        assert_eq!(out, b"abcdef ");
        assert_eq!(g.held_len(), 5);
        g.push(b"x", &mut out).unwrap();
        assert_eq!(out, b"abcdef sk-anx");
        assert_eq!(g.held_len(), 0);
        // A mid-secret fragment is held too: it could be a window's start.
        g.push(b" cret123", &mut out).unwrap();
        assert_eq!(g.held_len(), 7);
        g.push(b"\n", &mut out).unwrap();
        assert_eq!(g.held_len(), 0);
        assert_eq!(out, b"abcdef sk-anx cret123\n");

        let long = [b'k'; 64];
        let mut g = EchoGuard::new(automaton(&[b"0123456789abcdefghijklmnopqrstuv"]));
        let mut out = Vec::new();
        for chunk in [b"0123456".as_slice(), b"789abcd", b"e", &long] {
            g.push(chunk, &mut out).unwrap();
            assert!(g.held_len() < WINDOW);
        }
    }

    /// A short secret (below WINDOW) is matched whole; overlapping restarts
    /// keep exactly the still-viable suffix.
    #[test]
    fn short_secret_overlapping_restart() {
        let secret: &[u8] = b"aaaaaaab";
        let (out, tripped) = run(&[secret], &[b"aaaa", b"aaaa", b"aaaa", b"c"]);
        assert!(!tripped);
        assert_eq!(out, b"aaaaaaaaaaaac");
        let (out, tripped) = run(&[secret], &[b"aaaa", b"aaaa", b"aaaa", b"b"]);
        assert!(tripped);
        assert_eq!(
            out, b"aaaaa",
            "only bytes before the 7 a's of the occurrence"
        );
        let (_, tripped) = run(&[secret], &[b"aaaaaaa", b"c"]);
        assert!(
            !tripped,
            "seven of eight bytes of a short secret is not the secret"
        );
    }

    /// #tooth: several secrets of different lengths share one automaton and
    /// each keeps its own window, including a short one inside a long one.
    #[test]
    fn tooth_multi_secret_thresholds() {
        let a: &[u8] = b"sk-ant-secret12345";
        let b: &[u8] = b"ghp_0123456789abcdef";
        let short: &[u8] = b"secret123"; // 9 bytes, a substring of `a`
        for chunks in [
            vec![b"x sk-ant-secr".as_slice(), b"et12345"],
            vec![b"y ghp_0123", b"456789abc", b"def"],
        ] {
            let (out, tripped) = run(&[a, b], &chunks);
            assert!(tripped);
            assert_eq!(out.len(), 2);
        }
        // Alone, 9 bytes of `a` are below its window...
        let (_, tripped) = run(&[a], &[b"so secret123 it is"]);
        assert!(!tripped);
        // ...but they are the whole of `short`, reached as a suffix of a
        // longer partial match of `a`.
        let stream = b"so ant-secret123 it is";
        let (out, tripped) = run(&[a, short], &stream.chunks(1).collect::<Vec<_>>());
        assert!(tripped);
        assert_eq!(out, b"so ");
        let (out, tripped) = run(&[a, short], &[b"so secret12", b"x"]);
        assert!(!tripped);
        assert_eq!(out, b"so secret12x");
    }

    /// #tooth: the supported re-encodings of a secret with special bytes.
    #[test]
    fn tooth_encoded_variants_trip() {
        let secret: &[u8] = br#"ab/cd+ef=gh"ij\kl<mn>op&qr-0123456789"#;
        let spellings = variants(secret);
        assert_eq!(spellings.len(), 6);
        let text = |v: &Zeroizing<Vec<u8>>| String::from_utf8(v.to_vec()).unwrap();
        assert_eq!(
            text(&spellings[1]),
            "ab%2Fcd%2Bef%3Dgh%22ij%5Ckl%3Cmn%3Eop%26qr-0123456789"
        );
        assert_eq!(
            text(&spellings[2]),
            "ab%2fcd%2bef%3dgh%22ij%5ckl%3cmn%3eop%26qr-0123456789"
        );
        assert_eq!(
            text(&spellings[3]),
            r#"ab/cd+ef=gh\"ij\\kl<mn>op&qr-0123456789"#
        );
        assert_eq!(
            text(&spellings[4]),
            r#"ab\/cd+ef=gh\"ij\\kl<mn>op&qr-0123456789"#
        );
        assert_eq!(
            text(&spellings[5]),
            r#"ab/cd+ef=gh\"ij\\kl\u003cmn\u003eop\u0026qr-0123456789"#
        );
        for spelling in &spellings {
            let stream = [b"{\"k\":\"".as_slice(), spelling, b"\"}"].concat();
            for width in [1, 5, stream.len()] {
                let chunks: Vec<&[u8]> = stream.chunks(width).collect();
                let (out, tripped) = run(&[secret], &chunks);
                assert!(tripped, "{}", text(spelling));
                assert!(b"{\"k\":\"".starts_with(&out));
            }
        }
        assert_eq!(
            variants(b"plain-token_0123.~").len(),
            1,
            "unreserved-only secrets have no variants"
        );
        assert_eq!(guard_cost(b"plain-token_0123.~"), 18);
        // Not supported, and said so: base64 of the secret passes.
        let (_, tripped) = run(
            &[secret],
            &[b"YWIvY2QrZWY9Z2giaWpca2w8bW4+b3AmcXItMDEyMzQ1Njc4OQ=="],
        );
        assert!(!tripped);
    }

    #[test]
    fn non_printable_bytes_reset_the_match() {
        let (out, tripped) = run(&[SECRET], &[b"sk-ant-secret1\n2345"]);
        assert!(!tripped);
        assert_eq!(out, b"sk-ant-secret1\n2345");
        let (_, tripped) = run(&[SECRET], &[b"sk-ant-secret1\xff2345 sk-ant-secret12345"]);
        assert!(tripped);
    }

    #[test]
    fn tripped_guard_stays_tripped() {
        let mut g = EchoGuard::new(automaton(&[SECRET]));
        let mut out = Vec::new();
        assert_eq!(g.push(SECRET, &mut out), Err(Withheld));
        assert_eq!(g.push(b"harmless", &mut out), Err(Withheld));
        assert_eq!(g.finish(&mut out), Err(Withheld));
        assert!(out.is_empty());
    }

    #[test]
    fn whole_scan_and_refused_patterns() {
        let auto = automaton(&[SECRET]);
        assert!(auto.contains(b"x-debug: Bearer sk-ant-secret12345\r\n"));
        assert!(
            auto.contains(b"x-debug: Bearer sk-ant-secret1234\r\n"),
            "17 of 18 bytes"
        );
        assert!(
            !auto.contains(b"x-debug: Bearer sk-ant-secret12\r\n"),
            "15 bytes"
        );
        assert!(EchoAutomaton::empty().is_empty());
        assert!(!EchoAutomaton::empty().contains(SECRET));
        for bad in [b"short".as_slice(), b"has\nnewline-in-it", &[b'x'; 8193]] {
            assert_eq!(
                EchoAutomaton::build([bad]).err(),
                Some(GuardError::Unguardable)
            );
        }
    }

    /// #tooth: construction is bounded. Patterns over the byte cap are
    /// refused, and a full-cap automaton stays within a fixed table size.
    #[test]
    fn tooth_guard_size_is_bounded() {
        // Distinct 8 KiB secrets with no variants: eight fit, nine do not.
        let secrets: Vec<Vec<u8>> = (0..9u32)
            .map(|i| {
                let mut x = 0x9E37_79B9u32.wrapping_mul(i + 1);
                (0..8192)
                    .map(|_| {
                        x ^= x << 13;
                        x ^= x >> 17;
                        x ^= x << 5;
                        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                            [(x % 64) as usize]
                    })
                    .collect()
            })
            .collect();
        let eight = EchoAutomaton::build(secrets[..8].iter().map(Vec::as_slice)).unwrap();
        assert_eq!(eight.pattern_bytes(), MAX_GUARD_BYTES);
        assert_eq!(eight.secrets(), 8);
        assert!(
            eight.table_bytes() <= 4 << 20,
            "{} table bytes",
            eight.table_bytes()
        );
        for secret in &secrets[..8] {
            assert!(eight.contains(&secret[4000..4016]));
            assert!(!eight.contains(&secret[4000..4015]));
        }
        assert_eq!(
            EchoAutomaton::build(secrets.iter().map(Vec::as_slice)).err(),
            Some(GuardError::TooLarge {
                have: 9 * 8192,
                max: MAX_GUARD_BYTES
            })
        );
        // Variants count against the cap: 8 KiB of '/' costs far more than 8 KiB.
        let slashes = vec![b'/'; 8192];
        assert!(guard_cost(&slashes) > MAX_GUARD_BYTES);
        assert!(matches!(
            EchoAutomaton::build([slashes.as_slice()]),
            Err(GuardError::TooLarge { .. })
        ));
    }

    /// The definition, written the slow way: the earliest stream position
    /// at which some pattern window ends.
    fn naive_trip(patterns: &[Zeroizing<Vec<u8>>], stream: &[u8]) -> Option<(usize, usize)> {
        (0..stream.len()).find_map(|end| {
            patterns
                .iter()
                .flat_map(|p| p.windows(p.len().min(WINDOW)))
                .filter(|w| end + 1 >= w.len() && &stream[end + 1 - w.len()..=end] == *w)
                .map(|w| (end, w.len()))
                .max_by_key(|&(_, len)| len)
        })
    }

    /// #tooth: differential test against the naive definition on random
    /// streams over a tiny alphabet (so partial and overlapping matches are
    /// dense), at several chunkings. Trips exactly where the definition
    /// says, releases no byte of the tripping window, and otherwise passes
    /// the stream through unchanged.
    #[test]
    fn tooth_matches_the_naive_definition() {
        let mut x = 0x2545_F491u32;
        let mut next = move |n: u32| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x % n
        };
        let alphabet = b"ab/\"";
        let mut trips = 0;
        for round in 0..400 {
            let secrets: Vec<Vec<u8>> = (0..1 + next(3))
                .map(|_| {
                    (0..8 + next(30))
                        .map(|_| alphabet[next(4) as usize])
                        .collect()
                })
                .collect();
            let refs: Vec<&[u8]> = secrets.iter().map(Vec::as_slice).collect();
            let patterns: Vec<Zeroizing<Vec<u8>>> = refs.iter().flat_map(|s| variants(s)).collect();
            let mut stream: Vec<u8> = (0..next(200))
                .map(|_| b"ab/\"\\%2Ff\n"[next(10) as usize])
                .collect();
            if round % 3 == 0 {
                // Plant a fragment of a pattern so trips are common.
                let p = &patterns[next(patterns.len() as u32) as usize];
                let start = next(p.len() as u32) as usize;
                let at = next(stream.len() as u32 + 1) as usize;
                stream.splice(at..at, p[start..].iter().copied());
            }
            let expected = naive_trip(&patterns, &stream);
            trips += usize::from(expected.is_some());
            for width in [1, 2, 5, 16, 17, 1000] {
                let chunks: Vec<&[u8]> = stream.chunks(width).collect();
                let (out, tripped) = run(&refs, &chunks);
                match expected {
                    None => {
                        assert!(!tripped, "round {round} width {width}: false trip");
                        assert_eq!(out, stream, "round {round} width {width}");
                    }
                    Some((end, window)) => {
                        assert!(
                            tripped,
                            "round {round} width {width}: missed window ending at {end}"
                        );
                        assert!(stream.starts_with(&out));
                        assert!(
                            out.len() <= end + 1 - window,
                            "round {round} width {width}: released window bytes"
                        );
                        if width == 1 {
                            // With one-byte chunks the release is exact up
                            // to the holdback, which is below WINDOW.
                            assert!(out.len() + WINDOW > end, "round {round}: over-withheld");
                        }
                    }
                }
            }
            assert_eq!(
                automaton(&refs).contains(&stream),
                expected.is_some(),
                "round {round}"
            );
        }
        assert!(
            trips > 20 && trips < 380,
            "test streams should mix both outcomes ({trips})"
        );
    }

    /// Measurements, not assertions. Run with
    /// `cargo test --release -p keygate-core bench_guard -- --ignored --nocapture`.
    #[test]
    #[ignore = "benchmark"]
    fn bench_guard() {
        use std::time::Instant;
        let key = |seed: u32, len: usize| -> Vec<u8> {
            let mut x = 0x9E37_79B9u32.wrapping_mul(seed + 1);
            (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                        [(x % 64) as usize]
                })
                .collect()
        };
        // SSE-like traffic: JSON deltas of base64-alphabet text.
        let mut stream = Vec::new();
        let mut i = 0u32;
        while stream.len() < 32 << 20 {
            stream.extend_from_slice(b"data: {\"delta\":\"");
            stream.extend_from_slice(&key(1_000_000 + i, 96));
            stream.extend_from_slice(b"\"}\n\n");
            i += 1;
        }
        for (label, count, len) in [
            ("1 x 108 B", 1, 108),
            ("32 x 108 B", 32, 108),
            ("8 x 8 KiB (cap)", 8, 8192),
        ] {
            let secrets: Vec<Vec<u8>> = (0..count).map(|s| key(s, len)).collect();
            let started = Instant::now();
            let auto = Arc::new(EchoAutomaton::build(secrets.iter().map(Vec::as_slice)).unwrap());
            let build = started.elapsed();
            let mut guard = EchoGuard::new(auto.clone());
            let mut out = Vec::with_capacity(stream.len());
            let started = Instant::now();
            for chunk in stream.chunks(4096) {
                guard.push(chunk, &mut out).unwrap();
            }
            guard.finish(&mut out).unwrap();
            let scan = started.elapsed();
            assert_eq!(out.len(), stream.len());
            println!(
                "guard {label}: {} pattern bytes, {} KiB tables, built in {build:?}, scanned {:.0} MiB/s",
                auto.pattern_bytes(),
                auto.table_bytes() / 1024,
                (stream.len() >> 20) as f64 / scan.as_secs_f64()
            );
        }
    }
}
