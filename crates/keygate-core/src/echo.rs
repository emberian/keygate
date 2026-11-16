//! `EchoGuard`: a multi-secret streaming scrubber.
//!
//! An upstream that reflects the injected credential (error page, debug
//! echo, prompt-injected model output) must not get it past keygate, even
//! when the secret straddles network chunks. The guard runs a dense
//! Aho-Corasick DFA over every active secret and keeps its state across
//! chunks. The DFA state's depth is exactly the length of the longest suffix
//! of the stream so far that is a prefix of some secret, so that many bytes
//! are held back and everything before them is released immediately. A full
//! match trips the guard before any byte of the occurrence has been emitted.
//!
//! The automaton is hand-rolled rather than borrowed from a crate because
//! its tables encode the secrets and must be zeroed on drop.

use std::collections::VecDeque;
use std::sync::Arc;
use zeroize::Zeroize;

/// Secrets shorter than this are not guardable (they would match ordinary
/// traffic); `set` refuses them.
pub const MIN_SECRET_LEN: usize = 8;

const ROOT: u32 = 0;

pub struct EchoAutomaton {
    /// Full transition table: `next[state][byte]`.
    next: Vec<[u32; 256]>,
    /// Trie depth of each state.
    depth: Vec<u32>,
    /// State is, or has a suffix link chain reaching, a whole secret.
    hit: Vec<bool>,
}

impl EchoAutomaton {
    pub fn build<'a>(secrets: impl IntoIterator<Item = &'a [u8]>) -> Self {
        let mut next = vec![[u32::MAX; 256]];
        let mut depth = vec![0u32];
        let mut hit = vec![false];

        for secret in secrets {
            if secret.len() < MIN_SECRET_LEN {
                continue;
            }
            let mut state = ROOT as usize;
            for &b in secret {
                let slot = next[state][b as usize];
                state = if slot == u32::MAX {
                    let id = next.len();
                    next.push([u32::MAX; 256]);
                    depth.push(depth[state] + 1);
                    hit.push(false);
                    next[state][b as usize] = id as u32;
                    id
                } else {
                    slot as usize
                };
            }
            hit[state] = true;
        }

        // Breadth-first: resolve failure links and complete the trie into a DFA.
        let mut fail = vec![ROOT; next.len()];
        let mut queue = VecDeque::new();
        for slot in next[0].iter_mut() {
            match *slot {
                u32::MAX => *slot = ROOT,
                child => queue.push_back(child),
            }
        }
        while let Some(state) = queue.pop_front() {
            let state = state as usize;
            let via = fail[state] as usize;
            hit[state] |= hit[via];
            // `via` is strictly shallower than `state`, so its row is final.
            let mut via_row = next[via];
            for (slot, &fallback) in next[state].iter_mut().zip(via_row.iter()) {
                match *slot {
                    u32::MAX => *slot = fallback,
                    child => {
                        fail[child as usize] = fallback;
                        queue.push_back(child);
                    }
                }
            }
            via_row.zeroize();
        }
        EchoAutomaton { next, depth, hit }
    }

    /// True when no secret is guarded (every scan passes).
    pub fn is_empty(&self) -> bool {
        self.next.len() == 1
    }

    /// Whole-buffer scan, for response heads and buffered bodies.
    pub fn contains(&self, haystack: &[u8]) -> bool {
        let mut state = ROOT;
        haystack.iter().any(|&b| {
            state = self.next[state as usize][b as usize];
            self.hit[state as usize]
        })
    }
}

impl Drop for EchoAutomaton {
    fn drop(&mut self) {
        for row in &mut self.next {
            row.zeroize();
        }
        self.depth.zeroize();
    }
}

/// The guard tripped: a guarded secret occurred in the stream.
#[derive(Debug, PartialEq, Eq)]
pub struct Withheld;

/// Streaming state for one response body.
pub struct EchoGuard {
    automaton: Arc<EchoAutomaton>,
    state: u32,
    held: Vec<u8>,
    tripped: bool,
}

impl EchoGuard {
    pub fn new(automaton: Arc<EchoAutomaton>) -> Self {
        EchoGuard {
            automaton,
            state: ROOT,
            held: Vec::new(),
            tripped: false,
        }
    }

    /// Bytes currently withheld pending the next chunk.
    pub fn held_len(&self) -> usize {
        self.held.len()
    }

    /// Feed one chunk. Bytes that are now provably not part of a secret
    /// occurrence are appended to `out`. On a match nothing from this chunk
    /// or the holdback is released, the buffers are zeroed, and every later
    /// call fails too.
    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> Result<(), Withheld> {
        if self.tripped {
            return Err(Withheld);
        }
        for &b in chunk {
            self.state = self.automaton.next[self.state as usize][b as usize];
            if self.automaton.hit[self.state as usize] {
                self.trip();
                return Err(Withheld);
            }
        }
        let keep = self.automaton.depth[self.state as usize] as usize;
        let total = self.held.len() + chunk.len();
        debug_assert!(keep <= total);
        let release = total - keep;
        if release >= self.held.len() {
            let from_chunk = release - self.held.len();
            out.extend_from_slice(&self.held);
            out.extend_from_slice(&chunk[..from_chunk]);
            self.held.zeroize();
            self.held.extend_from_slice(&chunk[from_chunk..]);
        } else {
            out.extend_from_slice(&self.held[..release]);
            self.held.drain(..release);
            self.held.extend_from_slice(chunk);
        }
        Ok(())
    }

    /// End of stream: the holdback is a strict prefix of a secret that never
    /// completed, so it is ordinary data and is released.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), Withheld> {
        if self.tripped {
            return Err(Withheld);
        }
        out.extend_from_slice(&self.held);
        self.held.zeroize();
        self.state = ROOT;
        Ok(())
    }

    fn trip(&mut self) {
        self.tripped = true;
        self.held.zeroize();
        self.state = ROOT;
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

    fn guard(secrets: &[&[u8]]) -> EchoGuard {
        EchoGuard::new(Arc::new(EchoAutomaton::build(secrets.iter().copied())))
    }

    /// Feed `chunks`; return what reached the caller and whether it tripped.
    fn run(secrets: &[&[u8]], chunks: &[&[u8]]) -> (Vec<u8>, bool) {
        let mut g = guard(secrets);
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

    #[test]
    fn near_miss_is_released_in_full_and_in_order() {
        let stream = b"prefix sk-ant-secret1234X and sk-ant- again";
        for size in 1..stream.len() {
            let chunks: Vec<&[u8]> = stream.chunks(size).collect();
            let (out, tripped) = run(&[SECRET], &chunks);
            assert!(!tripped, "chunk size {size}");
            assert_eq!(out, stream, "chunk size {size}");
        }
    }

    #[test]
    fn holdback_is_only_the_matching_suffix() {
        let mut g = guard(&[SECRET]);
        let mut out = Vec::new();
        g.push(b"abcdef sk-an", &mut out).unwrap();
        assert_eq!(out, b"abcdef ");
        assert_eq!(g.held_len(), 5);
        g.push(b"x", &mut out).unwrap();
        assert_eq!(out, b"abcdef sk-anx");
        assert_eq!(g.held_len(), 0);
    }

    /// The holdback must shrink to the longest *still viable* prefix when a
    /// longer candidate dies (the failure-link case).
    #[test]
    fn overlapping_prefix_restart() {
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
    }

    /// #tooth: several secrets, one a suffix-overlap of another, all guarded.
    #[test]
    fn tooth_multi_secret() {
        let a: &[u8] = b"sk-ant-secret12345";
        let b: &[u8] = b"ghp_0123456789abcdef";
        let c: &[u8] = b"secret12345-and-more";
        for (needle, chunks) in [
            (a, vec![b"x sk-ant-secr".as_slice(), b"et12345"]),
            (b, vec![b"y ghp_0123", b"456789abc", b"def"]),
            (c, vec![b"z secret1234", b"5-and-more"]),
        ] {
            let (out, tripped) = run(&[a, b, c], &chunks);
            assert!(tripped, "{:?}", std::str::from_utf8(needle));
            assert_eq!(out.len(), 2);
        }
        // `c` begins inside `d`. When `d`'s candidate dies at the '4', the
        // guard must follow the suffix link into `c`'s partial match: the
        // bytes before it are released, the rest stays held, and `c` trips.
        let d: &[u8] = b"sk-ant-secret12399";
        let (out, tripped) = run(&[d, c], &[b"sk-ant-secret123", b"4", b"5-and-more"]);
        assert!(tripped);
        assert_eq!(out, b"sk-ant-");
    }

    #[test]
    fn tripped_guard_stays_tripped() {
        let mut g = guard(&[SECRET]);
        let mut out = Vec::new();
        assert_eq!(g.push(SECRET, &mut out), Err(Withheld));
        assert_eq!(g.push(b"harmless", &mut out), Err(Withheld));
        assert_eq!(g.finish(&mut out), Err(Withheld));
        assert!(out.is_empty());
    }

    #[test]
    fn whole_scan_and_short_secrets() {
        let auto = EchoAutomaton::build([SECRET, b"short".as_slice()]);
        assert!(auto.contains(b"x-debug: Bearer sk-ant-secret12345\r\n"));
        assert!(!auto.contains(b"x-debug: Bearer sk-ant-secret1234\r\n"));
        assert!(
            !auto.contains(b"short"),
            "sub-minimum secrets are not guarded"
        );
        assert!(EchoAutomaton::build([b"short".as_slice()]).is_empty());
    }
}
