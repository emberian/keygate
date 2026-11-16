//! `plain_path`: the only path shape keygate will sign off on.
//!
//! A plain path is `/` (zero segments) or `/seg/seg/...` where every segment is non-empty, is not
//! `.` or `..`, and uses a fixed unreserved alphabet. There is no
//! percent-encoding, so there is exactly one spelling of every path and no
//! proxy or router between keygate and the origin can normalize it into a
//! different one than the policy check saw.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    #[error("path must start with '/'")]
    NotAbsolute,
    #[error("path contains '%' (percent-encoding is refused)")]
    Percent,
    #[error("path contains a fragment or query delimiter")]
    Delimiter,
    #[error("path contains an empty segment")]
    EmptySegment,
    #[error("path contains a '.' or '..' segment")]
    DotSegment,
    #[error("path contains a byte outside the plain alphabet: {0:?}")]
    Byte(char),
    #[error("path is longer than {MAX_PATH_LEN} bytes")]
    TooLong,
    #[error("query contains a byte outside the allowed alphabet: {0:?}")]
    QueryByte(char),
}

pub const MAX_PATH_LEN: usize = 2048;

fn plain_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'_' | b'.' | b'~' | b':' | b'@' | b'+' | b'=' | b','
        )
}

/// A validated plain path. Construct with [`PlainPath::parse`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PlainPath(String);

impl PlainPath {
    pub fn parse(raw: &str) -> Result<Self, PathError> {
        if raw.len() > MAX_PATH_LEN {
            return Err(PathError::TooLong);
        }
        let Some(rest) = raw.strip_prefix('/') else {
            return Err(PathError::NotAbsolute);
        };
        for segment in rest.split('/').filter(|_| !rest.is_empty()) {
            if segment.is_empty() {
                return Err(PathError::EmptySegment);
            }
            if segment == "." || segment == ".." {
                return Err(PathError::DotSegment);
            }
            for &b in segment.as_bytes() {
                match b {
                    b'%' => return Err(PathError::Percent),
                    b'#' | b'?' => return Err(PathError::Delimiter),
                    b if plain_byte(b) => {}
                    _ => {
                        let c = segment
                            .chars()
                            .find(|c| !c.is_ascii() || !plain_byte(*c as u8));
                        return Err(PathError::Byte(c.unwrap_or(char::REPLACEMENT_CHARACTER)));
                    }
                }
            }
        }
        Ok(PlainPath(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0[1..].split('/').filter(|_| self.0.len() > 1)
    }

    /// Segment-wise prefix: `/repos` covers `/repos` and `/repos/x`, never
    /// `/reposx`.
    pub fn starts_with(&self, prefix: &PlainPath) -> bool {
        let mut mine = self.segments();
        prefix.segments().all(|p| mine.next() == Some(p))
    }

    pub fn under_any(&self, prefixes: &[PlainPath]) -> bool {
        prefixes.iter().any(|p| self.starts_with(p))
    }
}

impl fmt::Display for PlainPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Queries are opaque to routing, so percent-encoding is allowed there, but
/// fragments, whitespace, control and non-ASCII bytes are not.
pub fn check_query(query: &str) -> Result<(), PathError> {
    if query.len() > MAX_PATH_LEN {
        return Err(PathError::TooLong);
    }
    match query.chars().find(|&c| {
        !c.is_ascii_graphic()
            || matches!(
                c,
                '#' | '"' | '<' | '>' | '\\' | '^' | '`' | '{' | '|' | '}'
            )
    }) {
        Some(c) => Err(PathError::QueryByte(c)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #tooth: every normalization-differential spelling is refused.
    #[test]
    fn tooth_refuses_non_plain_paths() {
        let cases: &[(&str, PathError)] = &[
            ("v1/messages", PathError::NotAbsolute),
            ("", PathError::NotAbsolute),
            ("//", PathError::EmptySegment),
            ("/v1//messages", PathError::EmptySegment),
            ("/v1/messages/", PathError::EmptySegment),
            ("/v1/./messages", PathError::DotSegment),
            ("/v1/../admin", PathError::DotSegment),
            ("/..", PathError::DotSegment),
            ("/v1/%2e%2e/admin", PathError::Percent),
            ("/v1/a%2fb", PathError::Percent),
            ("/v1/messages#frag", PathError::Delimiter),
            ("/v1/messages?x=1", PathError::Delimiter),
            ("/v1/a b", PathError::Byte(' ')),
            ("/v1/a\\b", PathError::Byte('\\')),
            ("/v1/a;b", PathError::Byte(';')),
            ("/v1/caf\u{e9}", PathError::Byte('\u{e9}')),
            ("/v1/a\0b", PathError::Byte('\0')),
        ];
        for (raw, want) in cases {
            assert_eq!(PlainPath::parse(raw).as_ref(), Err(want), "{raw:?}");
        }
        assert_eq!(
            PlainPath::parse(&format!("/{}", "a".repeat(MAX_PATH_LEN))),
            Err(PathError::TooLong)
        );
    }

    #[test]
    fn accepts_plain_paths() {
        for raw in [
            "/",
            "/v1/messages",
            "/repos/o/r/issues",
            "/v1beta/models/gemini-pro:generateContent",
            "/a.b/c_d~e/@x",
        ] {
            assert_eq!(PlainPath::parse(raw).unwrap().as_str(), raw);
        }
    }

    #[test]
    fn prefix_is_segment_wise() {
        let p = |s| PlainPath::parse(s).unwrap();
        assert_eq!(p("/").segments().count(), 0);
        assert!(p("/repos").starts_with(&p("/")));
        assert!(!p("/").starts_with(&p("/repos")));
        assert!(p("/repos/o/r").starts_with(&p("/repos")));
        assert!(p("/repos").starts_with(&p("/repos")));
        assert!(!p("/reposx").starts_with(&p("/repos")));
        assert!(!p("/repo").starts_with(&p("/repos")));
        assert!(!p("/v1").starts_with(&p("/v1/messages")));
        assert!(p("/v1/messages").under_any(&[p("/x"), p("/v1")]));
        assert!(!p("/v2/messages").under_any(&[p("/x"), p("/v1")]));
    }

    #[test]
    fn query_alphabet() {
        assert!(check_query("beta=true&cursor=a%2Fb").is_ok());
        assert_eq!(check_query("a=1#frag"), Err(PathError::QueryByte('#')));
        assert_eq!(check_query("a=1 b"), Err(PathError::QueryByte(' ')));
        assert_eq!(check_query("a=\r\n"), Err(PathError::QueryByte('\r')));
    }
}
