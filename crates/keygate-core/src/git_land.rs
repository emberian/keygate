//! Wire body of a fast-forward-only service's POST /git/land operation.
//! The service must update exactly this ref with expected_old as its CAS.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitLand {
    pub repo: String,
    pub reference: String,
    pub expected_old: String,
    pub new_oid: String,
}

impl GitLand {
    pub fn valid(&self) -> bool {
        let oid = |s: &str| {
            matches!(s.len(), 40 | 64)
                && s.bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
                && s.bytes().any(|b| b != b'0')
        };
        crate::valid_name(&self.repo)
            && self.reference.starts_with("refs/heads/")
            && self.reference.split('/').all(|s| {
                !s.is_empty() && !s.starts_with('.') && !s.ends_with('.') && !s.ends_with(".lock")
            })
            && !self.reference.contains("..")
            && self
                .reference
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
            && oid(&self.expected_old)
            && oid(&self.new_oid)
            && self.expected_old.len() == self.new_oid.len()
            && self.expected_old != self.new_oid
    }
}
