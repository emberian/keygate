//! `SecretBytes`: the only container raw credentials are allowed to live in.

use std::fmt;
use zeroize::Zeroize;

/// Heap bytes that are zeroed on drop, print redacted, and deliberately
/// implement neither `Display`, `Serialize` nor `Clone`.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretBytes(bytes)
    }

    pub fn random(len: usize) -> std::io::Result<Self> {
        let mut buf = vec![0u8; len];
        crate::random_bytes(&mut buf)?;
        Ok(SecretBytes(buf))
    }

    /// The raw bytes. Every call site is a place a secret can escape; keep
    /// the borrow short and never format it.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// An explicit second copy (there is no `Clone`, so copies are greppable).
    pub fn duplicate(&self) -> Self {
        SecretBytes(self.0.clone())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(<redacted; {} bytes>)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = SecretBytes::new(b"sk-ant-secret12345".to_vec());
        let shown = format!("{s:?}");
        assert!(!shown.contains("sk-ant"));
        assert!(shown.contains("18 bytes"));
    }
}
