use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A serialized secret whose `Debug` output is always redacted and whose owned
/// buffer is cleared before it is released.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_exposes_secret() {
        let secret = SecretString::new("do-not-log-me");
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains(secret.expose()));
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn explicit_zeroize_clears_the_secret() {
        let mut secret = SecretString::new("erase-me");
        secret.zeroize();
        assert!(secret.is_empty());
    }
}
