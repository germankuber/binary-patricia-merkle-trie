use std::fmt;

/// Errors that can occur during trie operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrieError {
    /// The proof is structurally invalid (bad encoding, wrong hashes).
    InvalidProof,
    /// The proof does not contain enough nodes to reach the target key.
    IncompleteProof,
    /// A node could not be decoded from its binary representation.
    DecodingError,
}

impl fmt::Display for TrieError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProof => write!(f, "invalid proof"),
            Self::IncompleteProof => write!(f, "incomplete proof"),
            Self::DecodingError => write!(f, "node decoding error"),
        }
    }
}

impl std::error::Error for TrieError {}
