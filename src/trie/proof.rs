use std::collections::HashMap;

use crate::trie::bits::BitVec;
use crate::trie::error::TrieError;
use crate::trie::node::{blake2b_256, Hash, Node, EMPTY_ROOT};

/// A storage proof — a set of encoded trie nodes sufficient to verify a key lookup.
#[derive(Debug, Clone)]
pub struct StorageProof {
    pub nodes: Vec<Vec<u8>>,
}

impl StorageProof {
    /// Total size in bytes of all proof nodes.
    pub fn encoded_size(&self) -> usize {
        self.nodes.iter().map(|n| n.len()).sum()
    }
}

/// Verify a merkle proof against a known root hash and key.
///
/// Returns:
/// - `Ok(Some(value))` if the key is provably present with that value.
/// - `Ok(None)` if the key is provably absent.
/// - `Err(...)` if the proof is invalid or incomplete.
pub fn verify_proof(
    root: &Hash,
    key: &[u8],
    proof: &StorageProof,
) -> Result<Option<Vec<u8>>, TrieError> {
    if *root == EMPTY_ROOT {
        return if proof.nodes.is_empty() {
            Ok(None)
        } else {
            Err(TrieError::InvalidProof)
        };
    }

    let mut node_map: HashMap<Hash, &[u8]> = HashMap::new();
    for encoded in &proof.nodes {
        let hash = blake2b_256(encoded);
        node_map.insert(hash, encoded);
    }

    let key_bits = BitVec::from_bytes(key);
    verify_recursive(&node_map, root, &key_bits, 0)
}

fn verify_recursive(
    node_map: &HashMap<Hash, &[u8]>,
    hash: &Hash,
    key_bits: &BitVec,
    depth: usize,
) -> Result<Option<Vec<u8>>, TrieError> {
    let encoded = node_map.get(hash).ok_or(TrieError::IncompleteProof)?;
    let node = Node::decode(encoded).map_err(|_| TrieError::InvalidProof)?;

    match node {
        Node::Leaf { partial, value } => {
            let remaining = key_bits.slice(depth, key_bits.len() - depth);
            if remaining == partial {
                Ok(Some(value))
            } else {
                Ok(None) // Key not present — non-inclusion proof.
            }
        }
        Node::Extension { partial, child } => {
            let remaining_len = key_bits.len() - depth;
            if remaining_len < partial.len() {
                return Ok(None);
            }
            let key_segment = key_bits.slice(depth, partial.len());
            if key_segment == partial {
                verify_recursive(node_map, &child, key_bits, depth + partial.len())
            } else {
                Ok(None)
            }
        }
        Node::Branch { left, right, value } => {
            if depth == key_bits.len() {
                return Ok(value);
            }
            let bit = key_bits.get(depth);
            let child_hash = if bit { right } else { left };
            match child_hash {
                Some(h) => verify_recursive(node_map, &h, key_bits, depth + 1),
                None => Ok(None), // No child on this side — key not present.
            }
        }
    }
}
