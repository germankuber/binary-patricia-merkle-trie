use std::collections::HashMap;

use crate::trie::db::TrieDB;
use crate::trie::node::Hash;

/// In-memory content-addressed store: `blake2b_256(encoded_node) → encoded_node`.
///
/// Conceptually similar to Substrate's `memory-db`.
#[derive(Debug, Clone)]
pub struct MemoryDB {
    nodes: HashMap<Hash, Vec<u8>>,
}

impl MemoryDB {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }
}

impl TrieDB for MemoryDB {
    fn insert(&mut self, hash: Hash, data: Vec<u8>) {
        self.nodes.insert(hash, data);
    }

    fn get(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.nodes.get(hash).cloned()
    }

    fn remove(&mut self, hash: &Hash) {
        self.nodes.remove(hash);
    }

    fn len(&self) -> usize {
        self.nodes.len()
    }
}

impl Default for MemoryDB {
    fn default() -> Self {
        Self::new()
    }
}
