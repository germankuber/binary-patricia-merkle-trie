use crate::trie::node::Hash;

/// Trait for trie node storage backends.
///
/// Implementations store encoded trie nodes keyed by their Blake2b-256 hash.
pub trait TrieDB {
    /// Insert encoded node bytes, keyed by their hash.
    fn insert(&mut self, hash: Hash, data: Vec<u8>);

    /// Retrieve encoded node bytes by hash.
    fn get(&self, hash: &Hash) -> Option<Vec<u8>>;

    /// Remove a node by hash.
    fn remove(&mut self, hash: &Hash);

    /// Number of stored nodes (may be expensive for disk-backed stores).
    fn len(&self) -> usize;

    /// Whether the store is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
