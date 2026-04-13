use std::path::Path;

use crate::trie::db::TrieDB;
use crate::trie::node::Hash;

/// RocksDB-backed content-addressed store for trie nodes.
///
/// Stores encoded trie nodes keyed by their Blake2b-256 hash.
/// Data is persisted to disk and survives process restarts.
pub struct RocksTrieDB {
    db: rocksdb::DB,
}

impl RocksTrieDB {
    /// Open or create a RocksDB database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, rocksdb::Error> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = rocksdb::DB::open(&opts, path)?;
        Ok(Self { db })
    }

    /// Open with a temporary directory (useful for testing).
    pub fn open_temporary(path: impl AsRef<Path>) -> Result<Self, rocksdb::Error> {
        Self::open(path)
    }

    /// Flush all pending writes to disk.
    pub fn flush(&self) -> Result<(), rocksdb::Error> {
        self.db.flush()
    }
}

impl TrieDB for RocksTrieDB {
    fn insert(&mut self, hash: Hash, data: Vec<u8>) {
        self.db
            .put(hash, data)
            .expect("rocksdb put failed");
    }

    fn get(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.db
            .get(hash)
            .expect("rocksdb get failed")
    }

    fn remove(&mut self, hash: &Hash) {
        self.db
            .delete(hash)
            .expect("rocksdb delete failed");
    }

    fn len(&self) -> usize {
        // RocksDB doesn't have an O(1) count. Use the estimate.
        self.db
            .property_int_value("rocksdb.estimate-num-keys")
            .ok()
            .flatten()
            .unwrap_or(0) as usize
    }
}
