use std::collections::HashMap;
use std::path::Path;

use nomt::hasher::Blake3Hasher;
use nomt::{KeyReadWrite, Nomt, Options, SessionParams};

use crate::trie::db::TrieDB;
use crate::trie::node::Hash;

/// NOMT-backed content-addressed store for trie nodes.
///
/// Uses NOMT as a persistent key-value database: the 32-byte node hash is
/// used directly as the NOMT key path, and the encoded node bytes are stored
/// as the value.
///
/// Writes are buffered in memory and flushed to NOMT via `flush()`. Reads
/// check the buffer first, then fall back to NOMT on disk.
pub struct NomtTrieDB {
    nomt: Nomt<Blake3Hasher>,
    /// In-memory buffer: `None` means the key was deleted.
    buffer: HashMap<Hash, Option<Vec<u8>>>,
}

impl NomtTrieDB {
    /// Open or create a NOMT database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, anyhow::Error> {
        let mut opts = Options::new();
        opts.path(path.as_ref());
        opts.commit_concurrency(1);
        let nomt = Nomt::<Blake3Hasher>::open(opts)?;
        Ok(Self {
            nomt,
            buffer: HashMap::new(),
        })
    }

    /// Flush all pending writes to NOMT in a single commit.
    pub fn flush(&mut self) -> Result<(), anyhow::Error> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let session = self.nomt.begin_session(SessionParams::default());

        let entries: Vec<(Hash, Option<Vec<u8>>)> = self.buffer.drain().collect();

        for (hash, _) in &entries {
            session.warm_up(*hash);
        }

        let mut accesses: Vec<(Hash, KeyReadWrite)> = entries
            .into_iter()
            .map(|(hash, value)| (hash, KeyReadWrite::Write(value)))
            .collect();
        accesses.sort_by_key(|(k, _)| *k);

        let finished = session.finish(accesses)?;
        finished.commit(&self.nomt)?;

        Ok(())
    }
}

impl TrieDB for NomtTrieDB {
    fn insert(&mut self, hash: Hash, data: Vec<u8>) {
        self.buffer.insert(hash, Some(data));
    }

    fn get(&self, hash: &Hash) -> Option<Vec<u8>> {
        // Check buffer first.
        if let Some(entry) = self.buffer.get(hash) {
            return entry.clone();
        }

        // Read from NOMT on disk.
        let session = self.nomt.begin_session(SessionParams::default());
        session.read(*hash).ok().flatten()
    }

    fn remove(&mut self, hash: &Hash) {
        self.buffer.insert(*hash, None);
    }

    fn len(&self) -> usize {
        self.buffer.values().filter(|v| v.is_some()).count()
    }
}
