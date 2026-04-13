use binary_patricia_merkle_trie::{
    blake2b_256, verify_proof, BinaryPatriciaTrie, RocksTrieDB,
};
use std::path::PathBuf;

fn temp_db_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("trie_tests").join(name);
    // Clean up from previous runs.
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn rocksdb_insert_and_get() {
    let path = temp_db_path("insert_and_get");
    let db = RocksTrieDB::open(&path).unwrap();
    let mut trie = BinaryPatriciaTrie::with_db(db);

    trie.insert(b"key1", b"value1".to_vec());
    trie.insert(b"key2", b"value2".to_vec());

    assert_eq!(trie.get(b"key1"), Some(b"value1".to_vec()));
    assert_eq!(trie.get(b"key2"), Some(b"value2".to_vec()));
    assert_eq!(trie.get(b"missing"), None);
}

#[test]
fn rocksdb_delete() {
    let path = temp_db_path("delete");
    let db = RocksTrieDB::open(&path).unwrap();
    let mut trie = BinaryPatriciaTrie::with_db(db);

    trie.insert(b"k1", b"v1".to_vec());
    trie.insert(b"k2", b"v2".to_vec());

    let old = trie.delete(b"k1");
    assert_eq!(old, Some(b"v1".to_vec()));
    assert_eq!(trie.get(b"k1"), None);
    assert_eq!(trie.get(b"k2"), Some(b"v2".to_vec()));
}

#[test]
fn rocksdb_root_determinism() {
    let path_a = temp_db_path("determinism_a");
    let path_b = temp_db_path("determinism_b");
    let db_a = RocksTrieDB::open(&path_a).unwrap();
    let db_b = RocksTrieDB::open(&path_b).unwrap();

    let mut trie_a = BinaryPatriciaTrie::with_db(db_a);
    let mut trie_b = BinaryPatriciaTrie::with_db(db_b);

    trie_a.insert(b"alpha", b"1".to_vec());
    trie_a.insert(b"beta", b"2".to_vec());

    trie_b.insert(b"beta", b"2".to_vec());
    trie_b.insert(b"alpha", b"1".to_vec());

    assert_eq!(trie_a.root_hash(), trie_b.root_hash());
}

#[test]
fn rocksdb_proof_generation_and_verification() {
    let path = temp_db_path("proofs");
    let db = RocksTrieDB::open(&path).unwrap();
    let mut trie = BinaryPatriciaTrie::with_db(db);

    let keys: Vec<[u8; 32]> = (0..100u32)
        .map(|i| blake2b_256(&i.to_le_bytes()))
        .collect();

    for (i, key) in keys.iter().enumerate() {
        trie.insert(key, format!("val_{i}").into_bytes());
    }

    let root = trie.root_hash();

    // Verify inclusion proofs.
    for (i, key) in keys.iter().enumerate() {
        let proof = trie.generate_proof(key);
        let result = verify_proof(&root, key, &proof).unwrap();
        assert_eq!(result, Some(format!("val_{i}").into_bytes()));
    }

    // Verify non-inclusion proof.
    let missing = blake2b_256(b"missing_key");
    let proof = trie.generate_proof(&missing);
    let result = verify_proof(&root, &missing, &proof).unwrap();
    assert_eq!(result, None);
}

#[test]
fn rocksdb_persistence_across_reopen() {
    let path = temp_db_path("persistence");

    let root_hash;

    // Write data and close.
    {
        let db = RocksTrieDB::open(&path).unwrap();
        let mut trie = BinaryPatriciaTrie::with_db(db);
        trie.insert(b"persistent_key", b"persistent_value".to_vec());
        root_hash = trie.root_hash();
    }

    // Reopen and verify data is still there.
    {
        let db = RocksTrieDB::open(&path).unwrap();
        let trie = BinaryPatriciaTrie::from_existing(db, root_hash);
        assert_eq!(
            trie.get(b"persistent_key"),
            Some(b"persistent_value".to_vec())
        );
        assert_eq!(trie.root_hash(), root_hash);
    }
}

#[test]
fn rocksdb_same_root_as_memory_db() {
    let path = temp_db_path("same_root");

    let mut mem_trie = BinaryPatriciaTrie::new();
    let db = RocksTrieDB::open(&path).unwrap();
    let mut rocks_trie = BinaryPatriciaTrie::with_db(db);

    let entries = vec![
        (b"key1".to_vec(), b"val1".to_vec()),
        (b"key2".to_vec(), b"val2".to_vec()),
        (b"key3".to_vec(), b"val3".to_vec()),
    ];

    for (k, v) in &entries {
        mem_trie.insert(k, v.clone());
        rocks_trie.insert(k, v.clone());
    }

    assert_eq!(mem_trie.root_hash(), rocks_trie.root_hash());
}
