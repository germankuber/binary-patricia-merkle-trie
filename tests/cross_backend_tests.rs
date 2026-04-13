//! Cross-backend correctness tests.
//!
//! These tests verify that ALL backends produce consistent behavior:
//! same data in → same data out, same proofs verify, and the Patricia
//! backends produce identical root hashes regardless of storage engine.

use binary_patricia_merkle_trie::{
    blake2b_256, verify_proof, BinaryPatriciaTrie, NomtTrieDB, RocksTrieDB,
};
use std::path::PathBuf;

fn temp_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("cross_backend_tests").join(name);
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Generate deterministic test entries.
fn test_entries(count: usize) -> Vec<([u8; 32], Vec<u8>)> {
    (0..count)
        .map(|i| {
            let key = blake2b_256(&(i as u32).to_le_bytes());
            let value = format!("value_{i}").into_bytes();
            (key, value)
        })
        .collect()
}

// ── Root hash consistency ───────────────────────────────────────

#[test]
fn all_patricia_backends_produce_same_root() {
    let entries = test_entries(500);

    // Memory
    let mut mem_trie = BinaryPatriciaTrie::new();
    for (k, v) in &entries {
        mem_trie.insert(k, v.clone());
    }

    // RocksDB
    let rocks_path = temp_path("same_root_rocks");
    let db = RocksTrieDB::open(&rocks_path).unwrap();
    let mut rocks_trie = BinaryPatriciaTrie::with_db(db);
    for (k, v) in &entries {
        rocks_trie.insert(k, v.clone());
    }

    // NomtDB
    let nomt_path = temp_path("same_root_nomt");
    let db = NomtTrieDB::open(&nomt_path).unwrap();
    let mut nomt_trie = BinaryPatriciaTrie::with_db(db);
    for (k, v) in &entries {
        nomt_trie.insert(k, v.clone());
    }

    let mem_root = mem_trie.root_hash();
    let rocks_root = rocks_trie.root_hash();
    let nomt_root = nomt_trie.root_hash();

    assert_eq!(
        mem_root, rocks_root,
        "Memory and Rocks roots differ"
    );
    assert_eq!(
        mem_root, nomt_root,
        "Memory and NomtDB roots differ"
    );
}

// ── Data consistency ────────────────────────────────────────────

#[test]
fn all_backends_return_same_values() {
    let entries = test_entries(200);

    let mut mem_trie = BinaryPatriciaTrie::new();
    let rocks_path = temp_path("same_values_rocks");
    let mut rocks_trie = BinaryPatriciaTrie::with_db(
        RocksTrieDB::open(&rocks_path).unwrap(),
    );
    let nomt_path = temp_path("same_values_nomt");
    let mut nomt_trie = BinaryPatriciaTrie::with_db(
        NomtTrieDB::open(&nomt_path).unwrap(),
    );

    for (k, v) in &entries {
        mem_trie.insert(k, v.clone());
        rocks_trie.insert(k, v.clone());
        nomt_trie.insert(k, v.clone());
    }

    // Every key returns the same value across all backends.
    for (k, v) in &entries {
        let mem_val = mem_trie.get(k);
        let rocks_val = rocks_trie.get(k);
        let nomt_val = nomt_trie.get(k);

        assert_eq!(mem_val.as_ref(), Some(v), "Memory missing key");
        assert_eq!(rocks_val.as_ref(), Some(v), "Rocks missing key");
        assert_eq!(nomt_val.as_ref(), Some(v), "NomtDB missing key");
    }

    // Missing keys return None on all backends.
    let missing = blake2b_256(b"does_not_exist");
    assert_eq!(mem_trie.get(&missing), None);
    assert_eq!(rocks_trie.get(&missing), None);
    assert_eq!(nomt_trie.get(&missing), None);
}

// ── Proof cross-verification ────────────────────────────────────

#[test]
fn proof_from_one_backend_verifies_against_another() {
    let entries = test_entries(100);

    let mut mem_trie = BinaryPatriciaTrie::new();
    let rocks_path = temp_path("proof_cross_rocks");
    let mut rocks_trie = BinaryPatriciaTrie::with_db(
        RocksTrieDB::open(&rocks_path).unwrap(),
    );

    for (k, v) in &entries {
        mem_trie.insert(k, v.clone());
        rocks_trie.insert(k, v.clone());
    }

    let mem_root = mem_trie.root_hash();
    let rocks_root = rocks_trie.root_hash();
    assert_eq!(mem_root, rocks_root);

    // Generate proof from Memory, verify against the shared root.
    for (k, v) in &entries {
        let mem_proof = mem_trie.generate_proof(k);
        let rocks_proof = rocks_trie.generate_proof(k);

        // Both proofs verify against the same root.
        let mem_result = verify_proof(&mem_root, k, &mem_proof).unwrap();
        let rocks_result = verify_proof(&rocks_root, k, &rocks_proof).unwrap();

        assert_eq!(mem_result.as_ref(), Some(v));
        assert_eq!(rocks_result.as_ref(), Some(v));

        // Cross-verify: Memory proof verifies with Rocks root and vice versa.
        let cross1 = verify_proof(&rocks_root, k, &mem_proof).unwrap();
        let cross2 = verify_proof(&mem_root, k, &rocks_proof).unwrap();
        assert_eq!(cross1.as_ref(), Some(v));
        assert_eq!(cross2.as_ref(), Some(v));
    }
}

// ── Delete consistency ──────────────────────────────────────────

#[test]
fn delete_produces_same_root_across_backends() {
    let entries = test_entries(100);

    let mut mem_trie = BinaryPatriciaTrie::new();
    let rocks_path = temp_path("delete_roots_rocks");
    let mut rocks_trie = BinaryPatriciaTrie::with_db(
        RocksTrieDB::open(&rocks_path).unwrap(),
    );

    for (k, v) in &entries {
        mem_trie.insert(k, v.clone());
        rocks_trie.insert(k, v.clone());
    }

    // Delete the first 50 keys.
    for (k, _) in &entries[..50] {
        mem_trie.delete(k);
        rocks_trie.delete(k);
    }

    assert_eq!(
        mem_trie.root_hash(),
        rocks_trie.root_hash(),
        "Roots diverged after deletes"
    );

    // Deleted keys return None, remaining keys still work.
    for (k, _) in &entries[..50] {
        assert_eq!(mem_trie.get(k), None);
        assert_eq!(rocks_trie.get(k), None);
    }
    for (k, v) in &entries[50..] {
        assert_eq!(mem_trie.get(k), Some(v.clone()));
        assert_eq!(rocks_trie.get(k), Some(v.clone()));
    }
}

// ── Insert order independence ───────────────────────────────────

#[test]
fn all_backends_are_order_independent() {
    let entries = test_entries(100);
    let mut reversed = entries.clone();
    reversed.reverse();

    // Forward order
    let mut fwd = BinaryPatriciaTrie::new();
    for (k, v) in &entries {
        fwd.insert(k, v.clone());
    }

    // Reverse order
    let mut rev = BinaryPatriciaTrie::new();
    for (k, v) in &reversed {
        rev.insert(k, v.clone());
    }

    // Rocks forward
    let rocks_path = temp_path("order_rocks");
    let mut rocks = BinaryPatriciaTrie::with_db(
        RocksTrieDB::open(&rocks_path).unwrap(),
    );
    for (k, v) in &reversed {
        rocks.insert(k, v.clone());
    }

    assert_eq!(fwd.root_hash(), rev.root_hash(), "Forward != Reverse");
    assert_eq!(fwd.root_hash(), rocks.root_hash(), "Forward != Rocks(reverse)");
}
