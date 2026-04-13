use binary_patricia_merkle_trie::{
    blake2b_256, verify_proof, BinaryPatriciaTrie, TrieDB, EMPTY_ROOT,
};

// ── Basic operations ────────────────────────────────────────────

#[test]
fn empty_trie_has_empty_root() {
    let trie = BinaryPatriciaTrie::new();
    assert_eq!(trie.root_hash(), EMPTY_ROOT);
}

#[test]
fn empty_trie_get_returns_none() {
    let trie = BinaryPatriciaTrie::new();
    assert_eq!(trie.get(b"anything"), None);
}

#[test]
fn insert_single_key_and_retrieve() {
    let mut trie = BinaryPatriciaTrie::new();
    trie.insert(b"key1", b"value1".to_vec());
    assert_eq!(trie.get(b"key1"), Some(b"value1".to_vec()));
}

#[test]
fn insert_returns_old_value_on_update() {
    let mut trie = BinaryPatriciaTrie::new();
    assert_eq!(trie.insert(b"key1", b"v1".to_vec()), None);
    assert_eq!(
        trie.insert(b"key1", b"v2".to_vec()),
        Some(b"v1".to_vec())
    );
    assert_eq!(trie.get(b"key1"), Some(b"v2".to_vec()));
}

#[test]
fn insert_multiple_keys_and_retrieve_all() {
    let mut trie = BinaryPatriciaTrie::new();
    let keys: Vec<Vec<u8>> = (0..20u8).map(|i| vec![i]).collect();

    for (i, key) in keys.iter().enumerate() {
        trie.insert(key, format!("value_{i}").into_bytes());
    }

    for (i, key) in keys.iter().enumerate() {
        assert_eq!(
            trie.get(key),
            Some(format!("value_{i}").into_bytes()),
            "failed to retrieve key {i}"
        );
    }
}

#[test]
fn get_missing_key_returns_none() {
    let mut trie = BinaryPatriciaTrie::new();
    trie.insert(b"exists", b"yes".to_vec());
    assert_eq!(trie.get(b"missing"), None);
}

// ── Delete ──────────────────────────────────────────────────────

#[test]
fn delete_existing_key() {
    let mut trie = BinaryPatriciaTrie::new();
    trie.insert(b"key1", b"v1".to_vec());
    trie.insert(b"key2", b"v2".to_vec());

    let old = trie.delete(b"key1");
    assert_eq!(old, Some(b"v1".to_vec()));
    assert_eq!(trie.get(b"key1"), None);
    assert_eq!(trie.get(b"key2"), Some(b"v2".to_vec()));
}

#[test]
fn delete_missing_key_returns_none() {
    let mut trie = BinaryPatriciaTrie::new();
    trie.insert(b"key1", b"v1".to_vec());
    assert_eq!(trie.delete(b"nope"), None);
}

#[test]
fn delete_only_key_results_in_none_root() {
    let mut trie = BinaryPatriciaTrie::new();
    trie.insert(b"only", b"one".to_vec());
    trie.delete(b"only");
    // After deleting the only key, root should be None (empty trie).
    assert_eq!(trie.root_hash(), EMPTY_ROOT);
}

#[test]
fn insert_delete_insert_same_key() {
    let mut trie = BinaryPatriciaTrie::new();
    trie.insert(b"key", b"v1".to_vec());
    trie.delete(b"key");
    assert_eq!(trie.get(b"key"), None);
    trie.insert(b"key", b"v2".to_vec());
    assert_eq!(trie.get(b"key"), Some(b"v2".to_vec()));
}

// ── Root hash determinism ───────────────────────────────────────

#[test]
fn root_hash_changes_after_insert() {
    let mut trie = BinaryPatriciaTrie::new();
    let root0 = trie.root_hash();
    trie.insert(b"k1", b"v1".to_vec());
    let root1 = trie.root_hash();
    trie.insert(b"k2", b"v2".to_vec());
    let root2 = trie.root_hash();

    assert_ne!(root0, root1);
    assert_ne!(root1, root2);
}

#[test]
fn same_inserts_different_order_same_root() {
    let mut trie_a = BinaryPatriciaTrie::new();
    let mut trie_b = BinaryPatriciaTrie::new();

    trie_a.insert(b"alpha", b"1".to_vec());
    trie_a.insert(b"beta", b"2".to_vec());
    trie_a.insert(b"gamma", b"3".to_vec());

    trie_b.insert(b"gamma", b"3".to_vec());
    trie_b.insert(b"alpha", b"1".to_vec());
    trie_b.insert(b"beta", b"2".to_vec());

    assert_eq!(trie_a.root_hash(), trie_b.root_hash());
}

#[test]
fn root_hash_changes_after_delete() {
    let mut trie = BinaryPatriciaTrie::new();
    trie.insert(b"k1", b"v1".to_vec());
    trie.insert(b"k2", b"v2".to_vec());
    let root_before = trie.root_hash();

    trie.delete(b"k1");
    let root_after = trie.root_hash();
    assert_ne!(root_before, root_after);
}

// ── Extension nodes (shared prefixes) ───────────────────────────

#[test]
fn extension_node_created_for_shared_prefix() {
    let mut trie = BinaryPatriciaTrie::new();

    // These keys share a long prefix (same first bytes).
    let key1 = {
        let mut k = vec![0xAA; 16];
        k.push(0x01);
        k
    };
    let key2 = {
        let mut k = vec![0xAA; 16];
        k.push(0x02);
        k
    };

    trie.insert(&key1, b"v1".to_vec());
    trie.insert(&key2, b"v2".to_vec());

    assert_eq!(trie.get(&key1), Some(b"v1".to_vec()));
    assert_eq!(trie.get(&key2), Some(b"v2".to_vec()));
}

#[test]
fn substrate_like_storage_keys_with_pallet_prefix() {
    let mut trie = BinaryPatriciaTrie::new();

    // Simulate FRAME storage keys: twox128(pallet) ++ twox128(item) ++ key
    // All keys in the same pallet share a 128-bit prefix.
    let pallet_prefix = blake2b_256(b"Balances");
    let make_key = |suffix: &[u8]| {
        let mut key = pallet_prefix.to_vec();
        key.extend_from_slice(suffix);
        key
    };

    let k1 = make_key(b"Alice");
    let k2 = make_key(b"Bob");
    let k3 = make_key(b"Charlie");

    trie.insert(&k1, b"100".to_vec());
    trie.insert(&k2, b"200".to_vec());
    trie.insert(&k3, b"300".to_vec());

    assert_eq!(trie.get(&k1), Some(b"100".to_vec()));
    assert_eq!(trie.get(&k2), Some(b"200".to_vec()));
    assert_eq!(trie.get(&k3), Some(b"300".to_vec()));
}

// ── Edge cases ──────────────────────────────────────────────────

#[test]
fn single_byte_keys() {
    let mut trie = BinaryPatriciaTrie::new();
    for b in 0..=255u8 {
        trie.insert(&[b], vec![b]);
    }
    for b in 0..=255u8 {
        assert_eq!(trie.get(&[b]), Some(vec![b]));
    }
}

#[test]
fn empty_value() {
    let mut trie = BinaryPatriciaTrie::new();
    trie.insert(b"key", vec![]);
    assert_eq!(trie.get(b"key"), Some(vec![]));
}

#[test]
fn large_value() {
    let mut trie = BinaryPatriciaTrie::new();
    let big = vec![0xAB; 10_000];
    trie.insert(b"big", big.clone());
    assert_eq!(trie.get(b"big"), Some(big));
}

#[test]
fn keys_that_are_prefixes_of_each_other() {
    let mut trie = BinaryPatriciaTrie::new();

    // key "a" is a prefix of key "ab".
    trie.insert(b"a", b"short".to_vec());
    trie.insert(b"ab", b"long".to_vec());

    assert_eq!(trie.get(b"a"), Some(b"short".to_vec()));
    assert_eq!(trie.get(b"ab"), Some(b"long".to_vec()));
}

// ── Proofs ──────────────────────────────────────────────────────

#[test]
fn proof_for_existing_key() {
    let mut trie = BinaryPatriciaTrie::new();
    trie.insert(b"key1", b"v1".to_vec());
    trie.insert(b"key2", b"v2".to_vec());
    trie.insert(b"key3", b"v3".to_vec());

    let root = trie.root_hash();
    let proof = trie.generate_proof(b"key2");

    let result = verify_proof(&root, b"key2", &proof).unwrap();
    assert_eq!(result, Some(b"v2".to_vec()));
}

#[test]
fn proof_for_missing_key() {
    let mut trie = BinaryPatriciaTrie::new();
    trie.insert(b"key1", b"v1".to_vec());
    trie.insert(b"key2", b"v2".to_vec());

    let root = trie.root_hash();
    let proof = trie.generate_proof(b"missing");

    let result = verify_proof(&root, b"missing", &proof).unwrap();
    assert_eq!(result, None);
}

#[test]
fn proof_for_empty_trie() {
    let trie = BinaryPatriciaTrie::new();
    let root = trie.root_hash();
    let proof = trie.generate_proof(b"any");

    let result = verify_proof(&root, b"any", &proof).unwrap();
    assert_eq!(result, None);
}

#[test]
fn proof_invalid_with_wrong_root() {
    let mut trie = BinaryPatriciaTrie::new();
    trie.insert(b"key1", b"v1".to_vec());

    let proof = trie.generate_proof(b"key1");
    let wrong_root = [0xFFu8; 32];

    let result = verify_proof(&wrong_root, b"key1", &proof);
    assert!(result.is_err());
}

#[test]
fn proof_verified_for_all_keys_in_trie() {
    let mut trie = BinaryPatriciaTrie::new();
    let entries: Vec<(Vec<u8>, Vec<u8>)> = (0..50u8)
        .map(|i| (blake2b_256(&[i]).to_vec(), format!("val_{i}").into_bytes()))
        .collect();

    for (k, v) in &entries {
        trie.insert(k, v.clone());
    }

    let root = trie.root_hash();

    for (k, v) in &entries {
        let proof = trie.generate_proof(k);
        let result = verify_proof(&root, k, &proof).unwrap();
        assert_eq!(result.as_ref(), Some(v), "proof failed for key {}", hex::encode(k));
    }
}

// ── Benchmark-style test ────────────────────────────────────────

#[test]
fn benchmark_10k_inserts_and_proofs() {
    use std::time::Instant;

    let mut trie = BinaryPatriciaTrie::new();
    let keys: Vec<[u8; 32]> = (0..10_000u32)
        .map(|i| blake2b_256(&i.to_le_bytes()))
        .collect();

    let start = Instant::now();
    for (i, key) in keys.iter().enumerate() {
        trie.insert(key, format!("value_{i}").into_bytes());
    }
    let insert_time = start.elapsed();

    let root = trie.root_hash();
    println!("\n=== Benchmark Results ===");
    println!("Inserted 10,000 keys in {insert_time:?}");
    println!("Root: 0x{}", hex::encode(root));

    // Generate and verify proofs for 100 random keys.
    let proof_keys = &keys[..100];
    let start = Instant::now();
    let mut total_proof_size = 0usize;

    for key in proof_keys {
        let proof = trie.generate_proof(key);
        total_proof_size += proof.encoded_size();
        let result = verify_proof(&root, key, &proof).unwrap();
        assert!(result.is_some());
    }

    let proof_time = start.elapsed();
    let avg_proof_size = total_proof_size / proof_keys.len();

    println!("Generated & verified 100 proofs in {proof_time:?}");
    println!("Average proof size: {avg_proof_size} bytes");
    println!(
        "For comparison: radix-16 MPT proofs are typically 800-1200 bytes for a trie of this size"
    );
    println!("DB node count: {}", trie.db().len());
}
