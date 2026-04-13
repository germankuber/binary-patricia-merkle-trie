//! Cross-backend correctness tests.
//!
//! Every test runs against ALL 4 backends:
//! - Patricia + MemoryDB
//! - Patricia + RocksDB
//! - Patricia + NomtDB (our trie, NOMT storage)
//! - NOMT native (NOMT's own sparse merkle trie)

use binary_patricia_merkle_trie::{
    blake2b_256, verify_proof, BinaryPatriciaTrie, NomtTrieDB, RocksTrieDB, TrieDB,
};
use nomt::hasher::Blake3Hasher;
use nomt::{KeyReadWrite, Nomt, Options, SessionParams};
use std::path::PathBuf;

fn temp_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("cross_backend_tests").join(name);
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn test_entries(count: usize) -> Vec<([u8; 32], Vec<u8>)> {
    (0..count)
        .map(|i| {
            let key = blake2b_256(&(i as u32).to_le_bytes());
            let value = format!("value_{i}").into_bytes();
            (key, value)
        })
        .collect()
}

fn open_nomt(path: &std::path::Path) -> Nomt<Blake3Hasher> {
    let mut opts = Options::new();
    opts.path(path);
    opts.commit_concurrency(1);
    Nomt::<Blake3Hasher>::open(opts).unwrap()
}

fn nomt_insert(nomt: &Nomt<Blake3Hasher>, entries: &[([u8; 32], Vec<u8>)]) {
    let session = nomt.begin_session(SessionParams::default());
    for (k, _) in entries {
        session.warm_up(*k);
    }
    let mut accesses: Vec<_> = entries
        .iter()
        .map(|(k, v)| (*k, KeyReadWrite::Write(Some(v.clone()))))
        .collect();
    accesses.sort_by_key(|(k, _)| *k);
    let finished = session.finish(accesses).unwrap();
    finished.commit(nomt).unwrap();
}

fn nomt_delete(nomt: &Nomt<Blake3Hasher>, keys: &[[u8; 32]]) {
    let session = nomt.begin_session(SessionParams::default());
    for k in keys {
        session.warm_up(*k);
    }
    let mut accesses: Vec<_> = keys
        .iter()
        .map(|k| (*k, KeyReadWrite::Write(None)))
        .collect();
    accesses.sort_by_key(|(k, _)| *k);
    let finished = session.finish(accesses).unwrap();
    finished.commit(nomt).unwrap();
}

/// Helper: run a test function against a concrete Patricia backend.
fn assert_patricia_insert_read<DB: TrieDB>(
    name: &str,
    trie: &mut BinaryPatriciaTrie<DB>,
    entries: &[([u8; 32], Vec<u8>)],
) {
    for (k, v) in entries {
        trie.insert(k, v.clone());
    }
    for (k, v) in entries {
        assert_eq!(trie.get(k).as_ref(), Some(v), "{name}: missing key");
    }
    let missing = blake2b_256(b"missing");
    assert_eq!(trie.get(&missing), None, "{name}: ghost key");
}

fn assert_patricia_delete<DB: TrieDB>(
    name: &str,
    trie: &mut BinaryPatriciaTrie<DB>,
    entries: &[([u8; 32], Vec<u8>)],
    delete_count: usize,
) {
    for (k, v) in entries {
        trie.insert(k, v.clone());
    }
    for (k, _) in &entries[..delete_count] {
        trie.delete(k);
    }
    for (k, _) in &entries[..delete_count] {
        assert_eq!(trie.get(k), None, "{name}: deleted key still present");
    }
    for (k, v) in &entries[delete_count..] {
        assert_eq!(trie.get(k), Some(v.clone()), "{name}: surviving key missing");
    }
}

fn assert_patricia_proofs<DB: TrieDB>(
    name: &str,
    trie: &mut BinaryPatriciaTrie<DB>,
    entries: &[([u8; 32], Vec<u8>)],
) {
    for (k, v) in entries {
        trie.insert(k, v.clone());
    }
    let root = trie.root_hash();
    for (k, v) in entries {
        let proof = trie.generate_proof(k);
        let result = verify_proof(&root, k, &proof).unwrap();
        assert_eq!(result.as_ref(), Some(v), "{name}: inclusion proof failed");
    }
    let missing = blake2b_256(b"proof_missing");
    let proof = trie.generate_proof(&missing);
    assert_eq!(
        verify_proof(&root, &missing, &proof).unwrap(),
        None,
        "{name}: non-inclusion proof failed"
    );
}

fn assert_patricia_order_independent<DB1: TrieDB, DB2: TrieDB>(
    name: &str,
    t1: &mut BinaryPatriciaTrie<DB1>,
    t2: &mut BinaryPatriciaTrie<DB2>,
    entries: &[([u8; 32], Vec<u8>)],
) {
    let mut reversed = entries.to_vec();
    reversed.reverse();
    for (k, v) in entries {
        t1.insert(k, v.clone());
    }
    for (k, v) in &reversed {
        t2.insert(k, v.clone());
    }
    assert_eq!(t1.root_hash(), t2.root_hash(), "{name}: order dependent");
}

fn assert_patricia_root_changes<DB: TrieDB>(
    name: &str,
    trie: &mut BinaryPatriciaTrie<DB>,
    entries: &[([u8; 32], Vec<u8>)],
) {
    let r0 = trie.root_hash();
    trie.insert(&entries[0].0, entries[0].1.clone());
    let r1 = trie.root_hash();
    assert_ne!(r0, r1, "{name}: root unchanged after insert");
    trie.insert(&entries[1].0, entries[1].1.clone());
    let r2 = trie.root_hash();
    assert_ne!(r1, r2, "{name}: root unchanged after second insert");
    trie.delete(&entries[0].0);
    let r3 = trie.root_hash();
    assert_ne!(r2, r3, "{name}: root unchanged after delete");
}

// ═══════════════════════════════════════════════════════════════
// 1. Insert + Read
// ═══════════════════════════════════════════════════════════════

#[test]
fn insert_and_read_all_backends() {
    let entries = test_entries(300);

    let mut mem = BinaryPatriciaTrie::new();
    assert_patricia_insert_read("Memory", &mut mem, &entries);

    let rp = temp_path("ir_rocks");
    let mut rocks = BinaryPatriciaTrie::with_db(RocksTrieDB::open(&rp).unwrap());
    assert_patricia_insert_read("Rocks", &mut rocks, &entries);

    let np = temp_path("ir_nomtdb");
    let mut nomtdb = BinaryPatriciaTrie::with_db(NomtTrieDB::open(&np).unwrap());
    assert_patricia_insert_read("NomtDB", &mut nomtdb, &entries);

    // NOMT native
    let nomt_path = temp_path("ir_nomt");
    let nomt = open_nomt(&nomt_path);
    nomt_insert(&nomt, &entries);
    let session = nomt.begin_session(SessionParams::default());
    for (k, v) in &entries {
        assert_eq!(session.read(*k).unwrap().as_deref(), Some(v.as_slice()), "NOMT: missing key");
    }
    assert_eq!(session.read(blake2b_256(b"missing")).unwrap(), None, "NOMT: ghost key");
}

// ═══════════════════════════════════════════════════════════════
// 2. Delete
// ═══════════════════════════════════════════════════════════════

#[test]
fn delete_all_backends() {
    let entries = test_entries(200);

    let mut mem = BinaryPatriciaTrie::new();
    assert_patricia_delete("Memory", &mut mem, &entries, 100);

    let rp = temp_path("del_rocks");
    let mut rocks = BinaryPatriciaTrie::with_db(RocksTrieDB::open(&rp).unwrap());
    assert_patricia_delete("Rocks", &mut rocks, &entries, 100);

    let np = temp_path("del_nomtdb");
    let mut nomtdb = BinaryPatriciaTrie::with_db(NomtTrieDB::open(&np).unwrap());
    assert_patricia_delete("NomtDB", &mut nomtdb, &entries, 100);

    // NOMT native
    let nomt_path = temp_path("del_nomt");
    let nomt = open_nomt(&nomt_path);
    nomt_insert(&nomt, &entries);
    let del_keys: Vec<[u8; 32]> = entries[..100].iter().map(|(k, _)| *k).collect();
    nomt_delete(&nomt, &del_keys);
    let session = nomt.begin_session(SessionParams::default());
    for (k, _) in &entries[..100] {
        assert_eq!(session.read(*k).unwrap(), None, "NOMT: deleted key present");
    }
    for (k, v) in &entries[100..] {
        assert_eq!(session.read(*k).unwrap().as_deref(), Some(v.as_slice()), "NOMT: surviving missing");
    }
}

// ═══════════════════════════════════════════════════════════════
// 3. Root hash consistency — all Patricia backends must match
// ═══════════════════════════════════════════════════════════════

#[test]
fn all_patricia_backends_same_root() {
    let entries = test_entries(500);

    let mut mem = BinaryPatriciaTrie::new();
    let rp = temp_path("root_rocks");
    let mut rocks = BinaryPatriciaTrie::with_db(RocksTrieDB::open(&rp).unwrap());
    let np = temp_path("root_nomtdb");
    let mut nomtdb = BinaryPatriciaTrie::with_db(NomtTrieDB::open(&np).unwrap());

    for (k, v) in &entries {
        mem.insert(k, v.clone());
        rocks.insert(k, v.clone());
        nomtdb.insert(k, v.clone());
    }

    let root = mem.root_hash();
    assert_eq!(root, rocks.root_hash(), "Memory != Rocks");
    assert_eq!(root, nomtdb.root_hash(), "Memory != NomtDB");
}

// ═══════════════════════════════════════════════════════════════
// 4. Root changes after mutation
// ═══════════════════════════════════════════════════════════════

#[test]
fn root_changes_all_backends() {
    let entries = test_entries(10);

    let mut mem = BinaryPatriciaTrie::new();
    assert_patricia_root_changes("Memory", &mut mem, &entries);

    let rp = temp_path("rmut_rocks");
    let mut rocks = BinaryPatriciaTrie::with_db(RocksTrieDB::open(&rp).unwrap());
    assert_patricia_root_changes("Rocks", &mut rocks, &entries);

    let np = temp_path("rmut_nomtdb");
    let mut nomtdb = BinaryPatriciaTrie::with_db(NomtTrieDB::open(&np).unwrap());
    assert_patricia_root_changes("NomtDB", &mut nomtdb, &entries);

    // NOMT native
    let nomt_path = temp_path("rmut_nomt");
    let nomt = open_nomt(&nomt_path);
    let r0 = nomt.root().into_inner();
    nomt_insert(&nomt, &entries[..1]);
    let r1 = nomt.root().into_inner();
    assert_ne!(r0, r1, "NOMT: root unchanged after insert");
    nomt_insert(&nomt, &entries[1..2]);
    let r2 = nomt.root().into_inner();
    assert_ne!(r1, r2, "NOMT: root unchanged after second insert");
    nomt_delete(&nomt, &[entries[0].0]);
    let r3 = nomt.root().into_inner();
    assert_ne!(r2, r3, "NOMT: root unchanged after delete");
}

// ═══════════════════════════════════════════════════════════════
// 5. Order independence
// ═══════════════════════════════════════════════════════════════

#[test]
fn order_independence_all_backends() {
    let entries = test_entries(100);

    let mut m1 = BinaryPatriciaTrie::new();
    let mut m2 = BinaryPatriciaTrie::new();
    assert_patricia_order_independent("Memory", &mut m1, &mut m2, &entries);

    let rp1 = temp_path("ord_rocks1");
    let rp2 = temp_path("ord_rocks2");
    let mut r1 = BinaryPatriciaTrie::with_db(RocksTrieDB::open(&rp1).unwrap());
    let mut r2 = BinaryPatriciaTrie::with_db(RocksTrieDB::open(&rp2).unwrap());
    assert_patricia_order_independent("Rocks", &mut r1, &mut r2, &entries);

    let np1 = temp_path("ord_nomtdb1");
    let np2 = temp_path("ord_nomtdb2");
    let mut n1 = BinaryPatriciaTrie::with_db(NomtTrieDB::open(&np1).unwrap());
    let mut n2 = BinaryPatriciaTrie::with_db(NomtTrieDB::open(&np2).unwrap());
    assert_patricia_order_independent("NomtDB", &mut n1, &mut n2, &entries);

    // NOMT native
    let mut reversed = entries.clone();
    reversed.reverse();
    let p1 = temp_path("ord_nomt1");
    let p2 = temp_path("ord_nomt2");
    let nomt1 = open_nomt(&p1);
    let nomt2 = open_nomt(&p2);
    nomt_insert(&nomt1, &entries);
    nomt_insert(&nomt2, &reversed);
    assert_eq!(
        nomt1.root().into_inner(),
        nomt2.root().into_inner(),
        "NOMT: order dependent"
    );
}

// ═══════════════════════════════════════════════════════════════
// 6. Proofs — all Patricia backends
// ═══════════════════════════════════════════════════════════════

#[test]
fn proofs_all_patricia_backends() {
    let entries = test_entries(100);

    let mut mem = BinaryPatriciaTrie::new();
    assert_patricia_proofs("Memory", &mut mem, &entries);

    let rp = temp_path("proof_rocks");
    let mut rocks = BinaryPatriciaTrie::with_db(RocksTrieDB::open(&rp).unwrap());
    assert_patricia_proofs("Rocks", &mut rocks, &entries);

    let np = temp_path("proof_nomtdb");
    let mut nomtdb = BinaryPatriciaTrie::with_db(NomtTrieDB::open(&np).unwrap());
    assert_patricia_proofs("NomtDB", &mut nomtdb, &entries);
}

// ═══════════════════════════════════════════════════════════════
// 7. Cross-proof verification — proofs portable across backends
// ═══════════════════════════════════════════════════════════════

#[test]
fn proof_cross_verification_all_patricia() {
    let entries = test_entries(50);

    let mut mem = BinaryPatriciaTrie::new();
    let rp = temp_path("xproof_rocks");
    let mut rocks = BinaryPatriciaTrie::with_db(RocksTrieDB::open(&rp).unwrap());
    let np = temp_path("xproof_nomtdb");
    let mut nomtdb = BinaryPatriciaTrie::with_db(NomtTrieDB::open(&np).unwrap());

    for (k, v) in &entries {
        mem.insert(k, v.clone());
        rocks.insert(k, v.clone());
        nomtdb.insert(k, v.clone());
    }

    let root = mem.root_hash();
    assert_eq!(root, rocks.root_hash());
    assert_eq!(root, nomtdb.root_hash());

    for (k, v) in &entries {
        let mp = mem.generate_proof(k);
        let rp = rocks.generate_proof(k);
        let np = nomtdb.generate_proof(k);

        // All proofs verify against the shared root.
        assert_eq!(verify_proof(&root, k, &mp).unwrap().as_ref(), Some(v), "Memory proof failed");
        assert_eq!(verify_proof(&root, k, &rp).unwrap().as_ref(), Some(v), "Rocks proof failed");
        assert_eq!(verify_proof(&root, k, &np).unwrap().as_ref(), Some(v), "NomtDB proof failed");
    }
}

// ═══════════════════════════════════════════════════════════════
// 8. Delete root consistency — all Patricia backends
// ═══════════════════════════════════════════════════════════════

#[test]
fn delete_root_consistency_all_patricia() {
    let entries = test_entries(100);

    let mut mem = BinaryPatriciaTrie::new();
    let rp = temp_path("delroot_rocks");
    let mut rocks = BinaryPatriciaTrie::with_db(RocksTrieDB::open(&rp).unwrap());
    let np = temp_path("delroot_nomtdb");
    let mut nomtdb = BinaryPatriciaTrie::with_db(NomtTrieDB::open(&np).unwrap());

    for (k, v) in &entries {
        mem.insert(k, v.clone());
        rocks.insert(k, v.clone());
        nomtdb.insert(k, v.clone());
    }

    for (k, _) in &entries[..50] {
        mem.delete(k);
        rocks.delete(k);
        nomtdb.delete(k);
    }

    let root = mem.root_hash();
    assert_eq!(root, rocks.root_hash(), "Memory != Rocks after delete");
    assert_eq!(root, nomtdb.root_hash(), "Memory != NomtDB after delete");
}

// ═══════════════════════════════════════════════════════════════
// 9. Persistence — disk backends
// ═══════════════════════════════════════════════════════════════

#[test]
fn persistence_all_disk_backends() {
    let entries = test_entries(100);

    // RocksDB
    let rp = temp_path("persist_rocks");
    let rocks_root;
    {
        let mut trie = BinaryPatriciaTrie::with_db(RocksTrieDB::open(&rp).unwrap());
        for (k, v) in &entries {
            trie.insert(k, v.clone());
        }
        rocks_root = trie.root_hash();
    }
    {
        let trie = BinaryPatriciaTrie::from_existing(RocksTrieDB::open(&rp).unwrap(), rocks_root);
        for (k, v) in &entries {
            assert_eq!(trie.get(k), Some(v.clone()), "Rocks: data lost after reopen");
        }
    }

    // NOMT native
    let nomt_path = temp_path("persist_nomt");
    let nomt_root;
    {
        let nomt = open_nomt(&nomt_path);
        nomt_insert(&nomt, &entries);
        nomt_root = nomt.root().into_inner();
    }
    {
        let nomt = open_nomt(&nomt_path);
        assert_eq!(nomt.root().into_inner(), nomt_root, "NOMT: root changed after reopen");
        let session = nomt.begin_session(SessionParams::default());
        for (k, v) in &entries {
            assert_eq!(
                session.read(*k).unwrap().as_deref(),
                Some(v.as_slice()),
                "NOMT: data lost after reopen"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// 10. Cross-schema: Patricia vs NOMT — same data, different roots
// ═══════════════════════════════════════════════════════════════

#[test]
fn patricia_vs_nomt_same_data_different_roots() {
    let entries = test_entries(300);

    let mut mem = BinaryPatriciaTrie::new();
    let rp = temp_path("xs_rocks");
    let mut rocks = BinaryPatriciaTrie::with_db(RocksTrieDB::open(&rp).unwrap());
    let np = temp_path("xs_nomtdb");
    let mut nomtdb = BinaryPatriciaTrie::with_db(NomtTrieDB::open(&np).unwrap());

    for (k, v) in &entries {
        mem.insert(k, v.clone());
        rocks.insert(k, v.clone());
        nomtdb.insert(k, v.clone());
    }

    let nomt_path = temp_path("xs_nomt");
    let nomt = open_nomt(&nomt_path);
    nomt_insert(&nomt, &entries);

    let patricia_root = mem.root_hash();
    let nomt_root = nomt.root().into_inner();

    // Patricia backends all agree.
    assert_eq!(patricia_root, rocks.root_hash());
    assert_eq!(patricia_root, nomtdb.root_hash());

    // NOMT root is different (different schema + hasher).
    assert_ne!(patricia_root, nomt_root, "Patricia and NOMT should differ");

    // But ALL return the same data.
    let session = nomt.begin_session(SessionParams::default());
    for (k, v) in &entries {
        assert_eq!(mem.get(k).as_ref(), Some(v));
        assert_eq!(rocks.get(k).as_ref(), Some(v));
        assert_eq!(nomtdb.get(k).as_ref(), Some(v));
        assert_eq!(session.read(*k).unwrap().as_deref(), Some(v.as_slice()));
    }

    let missing = blake2b_256(b"xs_missing");
    assert_eq!(mem.get(&missing), None);
    assert_eq!(rocks.get(&missing), None);
    assert_eq!(nomtdb.get(&missing), None);
    assert_eq!(session.read(missing).unwrap(), None);
}
