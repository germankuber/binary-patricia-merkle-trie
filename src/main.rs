use std::time::Instant;

use clap::{Parser, ValueEnum};

use binary_patricia_merkle_trie::{
    blake2b_256, verify_proof, BinaryPatriciaTrie, RocksTrieDB, TrieDB,
};

#[derive(Debug, Clone, ValueEnum)]
enum Backend {
    Memory,
    Rocks,
}

#[derive(Parser)]
#[command(
    name = "trie-bench",
    about = "Benchmark the Binary Patricia Merkle Trie"
)]
struct Cli {
    /// Storage backend to use.
    #[arg(short, long, default_value = "memory")]
    backend: Backend,

    /// Number of keys to insert.
    #[arg(short = 'n', long, default_value_t = 1000)]
    keys: u32,

    /// Number of proofs to generate and verify.
    #[arg(short, long, default_value_t = 100)]
    proofs: u32,

    /// Path for the RocksDB database (only used with --backend rocks).
    #[arg(long, default_value = "/tmp/trie_bench_db")]
    db_path: String,
}

fn main() {
    let cli = Cli::parse();

    match cli.backend {
        Backend::Memory => {
            let trie = BinaryPatriciaTrie::new();
            run_bench(trie, &cli);
        }
        Backend::Rocks => {
            let _ = std::fs::remove_dir_all(&cli.db_path);
            let db = RocksTrieDB::open(&cli.db_path).expect("failed to open RocksDB");
            let trie = BinaryPatriciaTrie::with_db(db);
            run_bench(trie, &cli);
        }
    }
}

fn run_bench<DB: TrieDB>(mut trie: BinaryPatriciaTrie<DB>, cli: &Cli) {
    let keys: Vec<[u8; 32]> = (0..cli.keys)
        .map(|i| blake2b_256(&i.to_le_bytes()))
        .collect();

    // ── Insert ──────────────────────────────────────────────────
    let start = Instant::now();
    for (i, key) in keys.iter().enumerate() {
        trie.insert(key, format!("value_{i}").into_bytes());
    }
    let insert_time = start.elapsed();

    let root = trie.root_hash();
    println!("Backend:    {:?}", cli.backend);
    println!("Keys:       {}", cli.keys);
    println!("Insert:     {insert_time:?}");
    println!("Root:       0x{}", hex::encode(root));

    // ── Get ─────────────────────────────────────────────────────
    let start = Instant::now();
    for key in &keys {
        assert!(trie.get(key).is_some());
    }
    let get_time = start.elapsed();
    println!("Get all:    {get_time:?}");

    // ── Proofs ──────────────────────────────────────────────────
    let proof_count = cli.proofs.min(cli.keys) as usize;
    let proof_keys = &keys[..proof_count];

    let start = Instant::now();
    let mut total_proof_size = 0usize;
    let mut total_proof_nodes = 0usize;

    for key in proof_keys {
        let proof = trie.generate_proof(key);
        total_proof_size += proof.encoded_size();
        total_proof_nodes += proof.nodes.len();
        let result = verify_proof(&root, key, &proof).unwrap();
        assert!(result.is_some());
    }
    let proof_time = start.elapsed();

    let avg_proof_size = total_proof_size / proof_count;
    let avg_proof_nodes = total_proof_nodes / proof_count;

    println!("Proofs:     {proof_count} generated & verified in {proof_time:?}");
    println!("Avg proof:  {avg_proof_size} bytes, {avg_proof_nodes} nodes");

    // ── Delete ──────────────────────────────────────────────────
    let start = Instant::now();
    for key in &keys {
        trie.delete(key);
    }
    let delete_time = start.elapsed();
    println!("Delete all: {delete_time:?}");

    // ── DB stats ────────────────────────────────────────────────
    println!("DB nodes:   {}", trie.db().len());
}
