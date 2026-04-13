use std::fmt;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};

use binary_patricia_merkle_trie::{
    blake2b_256, verify_proof, BinaryPatriciaTrie, NomtTrieDB, RocksTrieDB, TrieDB,
};

#[derive(Debug, Clone, ValueEnum)]
enum Backend {
    Memory,
    Rocks,
    Nomt,
    NomtDb,
    All,
}

#[derive(Parser)]
#[command(
    name = "trie-bench",
    about = "Benchmark the Binary Patricia Merkle Trie (and NOMT)"
)]
struct Cli {
    /// Storage backend to use. Use "all" to run all three and compare.
    #[arg(short, long, default_value = "memory")]
    backend: Backend,

    /// Number of keys to insert.
    #[arg(short = 'n', long, default_value_t = 1000)]
    keys: u32,

    /// Number of proofs to generate and verify (patricia backends only).
    #[arg(short, long, default_value_t = 100)]
    proofs: u32,

    /// Path for the database on disk (used with rocks/nomt backends).
    #[arg(long, default_value = "/tmp/trie_bench_db")]
    db_path: String,
}

struct BenchResult {
    name: String,
    root: String,
    insert: Duration,
    get: Duration,
    delete: Duration,
    proof_info: Option<ProofInfo>,
}

struct ProofInfo {
    count: usize,
    time: Duration,
    avg_bytes: usize,
    avg_nodes: usize,
}

impl fmt::Display for BenchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  Insert:     {:?}", self.insert)?;
        writeln!(f, "  Get all:    {:?}", self.get)?;
        if let Some(ref p) = self.proof_info {
            writeln!(
                f,
                "  Proofs:     {} in {:?} (avg {} bytes, {} nodes)",
                p.count, p.time, p.avg_bytes, p.avg_nodes
            )?;
        }
        writeln!(f, "  Delete all: {:?}", self.delete)?;
        write!(f, "  Root:       {}", self.root)
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.backend {
        Backend::Memory => {
            let trie = BinaryPatriciaTrie::new();
            let r = run_patricia_bench("Memory", trie, &cli);
            print_single(&r);
        }
        Backend::Rocks => {
            let _ = std::fs::remove_dir_all(&cli.db_path);
            let db = RocksTrieDB::open(&cli.db_path).expect("failed to open RocksDB");
            let trie = BinaryPatriciaTrie::with_db(db);
            let r = run_patricia_bench("Rocks", trie, &cli);
            print_single(&r);
        }
        Backend::Nomt => {
            let r = run_nomt_bench(&cli);
            print_single(&r);
        }
        Backend::NomtDb => {
            let nomt_path = format!("{}_nomt_db", cli.db_path);
            let _ = std::fs::remove_dir_all(&nomt_path);
            let db = NomtTrieDB::open(&nomt_path).expect("failed to open NomtTrieDB");
            let trie = BinaryPatriciaTrie::with_db(db);
            let r = run_patricia_bench("NomtDB", trie, &cli);
            print_single(&r);
            let _ = std::fs::remove_dir_all(&nomt_path);
        }
        Backend::All => {
            run_all(&cli);
        }
    }
}

fn print_single(r: &BenchResult) {
    println!("Backend:    {}", r.name);
    println!("Keys:       (see below)");
    println!("{r}");
}

fn run_all(cli: &Cli) {
    println!(
        "=== Comparing all backends with {} keys ===\n",
        cli.keys
    );

    // Memory
    let trie = BinaryPatriciaTrie::new();
    let mem = run_patricia_bench("Memory (Patricia + HashMap)", trie, cli);

    // Rocks
    let rocks_path = format!("{}_rocks", cli.db_path);
    let _ = std::fs::remove_dir_all(&rocks_path);
    let db = RocksTrieDB::open(&rocks_path).expect("failed to open RocksDB");
    let trie = BinaryPatriciaTrie::with_db(db);
    let rocks = run_patricia_bench("Rocks (Patricia + RocksDB)", trie, cli);

    // NomtDB (Patricia trie over NOMT storage)
    let nomt_db_path = format!("{}_nomt_db", cli.db_path);
    let _ = std::fs::remove_dir_all(&nomt_db_path);
    let db = NomtTrieDB::open(&nomt_db_path).expect("failed to open NomtTrieDB");
    let trie = BinaryPatriciaTrie::with_db(db);
    let nomt_db = run_patricia_bench("NomtDB (Patricia + NOMT)", trie, cli);
    let _ = std::fs::remove_dir_all(&nomt_db_path);

    // NOMT native
    let nomt = run_nomt_bench(cli);

    // Print comparison table with colors
    use colored::Colorize;

    let results = [&mem, &rocks, &nomt_db, &nomt];

    println!(
        "{:<30} {:>14} {:>14} {:>14}",
        "Backend".bold(),
        "Insert".bold(),
        "Get".bold(),
        "Delete".bold()
    );
    println!("{}", "-".repeat(76));

    // Find fastest/slowest for each metric
    let fastest_insert = results.iter().map(|r| r.insert).min().unwrap();
    let slowest_insert = results.iter().map(|r| r.insert).max().unwrap();
    let fastest_get = results.iter().map(|r| r.get).min().unwrap();
    let slowest_get = results.iter().map(|r| r.get).max().unwrap();
    let fastest_delete = results.iter().map(|r| r.delete).min().unwrap();
    let slowest_delete = results.iter().map(|r| r.delete).max().unwrap();

    for r in &results {
        let insert_col = pad_and_color(r.insert, 14, fastest_insert, slowest_insert);
        let get_col = pad_and_color(r.get, 14, fastest_get, slowest_get);
        let delete_col = pad_and_color(r.delete, 14, fastest_delete, slowest_delete);

        println!("{:<30} {} {} {}", r.name, insert_col, get_col, delete_col);
    }

    // Root hashes
    println!("\n{:<30} {}", "Backend".bold(), "Root Hash".bold());
    println!("{}", "-".repeat(100));
    for r in &results {
        println!("{:<30} {}", r.name, r.root);
    }

    // Check patricia roots match
    let patricia_roots_match = mem.root == rocks.root && mem.root == nomt_db.root;
    if patricia_roots_match {
        println!(
            "\n{}",
            "[OK] Memory, Rocks, and NomtDB roots match (same Patricia trie schema).".green()
        );
    } else {
        println!("\n{}", "[!!] Patricia backend roots DIFFER.".red().bold());
        println!("     Memory:  {}", mem.root);
        println!("     Rocks:   {}", rocks.root);
        println!("     NomtDB:  {}", nomt_db.root);
    }

    if mem.root != nomt.root {
        println!(
            "{}",
            "[OK] NOMT native root differs (expected: different trie schema + hasher).".green()
        );
    }

    // Proof comparison (patricia backends only)
    let patricia_results = [&mem, &rocks, &nomt_db];
    println!(
        "\n{:<30} {:>10} {:>14} {:>10}",
        "Backend".bold(),
        "Avg bytes".bold(),
        "Proof time".bold(),
        "Avg nodes".bold()
    );
    println!("{}", "-".repeat(68));
    let proof_times: Vec<Duration> = patricia_results
        .iter()
        .filter_map(|r| r.proof_info.as_ref().map(|p| p.time))
        .collect();
    let fastest_proof = proof_times.iter().copied().min().unwrap_or_default();
    let slowest_proof = proof_times.iter().copied().max().unwrap_or_default();

    for r in &patricia_results {
        if let Some(p) = &r.proof_info {
            let time_col = pad_and_color(p.time, 14, fastest_proof, slowest_proof);
            println!(
                "{:<30} {:>10} {} {:>10}",
                r.name, p.avg_bytes, time_col, p.avg_nodes
            );
        }
    }
}

fn run_patricia_bench<DB: TrieDB>(
    name: &str,
    mut trie: BinaryPatriciaTrie<DB>,
    cli: &Cli,
) -> BenchResult {
    let keys: Vec<[u8; 32]> = (0..cli.keys)
        .map(|i| blake2b_256(&i.to_le_bytes()))
        .collect();

    // Insert
    let start = Instant::now();
    for (i, key) in keys.iter().enumerate() {
        trie.insert(key, format!("value_{i}").into_bytes());
    }
    let insert_time = start.elapsed();
    let root = trie.root_hash();

    // Get
    let start = Instant::now();
    for key in &keys {
        assert!(trie.get(key).is_some());
    }
    let get_time = start.elapsed();

    // Proofs
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

    // Delete
    let start = Instant::now();
    for key in &keys {
        trie.delete(key);
    }
    let delete_time = start.elapsed();

    BenchResult {
        name: name.to_string(),
        root: format!("0x{}", hex::encode(root)),
        insert: insert_time,
        get: get_time,
        delete: delete_time,
        proof_info: Some(ProofInfo {
            count: proof_count,
            time: proof_time,
            avg_bytes: total_proof_size / proof_count,
            avg_nodes: total_proof_nodes / proof_count,
        }),
    }
}

fn run_nomt_bench(cli: &Cli) -> BenchResult {
    use nomt::hasher::Blake3Hasher;
    use nomt::{KeyReadWrite, Nomt, Options, SessionParams};

    let nomt_path = format!("{}_nomt", cli.db_path);
    let _ = std::fs::remove_dir_all(&nomt_path);

    let mut opts = Options::new();
    opts.path(&nomt_path);
    opts.commit_concurrency(1);

    let nomt = Nomt::<Blake3Hasher>::open(opts).expect("failed to open NOMT");

    let keys: Vec<[u8; 32]> = (0..cli.keys)
        .map(|i| blake2b_256(&i.to_le_bytes()))
        .collect();

    // Insert
    let start = Instant::now();
    let session = nomt.begin_session(SessionParams::default());
    for key in &keys {
        session.warm_up(*key);
    }
    let mut accesses: Vec<([u8; 32], KeyReadWrite)> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            let value = format!("value_{i}").into_bytes();
            (*key, KeyReadWrite::Write(Some(value)))
        })
        .collect();
    accesses.sort_by_key(|(k, _)| *k);
    let finished = session.finish(accesses).expect("finish failed");
    let root = finished.root();
    finished.commit(&nomt).expect("commit failed");
    let insert_time = start.elapsed();

    // Read
    let start = Instant::now();
    let session = nomt.begin_session(SessionParams::default());
    for key in &keys {
        let val = session.read(*key).expect("read failed");
        assert!(val.is_some());
    }
    let get_time = start.elapsed();
    drop(session);

    // Delete
    let start = Instant::now();
    let session = nomt.begin_session(SessionParams::default());
    for key in &keys {
        session.warm_up(*key);
    }
    let mut deletes: Vec<([u8; 32], KeyReadWrite)> = keys
        .iter()
        .map(|key| (*key, KeyReadWrite::Write(None)))
        .collect();
    deletes.sort_by_key(|(k, _)| *k);
    let finished = session.finish(deletes).expect("finish failed");
    finished.commit(&nomt).expect("commit failed");
    let delete_time = start.elapsed();

    let _ = std::fs::remove_dir_all(&nomt_path);

    BenchResult {
        name: "NOMT (Sparse Merkle + Bitbox)".to_string(),
        root: format!("0x{}", hex::encode(root.into_inner())),
        insert: insert_time,
        get: get_time,
        delete: delete_time,
        proof_info: None,
    }
}

/// Right-pad a duration string to `width`, then apply color based on rank.
fn pad_and_color(value: Duration, width: usize, fastest: Duration, slowest: Duration) -> String {
    use colored::Colorize;
    let text = format!("{value:?}");
    let padded = format!("{text:>width$}");
    if value == fastest {
        format!("{}", padded.green().bold())
    } else if value == slowest {
        format!("{}", padded.red())
    } else {
        padded
    }
}
