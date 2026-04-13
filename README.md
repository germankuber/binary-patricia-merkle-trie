# Binary Patricia Merkle Trie

A from-scratch implementation of a **Binary Patricia Merkle Trie** in Rust, inspired by the [JAM (Join-Accumulate Machine)](https://graypaper.com/) specification for Polkadot's next-generation state trie.

Unlike Substrate's current radix-16 Modified Merkle Patricia Trie (where each node has up to 16 children), this implementation uses a **radix-2 (binary)** structure where each node has 0 or 2 children, with one child per bit (0 = left, 1 = right).

## Features

- **3 node types**: Branch (with optional children + value), Leaf (partial key + value), Extension (Patricia prefix compression)
- **Blake2b-256** hashing for node content addressing
- **Insert, Get, Delete** operations with automatic trie collapsing
- **Merkle proof** generation and verification (inclusion + non-inclusion)
- **Garbage collection** of stale nodes on insert/delete
- **4 storage backends** via the `TrieDB` trait:
  - `MemoryDB` -- in-memory HashMap
  - `RocksTrieDB` -- persistent via RocksDB
  - `NomtTrieDB` -- persistent via [NOMT](https://github.com/thrumdev/nomt) (Nearly Optimal Merkle Trie)
  - NOMT native -- direct comparison using NOMT's own sparse binary merkle trie
- **CLI benchmark tool** with colored output comparing all backends

## Node Encoding

```
Branch:    [0x00] [left_flag:1] [left:0|32] [right_flag:1] [right:0|32] [value_len:varint] [value]
Leaf:      [0x01] [partial_bits_len:varint] [partial_bits:packed] [value_len:varint] [value]
Extension: [0x02] [partial_bits_len:varint] [partial_bits:packed] [child_hash:32]
```

- Branch children are `Option<Hash>` (flag byte `0x00` = absent, `0x01` + 32 bytes = present)
- No placeholder nodes -- branches can have one or both children absent
- Node hash = `blake2b_256(encoded_bytes)`

## Usage

```rust
use binary_patricia_merkle_trie::{BinaryPatriciaTrie, verify_proof, blake2b_256};

let mut trie = BinaryPatriciaTrie::new(); // in-memory backend

// Insert
trie.insert(b"key1", b"value1".to_vec());
trie.insert(b"key2", b"value2".to_vec());

// Get
assert_eq!(trie.get(b"key1"), Some(b"value1".to_vec()));

// Root hash
let root = trie.root_hash();

// Merkle proof
let proof = trie.generate_proof(b"key1");
let result = verify_proof(&root, b"key1", &proof).unwrap();
assert_eq!(result, Some(b"value1".to_vec()));

// Delete
trie.delete(b"key1");
assert_eq!(trie.get(b"key1"), None);
```

### Using a different backend

```rust
use binary_patricia_merkle_trie::{BinaryPatriciaTrie, RocksTrieDB, NomtTrieDB};

// RocksDB
let db = RocksTrieDB::open("/tmp/my_trie").unwrap();
let mut trie = BinaryPatriciaTrie::with_db(db);

// NOMT
let db = NomtTrieDB::open("/tmp/my_nomt_trie").unwrap();
let mut trie = BinaryPatriciaTrie::with_db(db);
```

## CLI Benchmark

```bash
# Run a single backend
cargo run --release -- -b memory -n 10000
cargo run --release -- -b rocks -n 10000
cargo run --release -- -b nomt -n 10000
cargo run --release -- -b nomt-db -n 10000

# Compare all 4 backends (colored output)
cargo run --release -- -b all -n 5000 -p 50

# See all options
cargo run --release -- --help
```

### Sample benchmark (5,000 keys, release mode, Apple M1)

```
Backend                                Insert            Get         Delete
----------------------------------------------------------------------------
Memory (Patricia + HashMap)       36.102ms       10.749ms       33.022ms
Rocks (Patricia + RocksDB)       373.353ms       58.799ms      413.921ms
NomtDB (Patricia + NOMT)          37.528ms       10.802ms       42.950ms
NOMT (Sparse Merkle + Bitbox)     27.168ms        1.239ms       27.771ms

Backend                        Root Hash
---------------------------------------------
Memory (Patricia + HashMap)    0x0cb5cc27...
Rocks (Patricia + RocksDB)     0x0cb5cc27...  (same -- same trie schema)
NomtDB (Patricia + NOMT)       0x0cb5cc27...  (same -- same trie schema)
NOMT (Sparse Merkle + Bitbox)  0x1c04ff84...  (different -- different schema + hasher)

Backend                         Avg bytes     Proof time  Avg nodes
--------------------------------------------------------------------
Memory (Patricia + HashMap)          1744       454.333us         27
Rocks (Patricia + RocksDB)           1744      1.309042ms         27
NomtDB (Patricia + NOMT)             1744       403.292us         27
```

Key observations:
- **Memory, Rocks, and NomtDB produce identical root hashes** -- they all use our Patricia trie logic, just different storage backends
- **NOMT native has a different root** because it uses a fundamentally different trie schema (sparse binary merkle with Blake3 + MSB tagging) and no Extension nodes
- **NOMT native is fastest for reads** (~1.2ms vs ~10ms) thanks to its page-based storage optimized for SSDs
- **RocksDB is the slowest** due to LSM-tree overhead for this workload pattern

## How it differs from Substrate's current trie

| Aspect | Substrate (sp-trie) | This implementation |
|--------|-------------------|-------------------|
| Radix | 16 (one child per nibble) | 2 (one child per bit) |
| Max children per node | 16 | 2 |
| Proof size per level | Up to 15 x 32 = 480 bytes | 1 x 32 = 32 bytes |
| Tree depth | Shallower (4x fewer levels) | Deeper (but Extension nodes compress) |
| Hasher | Blake2b-256 | Blake2b-256 (compatible) |

## Tests

```bash
cargo test           # Run all 46 tests
cargo test --release # Run in release mode
```

## License

MIT
