use crate::trie::bits::BitVec;
use crate::trie::db::TrieDB;
use crate::trie::memory_db::MemoryDB;
use crate::trie::node::{blake2b_256, Hash, Node, EMPTY_ROOT};
use crate::trie::proof::StorageProof;

/// Binary Patricia Merkle Trie, generic over the storage backend.
///
/// Stores key-value pairs in a content-addressed trie where:
/// - Keys are decomposed into bits (MSB first)
/// - Bit 0 → left child, bit 1 → right child
/// - Extension nodes compress shared prefixes
pub struct BinaryPatriciaTrie<DB: TrieDB = MemoryDB> {
    db: DB,
    root: Option<Hash>,
}

impl BinaryPatriciaTrie<MemoryDB> {
    /// Create a new empty trie with an in-memory backend.
    pub fn new() -> Self {
        Self {
            db: MemoryDB::new(),
            root: None,
        }
    }
}

impl<DB: TrieDB> BinaryPatriciaTrie<DB> {
    /// Create a new empty trie with the given storage backend.
    pub fn with_db(db: DB) -> Self {
        Self { db, root: None }
    }

    /// Create a trie from an existing root hash and storage backend.
    pub fn from_existing(db: DB, root: Hash) -> Self {
        let root = if root == EMPTY_ROOT { None } else { Some(root) };
        Self { db, root }
    }

    /// Get the root hash. Returns `EMPTY_ROOT` for an empty trie.
    pub fn root_hash(&self) -> Hash {
        self.root.unwrap_or(EMPTY_ROOT)
    }

    /// Retrieve a value by key.
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let root = self.root?;
        let key_bits = BitVec::from_bytes(key);
        self.get_recursive(&root, &key_bits, 0)
    }

    /// Insert a key-value pair. Returns the previous value if the key already existed.
    pub fn insert(&mut self, key: &[u8], value: Vec<u8>) -> Option<Vec<u8>> {
        let key_bits = BitVec::from_bytes(key);
        let (new_hash, old_value) = match self.root {
            None => {
                let leaf = Node::Leaf {
                    partial: key_bits,
                    value: value.clone(),
                };
                (self.store_node(&leaf), None)
            }
            Some(root_hash) => self.insert_recursive(&root_hash, &key_bits, 0, value),
        };
        self.root = Some(new_hash);
        old_value
    }

    /// Delete a key. Returns the old value if it existed.
    pub fn delete(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        let root = self.root?;
        let key_bits = BitVec::from_bytes(key);
        let (new_root, old_value) = self.delete_recursive(&root, &key_bits, 0)?;
        self.root = new_root;
        Some(old_value)
    }

    /// Generate a merkle proof for a key (inclusion or exclusion).
    pub fn generate_proof(&self, key: &[u8]) -> StorageProof {
        let mut proof_nodes = Vec::new();
        if let Some(root) = self.root {
            let key_bits = BitVec::from_bytes(key);
            self.collect_proof(&root, &key_bits, 0, &mut proof_nodes);
        }
        StorageProof { nodes: proof_nodes }
    }

    /// Reference to the internal database.
    pub fn db(&self) -> &DB {
        &self.db
    }

    // ── Private helpers ─────────────────────────────────────────────

    fn load_node(&self, hash: &Hash) -> Node {
        let data = self
            .db
            .get(hash)
            .unwrap_or_else(|| panic!("node not found for hash: {}", hex::encode(hash)));
        Node::decode(&data).expect("corrupted node in db")
    }

    fn store_node(&mut self, node: &Node) -> Hash {
        let encoded = node.encode();
        let hash = blake2b_256(&encoded);
        self.db.insert(hash, encoded);
        hash
    }

    fn remove_node(&mut self, hash: &Hash) {
        self.db.remove(hash);
    }

    fn get_recursive(&self, hash: &Hash, key_bits: &BitVec, depth: usize) -> Option<Vec<u8>> {
        let node = self.load_node(hash);
        match node {
            Node::Leaf { partial, value } => {
                let remaining = key_bits.slice(depth, key_bits.len() - depth);
                if remaining == partial {
                    Some(value)
                } else {
                    None
                }
            }
            Node::Extension { partial, child } => {
                let remaining = key_bits.len() - depth;
                if remaining < partial.len() {
                    return None;
                }
                let key_segment = key_bits.slice(depth, partial.len());
                if key_segment == partial {
                    self.get_recursive(&child, key_bits, depth + partial.len())
                } else {
                    None
                }
            }
            Node::Branch { left, right, value } => {
                if depth == key_bits.len() {
                    return value;
                }
                let bit = key_bits.get(depth);
                let child = if bit { right } else { left };
                match child {
                    Some(h) => self.get_recursive(&h, key_bits, depth + 1),
                    None => None,
                }
            }
        }
    }

    fn insert_recursive(
        &mut self,
        hash: &Hash,
        key_bits: &BitVec,
        depth: usize,
        value: Vec<u8>,
    ) -> (Hash, Option<Vec<u8>>) {
        let old_hash = *hash;
        let node = self.load_node(hash);
        let result = match node {
            Node::Leaf {
                partial,
                value: existing_value,
            } => {
                let remaining = key_bits.slice(depth, key_bits.len() - depth);
                if remaining == partial {
                    let new_leaf = Node::Leaf {
                        partial,
                        value: value.clone(),
                    };
                    (self.store_node(&new_leaf), Some(existing_value))
                } else {
                    let common_len = remaining.common_prefix_len(&partial);
                    let new_hash =
                        self.split_leaf(&remaining, &value, &partial, &existing_value, common_len);
                    (new_hash, None)
                }
            }
            Node::Extension { partial, child } => {
                let remaining_len = key_bits.len() - depth;
                let remaining = key_bits.slice(depth, remaining_len);
                let common_len = remaining.common_prefix_len(&partial);

                if common_len == partial.len() {
                    let (new_child, old_val) =
                        self.insert_recursive(&child, key_bits, depth + partial.len(), value);
                    let new_ext = Node::Extension {
                        partial,
                        child: new_child,
                    };
                    (self.store_node(&new_ext), old_val)
                } else {
                    let new_hash = self.split_extension(
                        &remaining,
                        &value,
                        &partial,
                        &child,
                        common_len,
                    );
                    (new_hash, None)
                }
            }
            Node::Branch {
                left,
                right,
                value: branch_value,
            } => {
                if depth == key_bits.len() {
                    let old_val = branch_value;
                    let new_branch = Node::Branch {
                        left,
                        right,
                        value: Some(value),
                    };
                    (self.store_node(&new_branch), old_val)
                } else {
                    let bit = key_bits.get(depth);
                    if bit {
                        let (new_right, old_val) = match right {
                            Some(r) => self.insert_recursive(&r, key_bits, depth + 1, value),
                            None => {
                                let leaf = Node::Leaf {
                                    partial: key_bits.slice(depth + 1, key_bits.len() - depth - 1),
                                    value: value.clone(),
                                };
                                (self.store_node(&leaf), None)
                            }
                        };
                        let new_branch = Node::Branch {
                            left,
                            right: Some(new_right),
                            value: branch_value,
                        };
                        (self.store_node(&new_branch), old_val)
                    } else {
                        let (new_left, old_val) = match left {
                            Some(l) => self.insert_recursive(&l, key_bits, depth + 1, value),
                            None => {
                                let leaf = Node::Leaf {
                                    partial: key_bits.slice(depth + 1, key_bits.len() - depth - 1),
                                    value: value.clone(),
                                };
                                (self.store_node(&leaf), None)
                            }
                        };
                        let new_branch = Node::Branch {
                            left: Some(new_left),
                            right,
                            value: branch_value,
                        };
                        (self.store_node(&new_branch), old_val)
                    }
                }
            }
        };

        if result.0 != old_hash {
            self.remove_node(&old_hash);
        }
        result
    }

    fn split_leaf(
        &mut self,
        new_remaining: &BitVec,
        new_value: &[u8],
        existing_partial: &BitVec,
        existing_value: &[u8],
        common_len: usize,
    ) -> Hash {
        if common_len == new_remaining.len() {
            let existing_leaf = Node::Leaf {
                partial: existing_partial.slice(
                    common_len + 1,
                    existing_partial.len() - common_len - 1,
                ),
                value: existing_value.to_vec(),
            };
            let existing_hash = self.store_node(&existing_leaf);

            let existing_bit = existing_partial.get(common_len);
            let (left, right) = if existing_bit {
                (None, Some(existing_hash))
            } else {
                (Some(existing_hash), None)
            };

            let branch = Node::Branch {
                left,
                right,
                value: Some(new_value.to_vec()),
            };
            let branch_hash = self.store_node(&branch);
            return self.wrap_with_extension(new_remaining, common_len, branch_hash);
        }

        if common_len == existing_partial.len() {
            let new_leaf = Node::Leaf {
                partial: new_remaining.slice(common_len + 1, new_remaining.len() - common_len - 1),
                value: new_value.to_vec(),
            };
            let new_hash = self.store_node(&new_leaf);

            let new_bit = new_remaining.get(common_len);
            let (left, right) = if new_bit {
                (None, Some(new_hash))
            } else {
                (Some(new_hash), None)
            };

            let branch = Node::Branch {
                left,
                right,
                value: Some(existing_value.to_vec()),
            };
            let branch_hash = self.store_node(&branch);
            return self.wrap_with_extension(new_remaining, common_len, branch_hash);
        }

        let new_leaf = Node::Leaf {
            partial: new_remaining.slice(common_len + 1, new_remaining.len() - common_len - 1),
            value: new_value.to_vec(),
        };
        let existing_leaf = Node::Leaf {
            partial: existing_partial.slice(
                common_len + 1,
                existing_partial.len() - common_len - 1,
            ),
            value: existing_value.to_vec(),
        };
        let new_leaf_hash = self.store_node(&new_leaf);
        let existing_leaf_hash = self.store_node(&existing_leaf);

        let new_bit = new_remaining.get(common_len);
        let (left, right) = if new_bit {
            (Some(existing_leaf_hash), Some(new_leaf_hash))
        } else {
            (Some(new_leaf_hash), Some(existing_leaf_hash))
        };

        let branch = Node::Branch {
            left,
            right,
            value: None,
        };
        let branch_hash = self.store_node(&branch);
        self.wrap_with_extension(new_remaining, common_len, branch_hash)
    }

    fn wrap_with_extension(
        &mut self,
        bits: &BitVec,
        prefix_len: usize,
        child_hash: Hash,
    ) -> Hash {
        if prefix_len > 0 {
            let ext = Node::Extension {
                partial: bits.slice(0, prefix_len),
                child: child_hash,
            };
            self.store_node(&ext)
        } else {
            child_hash
        }
    }

    fn split_extension(
        &mut self,
        new_remaining: &BitVec,
        new_value: &[u8],
        ext_partial: &BitVec,
        ext_child: &Hash,
        common_len: usize,
    ) -> Hash {
        if common_len == new_remaining.len() {
            let ext_suffix_len = ext_partial.len() - common_len - 1;
            let ext_child_node = if ext_suffix_len > 0 {
                let suffix = ext_partial.slice(common_len + 1, ext_suffix_len);
                let ext_node = Node::Extension {
                    partial: suffix,
                    child: *ext_child,
                };
                self.store_node(&ext_node)
            } else {
                *ext_child
            };

            let ext_bit = ext_partial.get(common_len);
            let (left, right) = if ext_bit {
                (None, Some(ext_child_node))
            } else {
                (Some(ext_child_node), None)
            };

            let branch = Node::Branch {
                left,
                right,
                value: Some(new_value.to_vec()),
            };
            let branch_hash = self.store_node(&branch);
            return self.wrap_with_extension(new_remaining, common_len, branch_hash);
        }

        let ext_suffix_len = ext_partial.len() - common_len - 1;
        let ext_child_node = if ext_suffix_len > 0 {
            let suffix = ext_partial.slice(common_len + 1, ext_suffix_len);
            let ext_node = Node::Extension {
                partial: suffix,
                child: *ext_child,
            };
            self.store_node(&ext_node)
        } else {
            *ext_child
        };

        let new_suffix_len = new_remaining.len() - common_len - 1;
        let new_leaf = Node::Leaf {
            partial: new_remaining.slice(common_len + 1, new_suffix_len),
            value: new_value.to_vec(),
        };
        let new_leaf_hash = self.store_node(&new_leaf);

        let new_bit = new_remaining.get(common_len);
        let (left, right) = if new_bit {
            (Some(ext_child_node), Some(new_leaf_hash))
        } else {
            (Some(new_leaf_hash), Some(ext_child_node))
        };

        let branch = Node::Branch {
            left,
            right,
            value: None,
        };
        let branch_hash = self.store_node(&branch);
        self.wrap_with_extension(new_remaining, common_len, branch_hash)
    }

    fn delete_recursive(
        &mut self,
        hash: &Hash,
        key_bits: &BitVec,
        depth: usize,
    ) -> Option<(Option<Hash>, Vec<u8>)> {
        let old_hash = *hash;
        let node = self.load_node(hash);
        let result = match node {
            Node::Leaf { partial, value } => {
                let remaining = key_bits.slice(depth, key_bits.len() - depth);
                if remaining == partial {
                    Some((None, value))
                } else {
                    None
                }
            }
            Node::Extension { partial, child } => {
                let remaining_len = key_bits.len() - depth;
                if remaining_len < partial.len() {
                    return None;
                }
                let key_segment = key_bits.slice(depth, partial.len());
                if key_segment != partial {
                    return None;
                }

                let (new_child, old_value) =
                    self.delete_recursive(&child, key_bits, depth + partial.len())?;

                match new_child {
                    None => Some((None, old_value)),
                    Some(new_child_hash) => {
                        let child_node = self.load_node(&new_child_hash);
                        let collapsed = self.try_collapse_extension(&partial, &child_node);
                        Some((Some(collapsed), old_value))
                    }
                }
            }
            Node::Branch {
                left,
                right,
                value: branch_value,
            } => {
                if depth == key_bits.len() {
                    let old_value = branch_value?;
                    let collapsed = self.maybe_collapse_valueless_branch(&left, &right);
                    Some((Some(collapsed), old_value))
                } else {
                    let bit = key_bits.get(depth);
                    if bit {
                        let right_hash = right?;
                        let (new_right, old_value) =
                            self.delete_recursive(&right_hash, key_bits, depth + 1)?;
                        match new_right {
                            None => {
                                let collapsed =
                                    self.collapse_single_child(false, &left, &branch_value);
                                Some((Some(collapsed), old_value))
                            }
                            Some(new_right_hash) => {
                                let new_branch = Node::Branch {
                                    left,
                                    right: Some(new_right_hash),
                                    value: branch_value,
                                };
                                Some((Some(self.store_node(&new_branch)), old_value))
                            }
                        }
                    } else {
                        let left_hash = left?;
                        let (new_left, old_value) =
                            self.delete_recursive(&left_hash, key_bits, depth + 1)?;
                        match new_left {
                            None => {
                                let collapsed =
                                    self.collapse_single_child(true, &right, &branch_value);
                                Some((Some(collapsed), old_value))
                            }
                            Some(new_left_hash) => {
                                let new_branch = Node::Branch {
                                    left: Some(new_left_hash),
                                    right,
                                    value: branch_value,
                                };
                                Some((Some(self.store_node(&new_branch)), old_value))
                            }
                        }
                    }
                }
            }
        };

        if let Some((ref new_hash, _)) = result {
            let changed = match new_hash {
                Some(h) => *h != old_hash,
                None => true,
            };
            if changed {
                self.remove_node(&old_hash);
            }
        }

        result
    }

    fn collapse_single_child(
        &mut self,
        remaining_is_right: bool,
        remaining: &Option<Hash>,
        branch_value: &Option<Vec<u8>>,
    ) -> Hash {
        let bit = remaining_is_right;

        match (remaining, branch_value) {
            (None, Some(val)) => {
                let leaf = Node::Leaf {
                    partial: BitVec::new(),
                    value: val.clone(),
                };
                self.store_node(&leaf)
            }
            (Some(remaining_hash), None) => self.prepend_bit_to_child(bit, remaining_hash),
            (Some(remaining_hash), Some(val)) => {
                let (left, right) = if remaining_is_right {
                    (None, Some(*remaining_hash))
                } else {
                    (Some(*remaining_hash), None)
                };
                let branch = Node::Branch {
                    left,
                    right,
                    value: Some(val.clone()),
                };
                self.store_node(&branch)
            }
            (None, None) => {
                debug_assert!(
                    false,
                    "collapse_single_child called with no remaining child and no value"
                );
                EMPTY_ROOT
            }
        }
    }

    fn prepend_bit_to_child(&mut self, bit: bool, child_hash: &Hash) -> Hash {
        let child_node = self.load_node(child_hash);
        let mut prefix = BitVec::new();
        prefix.push(bit);

        match child_node {
            Node::Leaf { partial, value } => {
                for i in 0..partial.len() {
                    prefix.push(partial.get(i));
                }
                let new_leaf = Node::Leaf {
                    partial: prefix,
                    value,
                };
                self.store_node(&new_leaf)
            }
            Node::Extension { partial, child } => {
                for i in 0..partial.len() {
                    prefix.push(partial.get(i));
                }
                let new_ext = Node::Extension {
                    partial: prefix,
                    child,
                };
                self.store_node(&new_ext)
            }
            Node::Branch { .. } => {
                let ext = Node::Extension {
                    partial: prefix,
                    child: *child_hash,
                };
                self.store_node(&ext)
            }
        }
    }

    fn maybe_collapse_valueless_branch(
        &mut self,
        left: &Option<Hash>,
        right: &Option<Hash>,
    ) -> Hash {
        match (left, right) {
            (Some(l), Some(r)) => {
                let branch = Node::Branch {
                    left: Some(*l),
                    right: Some(*r),
                    value: None,
                };
                self.store_node(&branch)
            }
            (Some(l), None) => self.prepend_bit_to_child(false, l),
            (None, Some(r)) => self.prepend_bit_to_child(true, r),
            (None, None) => {
                debug_assert!(false, "branch with no children and no value");
                EMPTY_ROOT
            }
        }
    }

    fn try_collapse_extension(&mut self, ext_partial: &BitVec, child: &Node) -> Hash {
        match child {
            Node::Leaf { partial, value } => {
                let mut merged = ext_partial.clone();
                for i in 0..partial.len() {
                    merged.push(partial.get(i));
                }
                let new_leaf = Node::Leaf {
                    partial: merged,
                    value: value.clone(),
                };
                self.store_node(&new_leaf)
            }
            Node::Extension {
                partial: child_partial,
                child: grandchild,
            } => {
                let mut merged = ext_partial.clone();
                for i in 0..child_partial.len() {
                    merged.push(child_partial.get(i));
                }
                let new_ext = Node::Extension {
                    partial: merged,
                    child: *grandchild,
                };
                self.store_node(&new_ext)
            }
            Node::Branch { .. } => {
                let stored = self.store_node(child);
                let ext = Node::Extension {
                    partial: ext_partial.clone(),
                    child: stored,
                };
                self.store_node(&ext)
            }
        }
    }

    fn collect_proof(
        &self,
        hash: &Hash,
        key_bits: &BitVec,
        depth: usize,
        proof_nodes: &mut Vec<Vec<u8>>,
    ) {
        let data = match self.db.get(hash) {
            Some(d) => d,
            None => return,
        };
        proof_nodes.push(data.clone());

        let node = match Node::decode(&data) {
            Ok(n) => n,
            Err(_) => return,
        };

        match node {
            Node::Leaf { .. } => {}
            Node::Extension { partial, child } => {
                let remaining_len = key_bits.len() - depth;
                if remaining_len >= partial.len() {
                    let key_segment = key_bits.slice(depth, partial.len());
                    if key_segment == partial {
                        self.collect_proof(&child, key_bits, depth + partial.len(), proof_nodes);
                    }
                }
            }
            Node::Branch { left, right, .. } => {
                if depth < key_bits.len() {
                    let bit = key_bits.get(depth);
                    if bit {
                        if let Some(l) = left {
                            if let Some(left_data) = self.db.get(&l) {
                                proof_nodes.push(left_data);
                            }
                        }
                        if let Some(r) = right {
                            self.collect_proof(&r, key_bits, depth + 1, proof_nodes);
                        }
                    } else {
                        if let Some(r) = right {
                            if let Some(right_data) = self.db.get(&r) {
                                proof_nodes.push(right_data);
                            }
                        }
                        if let Some(l) = left {
                            self.collect_proof(&l, key_bits, depth + 1, proof_nodes);
                        }
                    }
                }
            }
        }
    }
}

impl Default for BinaryPatriciaTrie<MemoryDB> {
    fn default() -> Self {
        Self::new()
    }
}
