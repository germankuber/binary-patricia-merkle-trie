use crate::trie::bits::BitVec;
use crate::trie::encoding::{decode_varint, encode_varint};
use crate::trie::error::TrieError;

/// A 32-byte Blake2b-256 hash.
pub type Hash = [u8; 32];

/// Compute the Blake2b-256 hash of `data`.
pub fn blake2b_256(data: &[u8]) -> Hash {
    let h = blake2b_simd::Params::new().hash_length(32).hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// The well-known root hash for an empty trie.
pub const EMPTY_ROOT: Hash = [0u8; 32];

// Tag bytes for deterministic node encoding.
const TAG_BRANCH: u8 = 0x00;
const TAG_LEAF: u8 = 0x01;
const TAG_EXTENSION: u8 = 0x02;

// Presence flags for optional children in Branch encoding.
const CHILD_NONE: u8 = 0x00;
const CHILD_PRESENT: u8 = 0x01;

/// A node in the Binary Patricia Merkle Trie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// Branch node with optional left/right children and an optional value.
    ///
    /// At least one child or a value must be present for the node to be valid
    /// in a well-formed trie.
    Branch {
        left: Option<Hash>,
        right: Option<Hash>,
        value: Option<Vec<u8>>,
    },
    /// Leaf node storing the remaining partial key bits and a value.
    Leaf {
        partial: BitVec,
        value: Vec<u8>,
    },
    /// Extension node compressing a shared prefix into a single node.
    Extension {
        partial: BitVec,
        child: Hash,
    },
}

impl Node {
    /// Deterministic binary encoding of the node.
    ///
    /// ```text
    /// Branch:    [0x00] [left_flag: 1] [left: 0|32] [right_flag: 1] [right: 0|32]
    ///            [value_len: varint] [value: variable]
    /// Leaf:      [0x01] [partial bits encoded] [value_len: varint] [value]
    /// Extension: [0x02] [partial bits encoded] [child: 32]
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Node::Branch { left, right, value } => {
                let mut buf = Vec::with_capacity(1 + 1 + 32 + 1 + 32 + 10);
                buf.push(TAG_BRANCH);

                match left {
                    Some(h) => {
                        buf.push(CHILD_PRESENT);
                        buf.extend_from_slice(h);
                    }
                    None => buf.push(CHILD_NONE),
                }

                match right {
                    Some(h) => {
                        buf.push(CHILD_PRESENT);
                        buf.extend_from_slice(h);
                    }
                    None => buf.push(CHILD_NONE),
                }

                match value {
                    Some(v) => {
                        buf.extend_from_slice(&encode_varint(v.len() as u64 + 1));
                        buf.extend_from_slice(v);
                    }
                    None => {
                        buf.push(0); // varint 0 = no value
                    }
                }
                buf
            }
            Node::Leaf { partial, value } => {
                let mut buf = vec![TAG_LEAF];
                buf.extend_from_slice(&partial.encode());
                buf.extend_from_slice(&encode_varint(value.len() as u64));
                buf.extend_from_slice(value);
                buf
            }
            Node::Extension { partial, child } => {
                let mut buf = vec![TAG_EXTENSION];
                buf.extend_from_slice(&partial.encode());
                buf.extend_from_slice(child);
                buf
            }
        }
    }

    /// Decode a node from its binary representation.
    pub fn decode(data: &[u8]) -> Result<Node, TrieError> {
        if data.is_empty() {
            return Err(TrieError::DecodingError);
        }

        match data[0] {
            TAG_BRANCH => Self::decode_branch(&data[1..]),
            TAG_LEAF => Self::decode_leaf(&data[1..]),
            TAG_EXTENSION => Self::decode_extension(&data[1..]),
            _ => Err(TrieError::DecodingError),
        }
    }

    /// Compute the Blake2b-256 hash of this node's encoded form.
    pub fn hash(&self) -> Hash {
        blake2b_256(&self.encode())
    }

    fn decode_branch(data: &[u8]) -> Result<Node, TrieError> {
        let mut pos = 0;

        if pos >= data.len() {
            return Err(TrieError::DecodingError);
        }
        let left = Self::decode_optional_hash(data, &mut pos)?;
        let right = Self::decode_optional_hash(data, &mut pos)?;

        let rest = &data[pos..];
        let (val_encoded, varint_size) = decode_varint(rest).ok_or(TrieError::DecodingError)?;

        let value = if val_encoded == 0 {
            None
        } else {
            let val_len = (val_encoded - 1) as usize;
            if rest.len() < varint_size + val_len {
                return Err(TrieError::DecodingError);
            }
            Some(rest[varint_size..varint_size + val_len].to_vec())
        };

        Ok(Node::Branch { left, right, value })
    }

    fn decode_optional_hash(data: &[u8], pos: &mut usize) -> Result<Option<Hash>, TrieError> {
        if *pos >= data.len() {
            return Err(TrieError::DecodingError);
        }
        let flag = data[*pos];
        *pos += 1;
        match flag {
            CHILD_NONE => Ok(None),
            CHILD_PRESENT => {
                if *pos + 32 > data.len() {
                    return Err(TrieError::DecodingError);
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&data[*pos..*pos + 32]);
                *pos += 32;
                Ok(Some(hash))
            }
            _ => Err(TrieError::DecodingError),
        }
    }

    fn decode_leaf(data: &[u8]) -> Result<Node, TrieError> {
        let (partial, bits_consumed) = BitVec::decode(data)?;
        let rest = &data[bits_consumed..];
        let (val_len, varint_size) = decode_varint(rest).ok_or(TrieError::DecodingError)?;
        let val_len = val_len as usize;
        if rest.len() < varint_size + val_len {
            return Err(TrieError::DecodingError);
        }
        let value = rest[varint_size..varint_size + val_len].to_vec();
        Ok(Node::Leaf { partial, value })
    }

    fn decode_extension(data: &[u8]) -> Result<Node, TrieError> {
        let (partial, bits_consumed) = BitVec::decode(data)?;
        let rest = &data[bits_consumed..];
        if rest.len() < 32 {
            return Err(TrieError::DecodingError);
        }
        let mut child = [0u8; 32];
        child.copy_from_slice(&rest[..32]);
        Ok(Node::Extension { partial, child })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_encode_decode_both_children() {
        let node = Node::Branch {
            left: Some([1u8; 32]),
            right: Some([2u8; 32]),
            value: None,
        };
        let encoded = node.encode();
        let decoded = Node::decode(&encoded).unwrap();
        assert_eq!(node, decoded);
    }

    #[test]
    fn branch_encode_decode_left_only() {
        let node = Node::Branch {
            left: Some([1u8; 32]),
            right: None,
            value: Some(b"val".to_vec()),
        };
        let encoded = node.encode();
        let decoded = Node::decode(&encoded).unwrap();
        assert_eq!(node, decoded);
    }

    #[test]
    fn branch_encode_decode_right_only() {
        let node = Node::Branch {
            left: None,
            right: Some([2u8; 32]),
            value: Some(b"val".to_vec()),
        };
        let encoded = node.encode();
        let decoded = Node::decode(&encoded).unwrap();
        assert_eq!(node, decoded);
    }

    #[test]
    fn branch_encode_decode_with_value() {
        let node = Node::Branch {
            left: Some([1u8; 32]),
            right: Some([2u8; 32]),
            value: Some(b"hello".to_vec()),
        };
        let encoded = node.encode();
        let decoded = Node::decode(&encoded).unwrap();
        assert_eq!(node, decoded);
    }

    #[test]
    fn branch_encode_decode_empty_value() {
        let node = Node::Branch {
            left: Some([1u8; 32]),
            right: Some([2u8; 32]),
            value: Some(vec![]),
        };
        let encoded = node.encode();
        let decoded = Node::decode(&encoded).unwrap();
        assert_eq!(node, decoded);
    }

    #[test]
    fn leaf_encode_decode() {
        let node = Node::Leaf {
            partial: BitVec::from_bytes(&[0xAB, 0xCD]),
            value: b"leaf_value".to_vec(),
        };
        let encoded = node.encode();
        let decoded = Node::decode(&encoded).unwrap();
        assert_eq!(node, decoded);
    }

    #[test]
    fn extension_encode_decode() {
        let node = Node::Extension {
            partial: BitVec::from_bytes(&[0xFF]),
            child: [3u8; 32],
        };
        let encoded = node.encode();
        let decoded = Node::decode(&encoded).unwrap();
        assert_eq!(node, decoded);
    }

    #[test]
    fn hash_determinism() {
        let node = Node::Leaf {
            partial: BitVec::from_bytes(&[0x42]),
            value: b"data".to_vec(),
        };
        assert_eq!(node.hash(), node.hash());
    }
}
