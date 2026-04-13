/// Owned sequence of bits, used for partial keys in trie nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitVec {
    /// Packed bytes containing the bits (MSB first within each byte).
    bytes: Vec<u8>,
    /// Number of valid bits (may be less than `bytes.len() * 8`).
    len: usize,
}

impl BitVec {
    /// Create an empty bit vector.
    pub fn new() -> Self {
        Self {
            bytes: Vec::new(),
            len: 0,
        }
    }

    /// Create a `BitVec` from a byte slice, treating every bit as significant.
    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            bytes: data.to_vec(),
            len: data.len() * 8,
        }
    }

    /// Create a `BitVec` from raw packed bytes and a bit length.
    pub fn from_raw(bytes: Vec<u8>, len: usize) -> Self {
        debug_assert!(len <= bytes.len() * 8);
        Self { bytes, len }
    }

    /// Number of bits.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the bit vector is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get the bit at `index` (0 = MSB of first byte). Returns `true` for 1, `false` for 0.
    pub fn get(&self, index: usize) -> bool {
        assert!(index < self.len, "bit index {index} out of range (len {})", self.len);
        let byte_idx = index / 8;
        let bit_idx = 7 - (index % 8);
        (self.bytes[byte_idx] >> bit_idx) & 1 == 1
    }

    /// Push a single bit onto the end.
    pub fn push(&mut self, bit: bool) {
        let byte_idx = self.len / 8;
        let bit_idx = 7 - (self.len % 8);
        if byte_idx >= self.bytes.len() {
            self.bytes.push(0);
        }
        if bit {
            self.bytes[byte_idx] |= 1 << bit_idx;
        }
        self.len += 1;
    }

    /// Return a sub-range as a new `BitVec`.
    pub fn slice(&self, start: usize, length: usize) -> BitVec {
        assert!(start + length <= self.len);
        let mut result = BitVec::new();
        for i in 0..length {
            result.push(self.get(start + i));
        }
        result
    }

    /// Compute the length of the common prefix between `self` and `other`.
    pub fn common_prefix_len(&self, other: &BitVec) -> usize {
        let max = self.len.min(other.len());
        for i in 0..max {
            if self.get(i) != other.get(i) {
                return i;
            }
        }
        max
    }

    /// Encode to bytes: `[varint bit_length] [packed bytes]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = crate::trie::encoding::encode_varint(self.len as u64);
        let byte_count = (self.len + 7) / 8;
        out.extend_from_slice(&self.bytes[..byte_count]);
        out
    }

    /// Decode from a byte slice, returning `(BitVec, bytes_consumed)`.
    pub fn decode(data: &[u8]) -> Result<(BitVec, usize), crate::trie::error::TrieError> {
        let (bit_len, varint_size) =
            crate::trie::encoding::decode_varint(data).ok_or(crate::trie::error::TrieError::DecodingError)?;
        let bit_len = bit_len as usize;
        let byte_count = (bit_len + 7) / 8;
        if data.len() < varint_size + byte_count {
            return Err(crate::trie::error::TrieError::DecodingError);
        }
        let bytes = data[varint_size..varint_size + byte_count].to_vec();
        Ok((BitVec::from_raw(bytes, bit_len), varint_size + byte_count))
    }

    /// Reference to the underlying packed bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Default for BitVec {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_decomposition() {
        // 0xA3 = 1010_0011
        let bv = BitVec::from_bytes(&[0xA3]);
        assert_eq!(bv.len(), 8);
        assert!(bv.get(0));   // 1
        assert!(!bv.get(1));  // 0
        assert!(bv.get(2));   // 1
        assert!(!bv.get(3));  // 0
        assert!(!bv.get(4));  // 0
        assert!(!bv.get(5));  // 0
        assert!(bv.get(6));   // 1
        assert!(bv.get(7));   // 1
    }

    #[test]
    fn push_and_get() {
        let mut bv = BitVec::new();
        bv.push(true);
        bv.push(false);
        bv.push(true);
        assert_eq!(bv.len(), 3);
        assert!(bv.get(0));
        assert!(!bv.get(1));
        assert!(bv.get(2));
    }

    #[test]
    fn common_prefix() {
        let a = BitVec::from_bytes(&[0xFF]);
        let b = BitVec::from_bytes(&[0xF0]);
        assert_eq!(a.common_prefix_len(&b), 4);
    }

    #[test]
    fn slice_round_trip() {
        let bv = BitVec::from_bytes(&[0xA3, 0x5C]);
        let sliced = bv.slice(4, 8);
        assert_eq!(sliced.len(), 8);
        // bits 4..12 of 0xA3_5C = 0011_0101
        for i in 0..8 {
            assert_eq!(sliced.get(i), bv.get(4 + i));
        }
    }

    #[test]
    fn encode_decode_round_trip() {
        let bv = BitVec::from_bytes(&[0xA3, 0x5C]);
        let sliced = bv.slice(3, 11);
        let encoded = sliced.encode();
        let (decoded, consumed) = BitVec::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.len(), sliced.len());
        for i in 0..sliced.len() {
            assert_eq!(decoded.get(i), sliced.get(i));
        }
    }
}
