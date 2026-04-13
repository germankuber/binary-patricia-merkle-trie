/// Encode a `u64` as a variable-length integer (LEB128-style).
///
/// Each byte stores 7 bits of data; the MSB is a continuation flag (1 = more bytes follow).
pub fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
    buf
}

/// Decode a variable-length integer from a byte slice.
///
/// Returns `(value, bytes_consumed)` or `None` if the data is truncated.
pub fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in data.iter().enumerate() {
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_small() {
        for v in 0..300u64 {
            let encoded = encode_varint(v);
            let (decoded, size) = decode_varint(&encoded).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(size, encoded.len());
        }
    }

    #[test]
    fn round_trip_large() {
        let values = [0u64, 1, 127, 128, 255, 256, 16383, 16384, u32::MAX as u64, u64::MAX];
        for v in values {
            let encoded = encode_varint(v);
            let (decoded, _) = decode_varint(&encoded).unwrap();
            assert_eq!(decoded, v);
        }
    }
}
