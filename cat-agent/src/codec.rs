//! Length-prefixed frame encoding/decoding.
//!
//! Wire format: `[4-byte LE length][payload]`

use anyhow::{bail, Result};

#[allow(dead_code)]
const MAX_FRAME_LEN: usize = 16 * 1024 * 1024; // 16 MB

/// Encode `payload` into a length-prefixed frame.
#[allow(dead_code)]
pub fn frame_encode(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Decode a length-prefixed frame from `buf`.
///
/// Returns `(consumed, payload)` where `consumed` is the total bytes read
/// (4-byte header + payload length).
///
/// Errors if the declared length exceeds 16 MB or the buffer is too short.
#[allow(dead_code)]
pub fn frame_decode(buf: &[u8]) -> Result<(usize, &[u8])> {
    if buf.len() < 4 {
        bail!("buffer too short for frame header");
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_FRAME_LEN {
        bail!("frame length {len} exceeds 16 MB limit");
    }
    let total = 4 + len;
    if buf.len() < total {
        bail!("buffer too short: need {total} bytes, have {}", buf.len());
    }
    Ok((total, &buf[4..total]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = b"hello cloakcat";
        let frame = frame_encode(data);
        let (consumed, payload) = frame_decode(&frame).unwrap();
        assert_eq!(consumed, frame.len());
        assert_eq!(payload, data);
    }

    #[test]
    fn empty_payload() {
        let frame = frame_encode(b"");
        let (consumed, payload) = frame_decode(&frame).unwrap();
        assert_eq!(consumed, 4);
        assert!(payload.is_empty());
    }

    #[test]
    fn exceeds_max_length() {
        // Craft a header claiming 16 MB + 1
        let len = (MAX_FRAME_LEN as u32) + 1;
        let buf = len.to_le_bytes();
        let err = frame_decode(&buf).unwrap_err();
        assert!(err.to_string().contains("16 MB"));
    }
}
