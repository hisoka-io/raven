//! Length-prefixed framing for bench transports.
//!
//! Wire format: little-endian `u32` payload length, then that many payload
//! bytes. Empty and oversized (> [`MAX_FRAME_SIZE`]) payloads are rejected
//! on both sides.

use std::io::{self, Read, Write};

/// Maximum payload size per frame, in bytes.
pub const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

/// Write a single length-prefixed frame.
///
/// Errors if `payload` is empty or larger than [`MAX_FRAME_SIZE`].
pub fn write_frame<W: Write>(mut w: W, payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame payload must be non-empty",
        ));
    }
    if payload.len() > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "frame payload size {} exceeds maximum {}",
                payload.len(),
                MAX_FRAME_SIZE
            ),
        ));
    }
    let len = u32::try_from(payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame payload size exceeds u32",
        )
    })?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(payload)
}

/// Read a single length-prefixed frame.
///
/// Errors on empty frames, oversized frames, or premature EOF.
pub fn read_frame<R: Read>(mut r: R) -> io::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes)?;
    // integer cast hygiene. `u32 as usize` is widening on
    // every modern target (usize is ≥ 32 bits for our supported
    // platforms native + wasm32). Explicit `try_into` matches the
    // lint posture + keeps the cast inspectable.
    let len = usize::try_from(u32::from_le_bytes(len_bytes)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "frame length exceeds usize on this target",
        )
    })?;
    if len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame payload size must be non-zero",
        ));
    }
    if len > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame payload size {len} exceeds maximum {MAX_FRAME_SIZE}"),
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_single_frame() {
        let payload = vec![1u8, 2, 3, 4, 5];
        let mut buf = Vec::new();
        write_frame(&mut buf, &payload).expect("write");

        let mut cursor = Cursor::new(buf);
        let out = read_frame(&mut cursor).expect("read");
        assert_eq!(out, payload);
    }

    /// Known-answer test for the exact on-wire byte layout.
    ///
    /// This freezes the wire format so a reader written to an older version
    /// of this module can still decode frames produced today, and vice
    /// versa. Any change that alters the bytes here is breaking and must be
    /// versioned explicitly.
    #[test]
    fn kat_hello_frame_bytes() {
        let payload = b"hello";
        let mut buf = Vec::new();
        write_frame(&mut buf, payload).expect("write");

        // u32 little-endian length prefix (= 5) followed by the payload.
        let expected: [u8; 9] = [0x05, 0x00, 0x00, 0x00, b'h', b'e', b'l', b'l', b'o'];
        assert_eq!(buf, expected);
    }

    #[test]
    fn roundtrip_multiple_frames_preserves_order() {
        let p1 = vec![0xAA; 32];
        let p2 = vec![0xBB; 1024];
        let p3 = vec![0xCC; 1];
        let mut buf = Vec::new();
        write_frame(&mut buf, &p1).expect("write 1");
        write_frame(&mut buf, &p2).expect("write 2");
        write_frame(&mut buf, &p3).expect("write 3");

        let mut cursor = Cursor::new(buf);
        assert_eq!(read_frame(&mut cursor).expect("read 1"), p1);
        assert_eq!(read_frame(&mut cursor).expect("read 2"), p2);
        assert_eq!(read_frame(&mut cursor).expect("read 3"), p3);
    }

    #[test]
    fn empty_payload_is_rejected_by_writer() {
        let mut buf = Vec::new();
        let err = write_frame(&mut buf, &[]).expect_err("empty frame must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn zero_length_prefix_is_rejected_by_reader() {
        let buf = 0u32.to_le_bytes().to_vec();
        let err = read_frame(Cursor::new(buf)).expect_err("zero-length frame must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn oversized_frame_is_rejected_by_reader() {
        let buf = (u32::MAX - 1).to_le_bytes().to_vec();
        let err = read_frame(Cursor::new(buf)).expect_err("oversized frame must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn truncated_payload_is_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&10u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 5]); // only 5 of promised 10 bytes
        let err = read_frame(Cursor::new(buf)).expect_err("truncated frame must error");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
