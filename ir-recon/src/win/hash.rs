//! Bounded SHA-256 of a file, for the "here is the hash, look it up yourself" line
//! in the report.
//!
//! The cap is the point of this module. A scan runs on a machine that may be
//! hostile, so hashing every file to EOF would let a planted 40 GB file stall the
//! whole triage run. Callers pass `max_bytes`; when a file is larger, only the
//! first `max_bytes` are hashed and the report says the hash is partial. That is a
//! deliberate trade: a truncated hash is not a lookup key for a full-file
//! reputation lookup, but it is still stable and cheap, and the report never
//! pretends otherwise.
//!
//! Reading is chunked, so memory use is one 64 KiB buffer regardless of file size,
//! and the loop stops the moment the cap is reached (FR-13 evidence, SR-2).

use std::fs::File;
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Read granularity. Large enough that the syscall overhead disappears, small
/// enough that 64 KiB per hashed file is irrelevant next to the process table.
pub const CHUNK_BYTES: usize = 64 * 1024;

/// SHA-256 of the first `max_bytes` of `path`, lower-case hex.
///
/// `None` on any error (missing file, permission denied, a directory). A `None`
/// is reported as "hash unavailable", never as a clean file.
///
/// `max_bytes == 0` hashes the empty input; it does not read the file at all, so a
/// caller that cannot afford the read gets a defined value rather than an error.
pub fn sha256_file(path: &Path, max_bytes: u64) -> Option<String> {
    // A directory is not a hashable object; catching it here keeps a directory
    // walk that accidentally passed one from reporting a meaningless hash.
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }

    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK_BYTES];
    let mut remaining = max_bytes;

    while remaining > 0 {
        // Never ask for more than the caller's cap and never more than the
        // buffer: the cap is an upper bound on bytes read, not a hint.
        let want = remaining.min(CHUNK_BYTES as u64) as usize;
        let n = match file.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        };
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }

    Some(hex(&hasher.finalize()))
}

/// SHA-256 of an in-memory buffer, lower-case hex.
///
/// Used for small artefact strings (a task action, a registry value) where the
/// hash is attached as evidence rather than looked up.
pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex(&hasher.finalize())
}

/// Lower-case hex of a digest. Written out rather than pulled from a crate: it is
/// eight lines and it keeps the dependency list short.
fn hex(digest: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Published NIST/`sha256sum` value for "abc". The one known-answer test that
    /// proves the wiring (Digest -> finalize -> hex) is actually SHA-256 and not a
    /// half-initialised hasher that still returns 64 plausible characters.
    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn temp_file(tag: &str, data: &[u8]) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("irscan_hash_{tag}_{}.bin", std::process::id()));
        let mut f = match std::fs::File::create(&path) {
            Ok(f) => f,
            Err(_) => return path, // caller's assertions will surface the failure
        };
        let _ = f.write_all(data);
        let _ = f.flush();
        path
    }

    #[test]
    fn known_answer_matches_the_published_digest() {
        assert_eq!(sha256_bytes(b"abc"), ABC_SHA256);
    }

    #[test]
    fn empty_input_hashes_to_the_published_empty_digest() {
        assert_eq!(sha256_bytes(b""), EMPTY_SHA256);
        assert_eq!(hex(&[]), "");
        assert_eq!(sha256_bytes(b"\0"), sha256_bytes(&[0u8]));
    }

    #[test]
    fn files_hash_identically_to_the_in_memory_bytes() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let path = temp_file("eq", &data);
        assert_eq!(
            sha256_file(&path, data.len() as u64),
            Some(sha256_bytes(&data))
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn hashing_across_a_chunk_boundary_is_not_truncated_or_padded() {
        // One full chunk plus a tail, so the loop runs more than once and the last
        // read is short. A off-by-one in the chunk slicing shows up here.
        let data: Vec<u8> = (0..CHUNK_BYTES + 1234).map(|i| (i % 253) as u8).collect();
        let path = temp_file("chunk", &data);
        assert_eq!(sha256_file(&path, u64::MAX), Some(sha256_bytes(&data)));
        assert_eq!(
            sha256_file(&path, data.len() as u64),
            Some(sha256_bytes(&data))
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn max_bytes_truncates_the_read_and_hashes_only_that_prefix() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let path = temp_file("cap", &data);

        let capped = sha256_file(&path, 100);
        // The cap is honoured: the result is the hash of the first 100 bytes, not
        // of the whole file.
        assert_eq!(capped, Some(sha256_bytes(&data[..100])));
        assert_ne!(capped, Some(sha256_bytes(&data)));

        // A zero cap reads nothing and still returns a defined value.
        assert_eq!(sha256_file(&path, 0), Some(EMPTY_SHA256.to_string()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_and_directory_are_none_not_a_panic() {
        let mut missing = std::env::temp_dir();
        missing.push("irscan_hash_definitely_absent_file_3f9c.bin");
        assert_eq!(sha256_file(&missing, 1024), None);
        assert_eq!(sha256_file(&std::env::temp_dir(), 1024), None);
    }
}
