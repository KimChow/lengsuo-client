//! Independent Python digest vectors and bounded stream failure paths.
mod fixture;
use fixture::*;
use lengsuo_browser_package::{VerifyError, READ_CHUNK_BYTES};
use std::io::{self, Read};

#[test]
fn known_python_vectors_match_for_short_and_boundary_reads() {
    for &(size, digest) in KNOWN_VECTORS {
        let manifest = manifest_for(size);
        let data = lcg_payload(size);
        for chunk in [1, 17, READ_CHUNK_BYTES] {
            let report = manifest.verify_reader(Dribble::new(&data, chunk)).unwrap();
            assert_eq!(report.bytes_read(), size as u64);
            assert_eq!(report.sha256(), digest);
        }
    }
}

#[test]
fn truncated_stream_is_distinct_from_wrong_hash() {
    let manifest = manifest_for(64);
    for size in [0, 1, 63] {
        assert!(matches!(manifest.verify_reader(&lcg_payload(size)[..]),
            Err(VerifyError::Truncated { expected: 64, got }) if got == size as u64));
    }
    let mut corrupt = lcg_payload(64);
    corrupt[0] ^= 1;
    assert!(matches!(
        manifest.verify_reader(&corrupt[..]),
        Err(VerifyError::DigestMismatch { .. })
    ));
}

#[test]
fn oversize_stops_at_first_extra_byte_even_for_unbounded_input() {
    assert!(matches!(
        manifest_for(64).verify_reader(EndlessOversize::new(64)),
        Err(VerifyError::Oversize {
            expected: 64,
            got: 65
        })
    ));
    let mut input = io::Cursor::new(vec![0u8; 100_000]);
    assert!(matches!(
        manifest_for(64).verify_reader(&mut input),
        Err(VerifyError::Oversize { .. })
    ));
    assert_eq!(input.position(), 65);
}

#[test]
fn io_failure_preserves_offset_and_error_kind() {
    for size in [0, 3, 64] {
        let input = FailAfterChunks::new(&lcg_payload(size), 3, io::ErrorKind::ConnectionReset);
        match manifest_for(64).verify_reader(input) {
            Err(VerifyError::Io { read, source }) => {
                assert_eq!(read, size as u64);
                assert_eq!(source.kind(), io::ErrorKind::ConnectionReset);
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }
}

#[test]
fn invalid_manifest_never_reads_untrusted_body() {
    struct MustNotRead;
    impl Read for MustNotRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("must validate first")
        }
    }
    let mut manifest = manifest_for(64);
    manifest.size_bytes = 0;
    assert!(matches!(
        manifest.verify_reader(MustNotRead),
        Err(VerifyError::Manifest(_))
    ));
}

#[test]
fn reader_buffer_is_bounded_for_large_declared_artifact() {
    struct Probe;
    impl Read for Probe {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            assert!(buf.len() <= READ_CHUNK_BYTES);
            Err(io::Error::other("probe"))
        }
    }
    let mut manifest = manifest_for(64);
    manifest.size_bytes = 16 * 1024 * 1024 * 1024;
    assert!(matches!(
        manifest.verify_reader(Probe),
        Err(VerifyError::Io { read: 0, .. })
    ));
}
