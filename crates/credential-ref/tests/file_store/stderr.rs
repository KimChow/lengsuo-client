//! stderr 静默约束（自原 file_store.rs 原样搬移）。

#[test]
fn reopen_and_auth_failure_do_not_write_stderr() {
    let exe = std::env::current_exe().expect("test executable");
    for name in [
        "put_get_roundtrip_and_reopen_keeps_plaintext",
        "wrong_passphrase_is_rejected_on_open",
    ] {
        let result = std::process::Command::new(&exe)
            .args(["--exact", name, "--nocapture"])
            .output()
            .expect("child test");
        assert!(result.status.success(), "child test failed");
        assert!(
            result.stderr.is_empty(),
            "credential operations must not emit diagnostics to stderr"
        );
    }
}
