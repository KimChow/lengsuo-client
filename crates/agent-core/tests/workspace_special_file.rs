#[cfg(target_os = "linux")]
#[test]
fn named_pipe_is_rejected_without_waiting_for_a_writer() {
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("pipe");
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let root = dir.path().to_path_buf();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = agent_core::workspace_read::read_workspace_file(root, "pipe", 1024);
        let _ = tx.send(result);
    });
    let result = rx
        .recv_timeout(Duration::from_secs(1))
        .expect("special-file rejection must not block in open");
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    worker.join().unwrap();
}
