// ③ AEAD 记录层的跨进程互通用例。
#[tokio::test]
async fn xel_aead_aes_records_interop_between_processes() {
    run_case("aead-aes").await;
}

#[tokio::test]
async fn xel_aead_chacha_records_interop_between_processes() {
    run_case("aead-chacha").await;
}
