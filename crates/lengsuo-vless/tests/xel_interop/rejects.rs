// ⑤ 失效流必须 fail-closed：错钥、nonce 失步、坏魔数。
#[tokio::test]
async fn xel_wrong_key_is_rejected_between_processes() {
    run_case("wrong-key").await;
}

#[tokio::test]
async fn xel_skipped_record_breaks_nonce_between_processes() {
    run_case("nonce-gap").await;
}

#[tokio::test]
async fn xel_bad_magic_is_rejected_between_processes() {
    run_case("bad-magic").await;
}
