// ④ XOR 掩蔽（AES ⊕ XOR）与纯分帧（仅头部掩蔽）的跨进程互通用例。
#[tokio::test]
async fn xel_xor_masked_aead_records_interop_between_processes() {
    run_case("aead-xor").await;
}

#[tokio::test]
async fn xel_xor_header_only_framing_interop_between_processes() {
    run_case("xor-only").await;
}
