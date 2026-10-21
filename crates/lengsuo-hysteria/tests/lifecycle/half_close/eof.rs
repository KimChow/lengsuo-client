// 「EOF 且缓冲空」= 干净 EOF；「EOF 且残留半帧」= 协议错误（帧级判定）。
/// A2b：「EOF 且缓冲空」是干净 EOF，「EOF 且残留半帧」才是协议错误。
///
/// 本用例把两种 EOF 语义**显式区分**开：
///
/// 1. **干净 EOF（端到端，客户端方向）**：服务端把**完整**响应帧发完后
///    关闭流 ⇒ 客户端先读到完整帧，再读到 `Ok(0)`，且**缓冲已空**
///    ⇒ 判为干净 EOF（对齐参考 `common/buf/copy.go` 的 `Copy` 遇
///    `io.EOF` 正常返回 nil）。
/// 2. **残缺帧 = 协议错误（帧级判定）**：一个**被截断**的 TCPResponse
///    帧，解码器必须报 `Truncated`（协议错误），**不得**被当成完整帧
///    接受（对齐参考 `protocol.go` `ReadTCPResponse` 的 `io.ReadFull`
///    短读 ⇒ 错误）。
///
/// ⚠️ 口径说明（为什么第 2 条在帧级而不是流级断言）：
/// QUIC 流的读侧只把 **FIN** 映射成 EOF（`Ok(None)`），QUIC 本身没有
/// 「半帧」概念（HTTP/3 的帧边界在 H3 层）；而本仓服务端的响应帧是
/// `send.write_all(&response)` **原子**写出的 ⇒ 「干净 FIN + 半截响应
/// 帧」在**客户端流层**不可构造。故协议级判定落在**帧解码器**上，
/// 而**服务端请求解析器**的同类判定（残缺请求 ⇒ 拒绝、不建承载）由
/// `cleanup::cleanup_server_rejects_malformed_frame_without_residue`
/// 端到端覆盖。
#[tokio::test]
async fn half_close_clean_eof_is_distinct_from_truncated_frame() {
    let server = start_server("hc2b", 60).await;
    let client = connect_with(&server, &server.auth).await.expect("建连失败");

    // --- 1. 干净 EOF：完整响应帧 + 流结束 ---
    let target = spawn_tcp_target(TargetScript::CloseAfterFirstRead).await;
    let mut stream = proxy::tcp_connect(&client, &target.addr.to_string())
        .await
        .expect("tcp_connect 失败");
    // 写一点数据让服务端侧承载跑起来（响应帧此时已完整发出）。
    let write_fut = async {
        stream.write_all(b"ping").await.expect("写入失败");
        stream.finish().expect("半关闭失败");
    };
    tokio::time::timeout(IO_TIMEOUT, write_fut)
        .await
        .expect("写入 + 半关闭超时");

    // 读方向：先拿到响应帧之后的目标数据（此处为空），再拿到干净 EOF。
    // `ReadOutcome::CleanEof` 的定义就是「EOF 且缓冲为空」。
    let outcome = tokio::time::timeout(IO_TIMEOUT, super::read_proxy_to_eof(&mut stream))
        .await
        .expect("等待干净 EOF 超时");
    match outcome {
        super::ReadOutcome::CleanEof { data } => {
            assert!(data.is_empty(), "完整响应帧之后不应有残留字节");
        }
        super::ReadOutcome::EofWithResidue { data } => {
            panic!("完整响应帧后读到的是「EOF 且有残留」（{data:?}）——不该发生")
        }
        super::ReadOutcome::ReadError { err, .. } => {
            panic!("干净路径不应有读错误：{err}");
        }
    }

    // --- 2. 残缺帧 = 协议错误（帧级判定）---
    // 完整帧：解码器必须接受。
    let full = TcpResponse {
        status: Status::Ok,
        message: "ok".to_string(),
        padding: vec![0u8; 16],
    }
    .encode()
    .expect("编码完整响应帧");
    let (decoded, consumed) = TcpResponse::decode(&full).expect("完整帧应解码成功");
    assert_eq!(decoded.status, Status::Ok, "完整帧的状态字节应正确");
    assert_eq!(consumed, full.len(), "完整帧应被精确消耗");

    // 截断到一半：解码器必须报**协议错误**（`Truncated`），不得放行。
    let truncated = &full[..full.len() / 2];
    match TcpResponse::decode(truncated) {
        Err(lengsuo_hysteria::Error::Truncated { .. }) => {}
        Err(other) => panic!("残缺帧应报 Truncated，实际 {other:?}"),
        Ok(_) => panic!("残缺帧不得被当成完整帧接受（协议错误被放行）"),
    }
}
