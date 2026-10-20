//! UDP 关联的**成帧**回归用例：流侧一帧被切成多块时必须等齐（短读不是错误），
//! 一次读到的多余字节必须留给后续帧（不得丢弃）。
//!
//! 语义基线：Xray v26.3.27（`d2758a0`）`proxy/trojan/protocol.go` 的
//! `PacketReader.ReadMultiBuffer` 用 `io.ReadFull` 读载荷——短读会**继续等**，
//! 不是错误；参考侧的 `PacketWriter` 也把一帧写成**连续**字节。
//!
//! 这两条都是实机互通（Xray 客户端 → 本仓服务端）时暴露出来的：
//! 大载荷帧在 TLS 流上被切成多块时，若把「声明长度 > 已到达字节」当成协议错误，
//! 整条关联会被立刻掐断；若忽略解码器的消耗长度，一次读到的下一帧前半段会被丢掉。
//!
//! 观测面：回程**逐字节**比对 + 回显后端**收包计数**（不靠“没报错”当通过）。

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use lengsuo_trojan::udp_relay::relay;
use lengsuo_trojan::{udp, TargetAddr};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(5);
const TOTAL: Duration = Duration::from_secs(30);
/// 默认单包上限取参考服务端策略值。
const LIMIT: usize = lengsuo_trojan::stream::REFERENCE_MAX_DATAGRAM_PAYLOAD;

/// 脚本化读侧：按**预先切好的块**逐块交付，每次 `poll_read` 最多交一块。
///
/// 确定性：与 TCP/TLS 如何分段无关，块边界由测试自己定。
struct ScriptedReader {
    rx: mpsc::Receiver<Vec<u8>>,
    current: Vec<u8>,
    pos: usize,
}

impl ScriptedReader {
    fn new(rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            current: Vec::new(),
            pos: 0,
        }
    }
}

impl AsyncRead for ScriptedReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.pos < this.current.len() {
                let take = (this.current.len() - this.pos).min(buf.remaining());
                buf.put_slice(&this.current[this.pos..this.pos + take]);
                this.pos += take;
                return Poll::Ready(Ok(()));
            }
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    this.current = chunk;
                    this.pos = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// 起一个 UDP 回显服务：原样回写收到的每个数据报，返回其端口。
async fn spawn_udp_echo() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    port
}

fn v4_target(port: u16) -> TargetAddr {
    TargetAddr::V4([127, 0, 0, 1], port)
}

/// 从流侧读一个回程报文（带总超时）。
async fn read_reply<R: AsyncRead + Unpin>(reader: &mut R) -> (TargetAddr, Vec<u8>) {
    let mut buf = vec![0u8; 1 + 1 + 255 + 2 + 2 + 2 + LIMIT];
    let mut filled = 0usize;
    loop {
        match udp::decode_packet(&buf[..filled], LIMIT) {
            Ok(((addr, payload), _)) => return (addr, payload.to_vec()),
            // 头部齐了但载荷没到齐：继续读（与帧读取侧同口径）。
            Err(udp::Error::Truncated { .. }) | Err(udp::Error::LengthMismatch { .. }) => {
                let n = timeout(WAIT, reader.read(&mut buf[filled..]))
                    .await
                    .expect("回程超时")
                    .expect("回程读失败");
                assert!(n > 0, "对端在回程到达前关闭");
                filled += n;
            }
            Err(other) => panic!("回程报文非法 {other:?}"),
        }
    }
}

/// 尝试读一个回程报文：流侧已结束（EOF）时返回 `None`（不 panic）。
async fn try_read_reply<R: AsyncRead + Unpin>(reader: &mut R) -> Option<(TargetAddr, Vec<u8>)> {
    let mut buf = vec![0u8; 1 + 1 + 255 + 2 + 2 + 2 + LIMIT];
    let mut filled = 0usize;
    loop {
        match udp::decode_packet(&buf[..filled], LIMIT) {
            Ok(((addr, payload), _)) => return Some((addr, payload.to_vec())),
            Err(udp::Error::Truncated { .. }) | Err(udp::Error::LengthMismatch { .. }) => {
                let n = timeout(WAIT, reader.read(&mut buf[filled..]))
                    .await
                    .ok()?
                    .ok()?;
                if n == 0 {
                    return None;
                }
                filled += n;
            }
            Err(other) => panic!("回程报文非法 {other:?}"),
        }
    }
}

/// 起一个「脚本化读侧 + 回程写侧」的关联，返回（投递块的发送端、回程读端）。
fn spawn_association() -> (
    mpsc::Sender<Vec<u8>>,
    tokio::io::ReadHalf<tokio::io::DuplexStream>,
) {
    let (tx, rx) = mpsc::channel(32);
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let (client_read, _client_write) = tokio::io::split(client_side);
    let (_server_read, server_write) = tokio::io::split(server_side);
    tokio::spawn(async move {
        let reader = ScriptedReader::new(rx);
        let _ = relay(reader, server_write, LIMIT, WAIT).await;
    });
    (tx, client_read)
}

/// ① 一帧被切成多块（地址/长度/CRLF 在第一块，载荷分两块）：必须**等齐**再转发。
///
/// 回归点：块边界处 `decode_packet` 报「声明长度 > 已到达字节」，这不是协议错误，
/// 必须继续读（对齐参考 `io.ReadFull`）；当成错误会让整条关联被掐断。
#[tokio::test]
async fn frame_split_across_reads_is_reassembled() {
    timeout(TOTAL, async {
        let echo_port = spawn_udp_echo().await;
        let target = v4_target(echo_port);
        let (tx, mut reply) = spawn_association();

        let payload = &[0x37u8; 8180];
        let frame = udp::encode_packet(&target, payload).unwrap();
        // 头部 = 地址(7) + 长度(2) + CRLF(2)。
        let head = 11usize;
        assert!(frame.len() > head + 2);
        let split = frame.len() / 2;

        // 三块：头部 / 载荷前半 / 载荷后半。
        tx.send(frame[..head].to_vec()).await.unwrap();
        tx.send(frame[head..split].to_vec()).await.unwrap();
        tx.send(frame[split..].to_vec()).await.unwrap();

        let (addr, echoed) = read_reply(&mut reply).await;
        assert_eq!(addr, target, "回程地址须与请求一致");
        assert_eq!(echoed, payload, "分块到达的帧必须逐字节重组后转发");

        drop(tx);
    })
    .await
    .unwrap();
}

/// ② 两帧**背靠背在同一次读**里到达：两帧都必须被转发（不得丢掉第二帧）。
///
/// 回归点：解码器返回的消耗长度被忽略时，一次读里的第二帧前半段会被丢掉。
#[tokio::test]
async fn back_to_back_frames_in_one_read_are_both_delivered() {
    timeout(TOTAL, async {
        let first_port = spawn_udp_echo().await;
        let second_port = spawn_udp_echo().await;
        let (tx, mut reply) = spawn_association();

        let first = v4_target(first_port);
        let second = v4_target(second_port);
        let mut stream = udp::encode_packet(&first, b"first-frame").unwrap();
        stream.extend_from_slice(&udp::encode_packet(&second, b"second-frame").unwrap());

        // 一次性投递两帧。
        tx.send(stream).await.unwrap();

        let (addr_a, payload_a) = read_reply(&mut reply).await;
        let (addr_b, payload_b) = read_reply(&mut reply).await;
        // 回程顺序不保证（两个目标各自的回程是异步到达的），按内容配对。
        let mut payloads = vec![payload_a, payload_b];
        payloads.sort();
        assert_eq!(
            payloads,
            [b"first-frame".to_vec(), b"second-frame".to_vec()],
            "两帧的载荷都不得丢失"
        );
        let mut addrs = [addr_a, addr_b];
        addrs.sort_by_key(|addr| match addr {
            TargetAddr::V4(_, port) => u32::from(*port),
            _ => u32::MAX,
        });
        assert!(
            addrs.contains(&first) && addrs.contains(&second),
            "两帧的目标不同，两个回程地址都必须出现"
        );

        drop(tx);
    })
    .await
    .unwrap();
}

/// ③ 短读与背靠背同时出现：分块的第一帧 + 粘在同一次读里的第二帧，都不得丢。
#[tokio::test]
async fn split_frame_followed_by_coalesced_frame_are_both_delivered() {
    timeout(TOTAL, async {
        let first_port = spawn_udp_echo().await;
        let second_port = spawn_udp_echo().await;
        let (tx, mut reply) = spawn_association();

        let first = v4_target(first_port);
        let second = v4_target(second_port);
        let head = 11usize;
        let frame = udp::encode_packet(&first, &[0x5au8; 4096]).unwrap();
        let tail = udp::encode_packet(&second, b"after-split").unwrap();

        // 第一块：只到头部（载荷未齐）。
        tx.send(frame[..head].to_vec()).await.unwrap();
        // 第二块：补齐第一帧的载荷，**并粘上**第二帧。
        let mut second_chunk = frame[head..].to_vec();
        second_chunk.extend_from_slice(&tail);
        tx.send(second_chunk).await.unwrap();

        let (addr_a, payload_a) = read_reply(&mut reply).await;
        let (addr_b, payload_b) = read_reply(&mut reply).await;
        // 回程顺序不保证（两个目标各自异步回程）：按内容配对。
        let mut payloads = [payload_a, payload_b];
        payloads.sort_by_key(|payload| payload.len());
        assert_eq!(payloads[0], b"after-split", "粘着的次帧不得丢失");
        assert_eq!(payloads[1].len(), 4096, "分块帧的载荷必须完整");
        assert!(
            payloads[1].iter().all(|byte| *byte == 0x5a),
            "分块帧的载荷内容必须逐字节一致"
        );
        let mut addrs = [addr_a, addr_b];
        addrs.sort_by_key(|addr| match addr {
            TargetAddr::V4(_, port) => u32::from(*port),
            _ => u32::MAX,
        });
        assert!(
            addrs.contains(&first) && addrs.contains(&second),
            "两帧的目标不同，两个回程地址都必须出现"
        );

        drop(tx);
    })
    .await
    .unwrap();
}

/// ④ 读侧在**半帧**处结束：fail-closed（不得把半帧当整帧转发）。
#[tokio::test]
async fn half_frame_at_eof_is_rejected_fail_closed() {
    timeout(TOTAL, async {
        let echo_port = spawn_udp_echo().await;
        let target = v4_target(echo_port);
        let (tx, mut reply) = spawn_association();

        // 头部齐全但载荷声明 64 字节、实到 0 字节，然后 EOF。
        let mut frame = Vec::new();
        target.encode_into(&mut frame);
        frame.extend_from_slice(&64u16.to_be_bytes());
        frame.extend_from_slice(&udp::CRLF);
        tx.send(frame).await.unwrap();
        drop(tx);

        // 半帧不得被当成整帧转发 ⇒ 流侧不会有回程（流侧被 fail-closed 掐断也算没有）。
        let leaked = timeout(Duration::from_millis(800), try_read_reply(&mut reply))
            .await
            .ok()
            .flatten()
            .is_some();
        assert!(!leaked, "半帧不得被转发");
    })
    .await
    .unwrap();
}
