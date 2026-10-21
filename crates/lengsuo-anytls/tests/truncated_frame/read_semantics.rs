//! 读侧三态的**单元级**判据：不经过服务端，直接钉住 `Frame::read` 的错误语义表。
//!
//! 会话层用例（`clean_close` / `truncated` / `isolation`）证明**行为**；
//! 本模块证明**形状**——干净 EOF / 截断头 / 截断载荷是三个不同的错误值。
#![allow(dead_code)]

use super::harness::{discard, TOTAL, WAIT};
use lengsuo_anytls::{
    frame::{self, Command, Eof, Frame},
    Error,
};
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

/// 读侧三态的**单元级**判据：干净 EOF / 截断头 / 截断载荷分别是不同的错误值。
#[tokio::test]
async fn frame_read_distinguishes_clean_eof_from_truncation() {
    timeout(TOTAL, async {
        // 干净 EOF：一个字节都没有。写端必须**丢弃**（或 shutdown）才会有 EOF；
        // 持有 writer 活着则读端只会等到超时。
        let (writer, mut reader) = tokio::io::duplex(64);
        drop(writer);
        let err =
            discard(Frame::read(&mut reader, u16::MAX, WAIT).await).expect_err("干净 EOF 必须报错");
        assert_eq!(
            frame::eof_kind(&err),
            Some(Eof::Clean),
            "0 字节 EOF = 干净关闭，实际：{err}"
        );

        // 截断的帧头：3 字节。
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer
            .write_all(&[Command::Push as u8, 0x00, 0x00])
            .await
            .expect("写半截帧头");
        writer.shutdown().await.expect("半关闭写端");
        let err =
            discard(Frame::read(&mut reader, u16::MAX, WAIT).await).expect_err("截断必须报错");
        assert_eq!(
            frame::eof_kind(&err),
            Some(Eof::Truncated),
            "半个帧头 = 截断，实际：{err}"
        );

        // 截断的载荷：完整头 + 长度字段 100 + 只有 10 字节。
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let mut bytes = Frame {
            command: Command::Push,
            stream_id: 1,
            data: Vec::new(),
        }
        .encode()
        .expect("编码 PUSH");
        bytes[5..7].copy_from_slice(&100u16.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 10]);
        writer.write_all(&bytes).await.expect("写截断帧");
        writer.shutdown().await.expect("半关闭写端");
        let err =
            discard(Frame::read(&mut reader, u16::MAX, WAIT).await).expect_err("截断必须报错");
        assert_eq!(
            frame::eof_kind(&err),
            Some(Eof::Truncated),
            "半个载荷 = 截断，实际：{err}"
        );

        // 三个错误值必须彼此不同（干净 EOF ≠ 截断）。
        let clean = frame::eof_kind(&err);
        assert_ne!(clean, Some(Eof::Clean), "截断不得与干净 EOF 同形");
    })
    .await
    .expect("用例超时");
}

/// `Error` 枚举不得把「干净 EOF」与「截断」压成同一个值。
///
/// 这条钉住错误语义表的**形状**：`Error::Io` 的 kind 仍是 `UnexpectedEof`
/// （既有用例钉着它，不可改动），但**内层**必须带 `Eof` 分类 ⇒ 两者可区分。
#[tokio::test]
async fn eof_classification_is_carried_inside_the_io_error() {
    timeout(TOTAL, async {
        let (writer, mut reader) = tokio::io::duplex(64);
        drop(writer);
        let err =
            discard(Frame::read(&mut reader, u16::MAX, WAIT).await).expect_err("干净 EOF 必须报错");
        let Error::Io(io) = &err else {
            panic!("EOF 必须表现为 Io 错误，实际：{err}");
        };
        assert_eq!(
            io.kind(),
            std::io::ErrorKind::UnexpectedEof,
            "传输层 kind 保持 UnexpectedEof（既有用例钉住）"
        );
        let inner = io.get_ref().expect("内层 EOF 分类");
        assert!(
            inner.downcast_ref::<Eof>().is_some(),
            "内层必须携带 Eof 分类 ⇒ 干净 EOF 与截断可区分"
        );
    })
    .await
    .expect("用例超时");
}
