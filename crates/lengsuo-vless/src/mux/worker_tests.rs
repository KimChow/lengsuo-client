#[cfg(test)]
mod tests {
    use super::*;
    use crate::mux::frame::{
        decode_address_port, read_data, SessionStatus, OPTION_DATA, TARGET_NETWORK_TCP,
    };
    use std::io::Cursor;

    fn tcp(host: &str, port: u16) -> (TargetAddr, TargetNetwork) {
        (
            TargetAddr::Domain(host.to_string(), port),
            TargetNetwork::Tcp,
        )
    }

    fn drain_frame(wire: &[u8]) -> (FrameMetadata, Result<Vec<u8>, FrameError>) {
        let mut reader = Cursor::new(wire);
        let meta = FrameMetadata::decode_from(&mut reader, false).expect("帧头可解码");
        let data = if meta.has_data() {
            read_data(&mut reader, meta.status != SessionStatus::New)
        } else {
            Err(FrameError::MetaTooLong)
        };
        (meta, data)
    }

    #[test]
    fn writer_first_frame_is_new_then_keep_and_end_closes() {
        let mut out = Vec::new();
        let mut writer = SessionWriter::request(9, tcp("example.invalid", 443), TargetNetwork::Tcp);
        writer.write_data(&mut out, b"first").expect("可写");
        writer.write_data(&mut out, b"second").expect("可写");
        writer.close(&mut out).expect("可写");

        let (first, data) = drain_frame(&out);
        assert_eq!(first.status, SessionStatus::New);
        assert_eq!(first.session_id, 9);
        assert!(first.has_data());
        assert_eq!(first.target, Some(tcp("example.invalid", 443)));
        assert_eq!(data.expect("首帧有数据"), b"first".to_vec());

        // 第二帧的元数据体长度是 4（无地址），需要逐段重解。
        let mut reader = Cursor::new(&out);
        FrameMetadata::decode_from(&mut reader, false).expect("首帧");
        read_data(&mut reader, true).expect("首帧数据");
        let second = FrameMetadata::decode_from(&mut reader, false).expect("第二帧");
        assert_eq!(second.status, SessionStatus::Keep);
        assert_eq!(second.target, None, "Keep 帧不带地址");
        assert_eq!(read_data(&mut reader, true).expect("第二帧数据"), b"second");

        let third = FrameMetadata::decode_from(&mut reader, false).expect("第三帧");
        assert_eq!(third.status, SessionStatus::End);
        assert!(!third.has_data());
        assert!(!third.has_error());
    }

    #[test]
    fn writer_splits_stream_chunks_at_8192_and_keeps_packets_whole() {
        let payload = vec![0xAB; STREAM_CHUNK_SIZE + 10];
        let mut out = Vec::new();
        SessionWriter::request(1, tcp("a.invalid", 1), TargetNetwork::Tcp)
            .write_multi(&mut out, &payload)
            .expect("可写");
        let mut reader = Cursor::new(&out);
        let mut seen = Vec::new();
        let mut statuses = Vec::new();
        while (reader.position() as usize) < out.len() {
            let meta = FrameMetadata::decode_from(&mut reader, false).expect("帧头");
            statuses.push(meta.status);
            seen.push(read_data(&mut reader, true).expect("数据"));
        }
        assert_eq!(
            statuses,
            vec![SessionStatus::New, SessionStatus::Keep],
            "首帧 New、续帧 Keep"
        );
        assert_eq!(seen.len(), 2, "8KiB+10 分两帧（SplitSize 语义）");
        assert_eq!(seen[0].len(), STREAM_CHUNK_SIZE);
        assert_eq!(seen[1].len(), 10);
        assert_eq!(seen.concat(), payload);

        // 分组会话：一帧一包，不切分。
        let packet = vec![0xCD; STREAM_CHUNK_SIZE + 10];
        let mut out = Vec::new();
        let mut writer = SessionWriter::request(
            2,
            (
                TargetAddr::Domain("a.invalid".to_string(), 1),
                TargetNetwork::Udp,
            ),
            TargetNetwork::Udp,
        );
        writer.write_data(&mut out, &packet).expect("可写");
        let (meta, data) = drain_frame(&out);
        // 参考：分组会话首帧为 New + UDP 目标 + 8192 字节上限（超过即 fail-closed）。
        assert_eq!(meta.status, SessionStatus::New);
        assert_eq!(meta.target.map(|t| t.1), Some(TargetNetwork::Udp));
        assert!(matches!(
            data,
            Err(FrameError::PacketTooLarge { size: 8202 })
        ));
    }

    #[test]
    fn empty_payload_writes_metadata_only() {
        let mut out = Vec::new();
        SessionWriter::request(3, tcp("a.invalid", 1), TargetNetwork::Tcp)
            .write_multi(&mut out, &[])
            .expect("可写");
        let (meta, data) = drain_frame(&out);
        assert_eq!(meta.status, SessionStatus::New);
        assert!(!meta.has_data(), "参考 writeMetaOnly 不置 OptionData");
        assert!(data.is_err(), "无 OptionData 即无数据段");
    }

    #[test]
    fn concurrent_sessions_do_not_cross_packets() {
        let mut client = MuxClient::new();
        let mut out = Vec::new();
        // 三条并发会话（客户端侧使用服务端 ID 回包时也验证独立路由）。
        let mut wires = Vec::new();
        for (id, host) in [
            (1u16, "one.invalid"),
            (2, "two.invalid"),
            (3, "three.invalid"),
        ] {
            let mut writer = SessionWriter::request(id, tcp(host, 443), TargetNetwork::Tcp);
            writer
                .write_data(&mut out, format!("hello-{id}").as_bytes())
                .unwrap();
            wires.push((id, host));
        }
        for (id, _) in &wires {
            client.manager.add(
                *id,
                SessionState {
                    target: tcp("upstream.invalid", 1),
                },
            );
        }
        // 下行帧：每条会话一条 Keep（响应方向首帧即 Keep，无地址），
        // 既验证数据路由到自己的会话 ID，也验证 Keep 帧不携带地址。
        // 先清空上行 buffer，下面只看下行帧（否则会重读到上面的 New 帧）。
        out.clear();
        for (id, _host) in &wires {
            SessionWriter::response(*id, TargetNetwork::Tcp)
                .write_data(&mut out, format!("reply-{id}").as_bytes())
                .unwrap();
        }
        let mut reader = Cursor::new(&out);
        for (id, _host) in wires {
            let meta = FrameMetadata::decode_from(&mut reader, false).expect("帧头");
            let data = read_data(&mut reader, true).expect("数据");
            assert_eq!(meta.session_id, id);
            assert_eq!(meta.status, SessionStatus::Keep, "响应首帧为 Keep");
            assert_eq!(meta.target, None, "Keep 帧不带地址");
            let action = client.handle(&meta, Some(data)).expect("可处理");
            match action {
                Action::Deliver {
                    id: got, payload, ..
                } => {
                    assert_eq!(got, id);
                    assert_eq!(payload, format!("reply-{id}").as_bytes());
                }
                other => panic!("意外动作 {other:?}"),
            }
        }
        assert_eq!(client.manager.size(), 3, "三条会话互不干扰");

        // 客户端收到 New 帧（下行方向不承载新会话）时只丢弃数据。
        let new_meta = FrameMetadata {
            session_id: 42,
            status: SessionStatus::New,
            option: OPTION_DATA,
            target: Some(tcp("downlink.invalid", 1)),
            source: None,
            local: None,
            udp_continuation: false,
        };
        assert_eq!(
            client.handle(&new_meta, Some(vec![9, 9])).expect("可处理"),
            Action::None
        );
        assert_eq!(client.manager.size(), 3, "New 帧不建立会话");
    }

    #[test]
    fn end_of_one_session_leaves_others_untouched() {
        let mut server = MuxServer::new();
        for id in [1u16, 2, 3] {
            let meta = FrameMetadata {
                session_id: id,
                status: SessionStatus::New,
                option: OPTION_DATA,
                target: Some(tcp("upstream.invalid", 80)),
                source: None,
                local: None,
                udp_continuation: false,
            };
            assert_eq!(server.handle_new(&meta).expect("可登记"), id);
        }
        // 会话 2 结束。
        let end = FrameMetadata {
            session_id: 2,
            status: SessionStatus::End,
            option: 0,
            target: None,
            source: None,
            local: None,
            udp_continuation: false,
        };
        assert_eq!(
            server.handle(&end, None).expect("可处理"),
            Action::CloseSession { id: 2 }
        );
        server.manager.remove(2);
        assert_eq!(server.manager.size(), 2);
        assert!(server.manager.get(2).is_none());
        for id in [1u16, 3] {
            assert!(server.manager.get(id).is_some(), "会话 {id} 不受影响");
        }
        // 其余会话继续收发。
        let keep = FrameMetadata {
            session_id: 3,
            status: SessionStatus::Keep,
            option: OPTION_DATA,
            target: None,
            source: None,
            local: None,
            udp_continuation: false,
        };
        assert_eq!(
            server
                .handle(&keep, Some(b"still-alive".to_vec()))
                .expect("可处理"),
            Action::Deliver {
                id: 3,
                payload: b"still-alive".to_vec(),
                new: false
            }
        );
    }

    #[test]
    fn keep_alive_discards_data_and_never_opens_session() {
        let mut server = MuxServer::new();
        let keep_alive = FrameMetadata {
            session_id: 77,
            status: SessionStatus::KeepAlive,
            option: OPTION_DATA,
            target: None,
            source: None,
            local: None,
            udp_continuation: false,
        };
        assert_eq!(
            server
                .handle(&keep_alive, Some(vec![1, 2, 3]))
                .expect("可处理"),
            Action::None
        );
        assert_eq!(server.manager.size(), 0, "KeepAlive 不建立会话");

        let mut client = MuxClient::new();
        assert_eq!(
            client
                .handle(&keep_alive, Some(vec![1, 2, 3]))
                .expect("可处理"),
            Action::None
        );
    }

    #[test]
    fn keep_for_unknown_session_replies_end_and_drops_data() {
        for action in [
            MuxServer::new().handle(
                &FrameMetadata {
                    session_id: 5,
                    status: SessionStatus::Keep,
                    option: OPTION_DATA,
                    target: None,
                    source: None,
                    local: None,
                    udp_continuation: false,
                },
                Some(b"orphan".to_vec()),
            ),
            MuxClient::new().handle(
                &FrameMetadata {
                    session_id: 5,
                    status: SessionStatus::Keep,
                    option: OPTION_DATA,
                    target: None,
                    source: None,
                    local: None,
                    udp_continuation: false,
                },
                Some(b"orphan".to_vec()),
            ),
        ] {
            assert_eq!(action.expect("可处理"), Action::SendEnd { id: 5 });
        }
        // 通知帧即 `NewResponseWriter(id).Close()`：End，不带 OptionData。
        let mut out = Vec::new();
        write_closing_end(&mut out, 5, TargetNetwork::Tcp).expect("可写");
        let (meta, data) = drain_frame(&out);
        assert_eq!(meta.status, SessionStatus::End);
        assert_eq!(meta.session_id, 5);
        assert!(data.is_err(), "End 通知帧不带数据段");
    }

    #[test]
    fn server_rejects_unknown_network_and_unparsable_new_target() {
        let mut server = MuxServer::new();
        // 目标缺失的 New 帧 => 协议错误（参考必然解析出 Target）。
        let missing = FrameMetadata {
            session_id: 1,
            status: SessionStatus::New,
            option: 0,
            target: None,
            source: None,
            local: None,
            udp_continuation: false,
        };
        assert!(matches!(
            server.handle_new(&missing),
            Err(FrameError::ShortMeta { .. })
        ));
        // 地址解析失败 => 在解码阶段就被拒绝。
        let mut bad = vec![
            0x00,
            0x09,
            SessionStatus::New.to_byte(),
            0x00,
            TARGET_NETWORK_TCP,
        ];
        bad.extend_from_slice(&[0x01, 0xBB, 4]); // 未知地址类型 4
        assert!(matches!(
            FrameMetadata::decode_meta(&bad, false),
            Err(FrameError::Address)
        ));
    }

    #[test]
    fn session_manager_enforces_strategy_and_idle_close() {
        let strategy = Strategy {
            max_concurrency: 2,
            max_connection: 3,
        };
        let mut manager = SessionManager::new();
        let a = manager.allocate(&strategy).expect("第一次分配");
        assert_eq!(a, 1, "ID 从 1 起");
        assert!(manager.add(
            a,
            SessionState {
                target: tcp("a", 1)
            }
        ));
        let b = manager.allocate(&strategy).expect("第二次分配");
        assert!(manager.add(
            b,
            SessionState {
                target: tcp("b", 1)
            }
        ));
        assert_eq!(manager.size(), 2);
        assert_eq!(
            manager.allocate(&strategy),
            Err(AllocateError::ConcurrencyLimit)
        );
        // 释放一条后仍可分配（活跃数 vs 累计数不同口径）。
        manager.remove(a);
        let c = manager.allocate(&strategy).expect("释放后可分配");
        assert!(manager.add(
            c,
            SessionState {
                target: tcp("c", 1)
            }
        ));
        assert_eq!(manager.size(), 2);
        assert_eq!(manager.count(), 3);
        manager.remove(b);
        manager.remove(c);
        assert_eq!(
            manager.allocate(&strategy),
            Err(AllocateError::ConnectionLimit)
        );

        // `CloseIfNoSessionAndIdle`：`count` 未变且无活跃会话时才关闭。
        let mut idle = SessionManager::new();
        let id = idle.allocate(&Strategy::default()).expect("可分配");
        idle.add(
            id,
            SessionState {
                target: tcp("a", 1),
            },
        );
        assert!(!idle.close_if_no_session_and_idle(1, 1), "仍有活跃会话");
        idle.remove(id);
        assert!(
            !idle.close_if_no_session_and_idle(1, 1),
            "活跃数快照与当前不符（参考 checkSize 语义）"
        );
        assert!(!idle.close_if_no_session_and_idle(0, 99), "count 已变");
        assert!(idle.close_if_no_session_and_idle(0, 1));
        assert!(idle.closed());
        assert_eq!(
            idle.allocate(&Strategy::default()),
            Err(AllocateError::Closed)
        );
    }

    #[test]
    fn close_with_error_sets_option_error_and_address_codec_covers_all_families() {
        let mut writer = SessionWriter::response(4, TargetNetwork::Udp);
        writer.has_error = true;
        let mut out = Vec::new();
        writer.close(&mut out).expect("可写");
        let (meta, _) = drain_frame(&out);
        assert!(meta.has_error(), "hasError 时置 OptionError");

        for (addr, kind) in [
            (TargetAddr::V4([127, 0, 0, 1], 53), 1u8),
            (TargetAddr::Domain("test.invalid".into(), 53), 2),
            (
                TargetAddr::V6([0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 53),
                3,
            ),
        ] {
            let mut wire = Vec::new();
            crate::mux::frame::encode_address_port(&mut wire, &addr).expect("可编码");
            assert_eq!(wire[2], kind);
            assert_eq!(
                decode_address_port(&wire).expect("可解码"),
                (addr, wire.len())
            );
        }
        // 未知地址类型与截断均 fail-closed。
        assert!(decode_address_port(&[0, 1, 9, 0]).is_err());
        assert!(decode_address_port(&[0, 1]).is_err());
        assert!(decode_address_port(&[0, 1, 2, 0]).is_err(), "空域名");
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    use crate::mux::frame::TargetNetwork;
    use ss_core::target::TargetAddr;

    /// 固化 New+数据帧的线上布局（对照参考 `FrameMetadata.WriteTo` +
    /// `writeMetaWithFrame`：`metaLen | id | status | option | network | port | type |
    /// addr | dataLen | data`）。
    ///
    /// `metaLen` 在参考里取自「写完全部元数据段后的长度减去写完 2 字节长度前缀后的
    /// 长度」（`len1 - len0`，`len0` 在 `Extend(2)` **之后**取），故不含自身。
    #[test]
    fn new_data_frame_wire_layout_matches_reference() {
        let mut wire = Vec::new();
        let mut writer = SessionWriter::request(
            1,
            (TargetAddr::V4([127, 0, 0, 1], 0x4651), TargetNetwork::Tcp),
            TargetNetwork::Tcp,
        );
        writer.write_data(&mut wire, b"hello").expect("可写");
        assert_eq!(
            wire,
            vec![
                0x00, 0x0c, // metaLen = 12（不含自身）
                0x00, 0x01, // session id
                0x01, // New
                0x01, // OptionData
                0x01, // TargetNetworkTCP
                0x46, 0x51, // port 18001
                0x01, // IPv4
                0x7f, 0x00, 0x00, 0x01, // 127.0.0.1
                0x00, 0x05, // 数据长度
                b'h', b'e', b'l', b'l', b'o',
            ]
        );
    }
}
