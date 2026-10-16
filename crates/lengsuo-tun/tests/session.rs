//! 五元组会话表测试：插入、命中、过期回收、容量满拒绝、TTL 刷新与 IPv6 键。
//! 全部纯内存，不触网、不建设备；每个用例都在 timeout 与 blocking 线程的双重约束下
//! 运行，断言只针对表语义本身，不代表任何设备或协议栈行为。

use lengsuo_tun::packet::Transport;
use lengsuo_tun::session::{Clock, OpenError, SessionKey, SessionTable};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::task::spawn_blocking;
use tokio::time::timeout;

/// 纯内存用例的兜底超时：本模块不碰网络与设备，正常应在毫秒级完成。
const WAIT: Duration = Duration::from_secs(5);

/// 在 blocking 线程里跑同步用例，外层套 timeout；线程 panic 会作为 Err 上抛。
async fn bounded<T, F>(name: &'static str, work: F)
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    timeout(WAIT, spawn_blocking(work))
        .await
        .unwrap_or_else(|_| panic!("{name} 超出 {WAIT:?}"))
        .unwrap_or_else(|error| panic!("{name} 线程失败：{error}"));
}

fn v4(host: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, host))
}

fn v6(host: u16) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, host))
}

fn tcp_v4(source_port: u16, destination_port: u16) -> SessionKey {
    SessionKey::new(Transport::Tcp, v4(1), source_port, v4(7), destination_port)
}

fn udp_v6(source_port: u16, destination_port: u16) -> SessionKey {
    SessionKey::new(Transport::Udp, v6(1), source_port, v6(2), destination_port)
}

/// 混合地址族键：IPv4 源到 IPv6 目的，只作哈希与比较，不应被拒绝或 panic。
fn mixed_key() -> SessionKey {
    SessionKey::new(Transport::Tcp, v4(1), 5000, v6(2), 443)
}

#[tokio::test]
async fn insert_hit_and_close() {
    bounded("insert_hit_and_close", || {
        let mut table = SessionTable::new(4, 1_000);
        let key = tcp_v4(5000, 443);
        assert!(table.is_empty());
        assert_eq!(table.capacity(), 4);
        assert_eq!(table.remaining(), 4);
        {
            let value = table.open(key, "新会话".to_string(), 0).expect("插入成功");
            assert_eq!(value, "新会话");
        }
        assert_eq!(table.len(), 1);
        assert_eq!(table.remaining(), 3);
        assert!(table.contains(key));
        assert_eq!(table.peek(key, 100).map(String::as_str), Some("新会话"));
        assert_eq!(table.get(key, 999).map(|v| v.as_str()), Some("新会话"));
        // close 取回值并释放额度；再次 close 与 get 都是空操作。
        assert_eq!(table.close(key).as_deref(), Some("新会话"));
        assert_eq!(table.len(), 0);
        assert!(table.close(key).is_none());
        assert!(table.get(key, 1000).is_none());
        assert!(table.peek(key, 0).is_none());
    })
    .await;
}

/// open 与 get 返回可变借用，值可就地累积并在下次查询可见。
#[tokio::test]
async fn value_can_be_mutated_in_place() {
    bounded("value_mutation", || {
        let mut table = SessionTable::new(2, 1_000);
        let key = udp_v6(1000, 2000);
        table.open(key, Vec::new(), 0).expect("插入").push(1u8);
        assert_eq!(table.get(key, 1).map(|v| v.as_slice()), Some(&[1u8][..]));
        table.open(key, vec![2u8], 2).expect("覆盖").push(3u8);
        assert_eq!(table.peek(key, 3).map(Vec::as_slice), Some(&[2u8, 3u8][..]));
        assert_eq!(table.close(key), Some(vec![2u8, 3u8]));
    })
    .await;
}

#[tokio::test]
async fn hit_and_duplicate_open_refresh_ttl() {
    bounded("hit_and_duplicate_open_refresh_ttl", || {
        let mut table = SessionTable::new(2, 100);
        let key = tcp_v4(5000, 443);
        table.open(key, 1u32, 0).expect("插入");
        // 每次命中都把过期点推后：t=90 命中 -> 190 过期。
        assert_eq!(table.get(key, 90).copied(), Some(1));
        assert_eq!(table.ttl(), 100);
        // 边界：恰好 `expires_at <= now` 判过期。
        assert!(table.peek(key, 189).is_some());
        assert!(table.peek(key, 190).is_none());
        // 过期后的 get 按未命中处理，并就地回收该键。
        assert_eq!(table.get(key, 250).copied(), None);
        assert_eq!(table.len(), 0, "被访问的过期键应就地回收");
        assert!(!table.contains(key));

        // 重复 open 覆盖值并刷新 TTL，条目数不增加。
        table.open(key, 10u32, 300).expect("插入");
        table.open(key, 20u32, 350).expect("重复 open");
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(key, 400).copied(), Some(20));
        // 上面那次命中把过期点推到 500。
        assert!(table.peek(key, 499).is_some());
        assert!(table.peek(key, 500).is_none());
    })
    .await;
}

#[tokio::test]
async fn gc_reclaims_only_expired() {
    bounded("gc_reclaims_only_expired", || {
        let mut table = SessionTable::new(8, 100);
        let first = tcp_v4(1, 2);
        let second = tcp_v4(3, 4);
        let third = udp_v6(5, 6);
        table.open(first, "a".to_string(), 0).expect("插入");
        table.open(second, "b".to_string(), 50).expect("插入");
        table.open(third, "c".to_string(), 100).expect("插入");
        // 过期点依次为 100 / 150 / 200：t=120 只回收 first。
        assert_eq!(table.gc(120), vec!["a".to_string()]);
        assert_eq!(table.len(), 2, "未过期条目不得被回收");
        assert!(table.contains(second) && table.contains(third));
        assert_eq!(table.gc(180), vec!["b".to_string()]);
        assert_eq!(table.gc(200), vec!["c".to_string()]);
        assert!(table.is_empty());
        assert_eq!(table.remaining(), 8);
        // 空表上重复 gc 无害。
        assert!(table.gc(Clock::MAX).is_empty());
        assert!(table.gc(0).is_empty());
    })
    .await;
}

#[tokio::test]
async fn capacity_full_rejects_new_session_without_eviction() {
    bounded("capacity_full_rejects", || {
        let mut table = SessionTable::new(2, 1_000);
        let kept = [tcp_v4(5000, 443), udp_v6(6000, 53)];
        for (index, key) in kept.iter().enumerate() {
            table.open(*key, index, 0).expect("前两次插入");
        }
        assert_eq!(table.len(), 2);
        assert_eq!(table.remaining(), 0);

        let extra = tcp_v4(9000, 9999);
        let error = table.open(extra, 99, 10).expect_err("容量满必须拒绝新会话");
        assert!(matches!(error, OpenError::Capacity { capacity: 2, .. }));
        assert_eq!(error.capacity(), 2);
        assert_eq!(error.into_value(), 99, "被拒绝的值要原样交还");
        assert_eq!(table.len(), 2, "拒绝不得改变条目数");
        // 既不驱逐任何既有条目，也不改动它们的值。
        assert_eq!(table.get(kept[0], 20).copied(), Some(0));
        assert_eq!(table.get(kept[1], 20).copied(), Some(1));
        // 已满时仍可覆盖已有键（那不是新会话）。覆盖用 peek 断言（peek 不刷新
        // TTL，避免干扰后面的 gc 时序）。
        assert!(table.open(kept[0], 7, 30).is_ok());
        assert_eq!(table.len(), 2);
        assert_eq!(table.peek(kept[1], 30).copied(), Some(1));

        // 过期回收后额度要能腾出来：kept[1] 最后一次触达在 20，1020 过期；
        // kept[0] 被覆盖于 30，1030 过期——gc(1020) 只回收 kept[1]。
        assert_eq!(table.gc(1_020).len(), 1);
        assert_eq!(table.remaining(), 1);
        assert!(table.open(extra, 8, 1_020).is_ok());
        assert_eq!(table.len(), 2);
    })
    .await;
}

#[tokio::test]
async fn zero_capacity_table_always_rejects() {
    bounded("zero_capacity_table", || {
        let mut table: SessionTable<u32> = SessionTable::new(0, 100);
        let key = tcp_v4(1, 1);
        let error = table.open(key, 1, 0).expect_err("容量 0 拒绝一切新会话");
        assert_eq!(error.capacity(), 0);
        assert_eq!(error.into_value(), 1);
        assert!(table.is_empty());
        assert_eq!(table.remaining(), 0);
        assert!(table.get(key, 0).is_none());
        assert_eq!(table.capacity(), 0);
    })
    .await;
}

#[tokio::test]
async fn keys_cover_both_address_families() {
    bounded("keys_cover_both_families", || {
        let mut table = SessionTable::new(8, 100);
        let keys = [
            tcp_v4(1, 2),
            udp_v6(3, 4),
            mixed_key(),
            SessionKey::new(Transport::Udp, v6(1), 3, v4(7), 4),
        ];
        for (index, key) in keys.iter().enumerate() {
            assert!(table.open(*key, index, 0).is_ok(), "IPv6/混合键要能插入");
        }
        assert_eq!(table.len(), 4);
        // 协议与地址族差异都必须区分键，IPv6 与 IPv4 的同端口号不得混用。
        assert_eq!(table.get(keys[1], 10).copied(), Some(1));
        assert!(table.get(tcp_v4(3, 4), 10).is_none());
        assert!(table.get(udp_v6(1, 2), 10).is_none());
        assert_eq!(table.peek(keys[2], 10).copied(), Some(2));

        // 反向键是另一个键；插入后共 5 项，仍不触发驱逐。
        let back = keys[0].reversed();
        assert_ne!(back, keys[0]);
        assert!(table.get(back, 10).is_none());
        assert!(table.open(back, 100, 10).is_ok());
        assert_eq!(table.get(back, 20).copied(), Some(100));
        assert_eq!(table.get(keys[0], 20).copied(), Some(0));
        assert_eq!(table.len(), 5);
        assert_eq!(back.reversed(), keys[0]);

        // 键字段可读回，便于上层做日志与策略。
        assert_eq!(keys[0].protocol(), Transport::Tcp);
        assert_eq!(keys[0].source(), v4(1));
        assert_eq!(keys[0].source_port(), 1);
        assert_eq!(keys[0].destination(), v4(7));
        assert_eq!(keys[0].destination_port(), 2);
        assert_eq!(mixed_key().destination(), v6(2));
    })
    .await;
}

#[tokio::test]
async fn ttl_expiry_boundary_and_saturated_clock() {
    bounded("ttl_boundary_and_clock", || {
        let mut table = SessionTable::new(1, 50);
        let key = tcp_v4(7, 8);
        table.open(key, "v".to_string(), 10).expect("插入");
        assert!(table.peek(key, 59).is_some());
        // 过期判定为 `expires_at <= now`，即 60 这一刻度已经过期。
        assert!(table.peek(key, 60).is_none());
        assert_eq!(table.gc(60), vec!["v".to_string()]);

        // 时钟接近上界时饱和而不回绕：回绕会让条目立刻被判过期并被误回收。
        let mut table = SessionTable::new(1, 100);
        let key = udp_v6(9, 9);
        table
            .open(key, "x".to_string(), Clock::MAX - 50)
            .expect("插入");
        assert!(table.peek(key, Clock::MAX - 1).is_some());
        assert!(table.gc(Clock::MAX - 1).is_empty());
        assert_eq!(table.len(), 1);
        assert_eq!(table.close(key).as_deref(), Some("x"));
        // 零 TTL：插入即过期，容量仍被占用直到被回收。
        let mut table = SessionTable::new(1, 0);
        assert!(table.open(key, "z".to_string(), 5).is_ok());
        assert!(table.peek(key, 5).is_none());
        assert_eq!(table.len(), 1);
        assert!(
            table.open(mixed_key(), "y".to_string(), 5).is_err(),
            "过期条目仍占额度"
        );
        assert_eq!(table.gc(5).len(), 1);
        assert!(table.open(mixed_key(), "y".to_string(), 5).is_ok());
    })
    .await;
}

/// 表操作路径不 panic 的对抗性入参：地址族、端口、容量、TTL 与时钟边界组合。
#[tokio::test]
async fn never_panics_on_adversarial_operations() {
    bounded("never_panics", || {
        let families = [v4(1), v4(254), v6(0), v6(u16::MAX)];
        for capacity in [0usize, 1, 3] {
            for ttl in [0u64, 1, 60_000, Clock::MAX] {
                let mut table = SessionTable::new(capacity, ttl);
                for (index, protocol) in [Transport::Tcp, Transport::Udp].iter().enumerate() {
                    for (family_index, source) in families.iter().enumerate() {
                        for destination in families.iter().rev() {
                            let key = SessionKey::new(
                                *protocol,
                                *source,
                                index as u16 + family_index as u16,
                                *destination,
                                u16::MAX,
                            );
                            let _ = table.open(key, index, 0);
                            let _ = table.get(key, 1);
                            let _ = table.peek(key, 1);
                            let _ = table.contains(key);
                            assert!(table.len() <= table.capacity(), "占用不得超过容量");
                        }
                    }
                }
                let _ = table.gc(Clock::MAX);
                let _ = table.gc(0);
                assert!(table.len() <= capacity);
                assert_eq!(table.remaining(), capacity - table.len());
            }
        }
    })
    .await;
}

/// 拒绝语义的错误信息可读且实现了 std::error::Error。
#[tokio::test]
async fn rejection_error_is_describable() {
    bounded("rejection_error_text", || {
        let mut table = SessionTable::new(1, 10);
        table.open(tcp_v4(1, 1), 0u8, 0).expect("插入");
        let error = table
            .open(tcp_v4(2, 2), 1u8, 0)
            .expect_err("第二会话被拒绝");
        let text = error.to_string();
        assert!(text.contains("拒绝"), "错误信息要说明拒绝：{text}");
        assert!(text.contains('1'), "要带出容量：{text}");
        let reference: &dyn std::error::Error = &error;
        assert!(!reference.to_string().is_empty());
        assert!(!format!("{error:?}").is_empty());
        assert_eq!(error.into_value(), 1);
    })
    .await;
}
