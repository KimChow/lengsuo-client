use lengsuo_ss2022::{
    crypto::{Key, Method},
    packet::Sender,
    receiver::{Clock, Receiver},
    Error,
};
use ss_core::target::TargetAddr;
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
fn key() -> Key {
    Key::new(Method::Aes128, &[17; 16]).unwrap()
}
fn clock(base: Instant, seconds: u64) -> Clock {
    Clock {
        unix_seconds: 1000 + seconds,
        monotonic: base + Duration::from_secs(seconds),
    }
}
fn peer(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}
fn seal(sender: &mut Sender, time: u64) -> Vec<u8> {
    sender
        .seal(&TargetAddr::V4([1; 4], 80), b"test", time, 0)
        .unwrap()
}
fn receiver(cap: usize) -> Receiver {
    Receiver::new(key(), None, cap, Duration::from_secs(60)).unwrap()
}
#[test]
fn reordered_packets_and_replay_cannot_redirect_peer() {
    let base = Instant::now();
    let mut rx = receiver(1);
    let mut tx = Sender::new(key(), None).unwrap();
    let packets: Vec<_> = (0..3).map(|_| seal(&mut tx, 1000)).collect();
    for i in [2, 0, 1] {
        rx.receive(&packets[i], peer(1), clock(base, 0)).unwrap();
    }
    assert!(matches!(
        rx.receive(&packets[2], peer(2), clock(base, 1)),
        Err(Error::Replay)
    ));
    assert_eq!(rx.last_peer(tx.session_id()), Some(peer(1)));
    rx.receive(&seal(&mut tx, 1001), peer(2), clock(base, 1))
        .unwrap();
    assert_eq!(rx.last_peer(tx.session_id()), Some(peer(2)));
}
#[test]
fn authentication_and_capacity_failures_leave_state_intact() {
    let base = Instant::now();
    let mut rx = receiver(1);
    let mut tx = Sender::new(key(), None).unwrap();
    let packet = seal(&mut tx, 1000);
    let mut bad = packet.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(rx.receive(&bad, peer(2), clock(base, 0)).is_err());
    rx.receive(&packet, peer(1), clock(base, 0)).unwrap();
    let mut other = Sender::new(key(), None).unwrap();
    assert!(matches!(
        rx.receive(&seal(&mut other, 1000), peer(2), clock(base, 0)),
        Err(Error::SessionCapacity)
    ));
    rx.receive(&seal(&mut tx, 1000), peer(1), clock(base, 0))
        .unwrap();
    assert_eq!(rx.last_peer(other.session_id()), None);
}
#[test]
fn future_timestamp_boundary_cannot_reopen_window_at_sixty_seconds() {
    let base = Instant::now();
    let mut rx = receiver(1);
    let mut tx = Sender::new(key(), None).unwrap();
    let packet = seal(&mut tx, 1030);
    rx.receive(&packet, peer(1), clock(base, 0)).unwrap();
    rx.gc(clock(base, 60)).unwrap();
    assert!(matches!(
        rx.receive(&packet, peer(2), clock(base, 60)),
        Err(Error::Replay)
    ));
    rx.gc(clock(base, 61)).unwrap();
    assert_eq!(rx.last_peer(tx.session_id()), None);
    assert!(matches!(
        rx.receive(&packet, peer(2), clock(base, 61)),
        Err(Error::Timestamp)
    ));
}
#[test]
fn rollback_and_frozen_wall_clock_fail_closed() {
    let base = Instant::now();
    let mut rx = receiver(1);
    let mut tx = Sender::new(key(), None).unwrap();
    let packet = seal(&mut tx, 1000);
    rx.receive(&packet, peer(1), clock(base, 0)).unwrap();
    rx.gc(Clock {
        unix_seconds: 1000,
        monotonic: base + Duration::from_secs(120),
    })
    .unwrap();
    assert_eq!(rx.last_peer(tx.session_id()), Some(peer(1)));
    assert!(matches!(rx.gc(clock(base, 1)), Err(Error::ClockRollback)));
    assert!(matches!(
        rx.receive(
            &packet,
            peer(2),
            Clock {
                unix_seconds: 999,
                monotonic: base + Duration::from_secs(121)
            }
        ),
        Err(Error::ClockRollback)
    ));
}
#[test]
fn responses_bind_client_and_allow_two_independent_server_sessions() {
    let base = Instant::now();
    let client = [5; 8];
    let mut rx = Receiver::new(key(), Some(client), 2, Duration::from_secs(60)).unwrap();
    let mut wrong = Sender::new(key(), Some([6; 8])).unwrap();
    assert!(matches!(
        rx.receive(&seal(&mut wrong, 1000), peer(3), clock(base, 0)),
        Err(Error::ClientSession)
    ));
    let mut a = Sender::new(key(), Some(client)).unwrap();
    let mut b = Sender::new(key(), Some(client)).unwrap();
    rx.receive(&seal(&mut a, 1000), peer(1), clock(base, 0))
        .unwrap();
    rx.receive(&seal(&mut b, 1000), peer(2), clock(base, 0))
        .unwrap();
    assert_eq!(rx.last_peer(a.session_id()), Some(peer(1)));
    assert_eq!(rx.last_peer(b.session_id()), Some(peer(2)));
}
