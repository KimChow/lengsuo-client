use lengsuo_environment::{
    runtime::{Error, Runtime},
    DeviceId, EnvironmentId,
};
use std::time::Duration;
use tokio::{
    io::{duplex, AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
const WAIT: Duration = Duration::from_secs(2);

#[tokio::test]
async fn offline_cancels_only_affected_relay() {
    timeout(WAIT, async {
        let mut runtime = Runtime::new(4).unwrap();
        runtime.set_online(DeviceId(1), true);
        runtime.set_online(DeviceId(2), true);
        let a = runtime.bind(EnvironmentId(1), DeviceId(1)).unwrap();
        let b = runtime.bind(EnvironmentId(2), DeviceId(2)).unwrap();
        let flow_a = runtime.register(a).unwrap();
        let flow_b = runtime.register(b).unwrap();
        let (mut ca, ia) = duplex(64);
        let (ea, mut ta) = duplex(64);
        let (mut cb, ib) = duplex(64);
        let (eb, mut tb) = duplex(64);
        let worker_a = tokio::spawn(flow_a.relay(ia, ea, WAIT));
        let worker_b = tokio::spawn(flow_b.relay(ib, eb, WAIT));
        ca.write_all(b"a").await.unwrap();
        assert_eq!(ta.read_u8().await.unwrap(), b'a');
        runtime.set_online(DeviceId(1), false);
        assert!(matches!(worker_a.await.unwrap(), Err(Error::Revoked)));
        assert!(runtime.register(a).is_err());
        cb.write_all(b"b").await.unwrap();
        assert_eq!(tb.read_u8().await.unwrap(), b'b');
        ta.shutdown().await.unwrap();
        cb.shutdown().await.unwrap();
        tb.shutdown().await.unwrap();
        assert!(worker_b.await.unwrap().is_ok());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn switching_remove_and_runtime_drop_revoke_guards() {
    timeout(WAIT, async {
        let mut runtime = Runtime::new(4).unwrap();
        runtime.set_online(DeviceId(1), true);
        runtime.set_online(DeviceId(2), true);
        let old = runtime.bind(EnvironmentId(1), DeviceId(1)).unwrap();
        let mut flow = runtime.register(old).unwrap();
        assert!(!flow.is_revoked());
        let current = runtime.bind(EnvironmentId(1), DeviceId(2)).unwrap();
        flow.revoked().await;
        assert!(flow.is_revoked());
        assert!(runtime.register(old).is_err());
        let mut second = runtime.register(current).unwrap();
        runtime.remove(EnvironmentId(1));
        second.revoked().await;
        let current = runtime.bind(EnvironmentId(1), DeviceId(2)).unwrap();
        let mut final_flow = runtime.register(current).unwrap();
        drop(runtime);
        final_flow.revoked().await;
        assert!(final_flow.is_revoked());
    })
    .await
    .unwrap();
}

#[test]
fn capacity_is_bounded_and_finished_guards_are_reclaimed() {
    assert!(Runtime::new(0).is_err());
    let mut runtime = Runtime::new(1).unwrap();
    runtime.set_online(DeviceId(1), true);
    let lease = runtime.bind(EnvironmentId(1), DeviceId(1)).unwrap();
    let flow = runtime.register(lease).unwrap();
    assert!(matches!(runtime.register(lease), Err(Error::Capacity)));
    assert_eq!(flow.lease(), lease);
    drop(flow);
    assert!(runtime.register(lease).is_ok());
}

#[tokio::test]
async fn relay_half_close_and_lifetime_limit() {
    timeout(WAIT, async {
        let mut runtime = Runtime::new(1).unwrap();
        runtime.set_online(DeviceId(1), true);
        let lease = runtime.bind(EnvironmentId(1), DeviceId(1)).unwrap();
        let flow = runtime.register(lease).unwrap();
        let (mut client, ingress) = duplex(64);
        let (egress, mut target) = duplex(64);
        let worker = tokio::spawn(flow.relay(ingress, egress, WAIT));
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut request = Vec::new();
        target.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        target.write_all(b"reply").await.unwrap();
        target.shutdown().await.unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"reply");
        assert_eq!(worker.await.unwrap().unwrap(), (7, 5));
        let flow = runtime.register(lease).unwrap();
        let (_client, ingress) = duplex(64);
        let (egress, _target) = duplex(64);
        assert!(matches!(
            flow.relay(ingress, egress, Duration::from_millis(20)).await,
            Err(Error::Timeout)
        ));
    })
    .await
    .unwrap();
}
