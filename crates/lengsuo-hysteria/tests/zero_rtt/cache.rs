// ④ `SessionCache` 的容量 / LRU / 未命中语义。
// ---- ④ SessionCache 容量 / LRU / 未命中 ----

#[test]
fn session_cache_capacity_lru_and_miss() {
    let name = |s: &str| quinn::rustls::pki_types::ServerName::try_from(s.to_owned()).unwrap();
    use quinn::rustls::NamedGroup;

    let cache = MemorySessionCache::new(2);
    let a = name("a.example");
    let b = name("b.example");
    let c = name("c.example");
    cache.set_kx_hint(a.clone(), NamedGroup::X25519);
    cache.set_kx_hint(b.clone(), NamedGroup::secp256r1);
    assert_eq!(cache.server_count(), 2);
    assert_eq!(cache.kx_hint(&a), Some(NamedGroup::X25519)); // 访问 a，使其变为最近使用

    cache.set_kx_hint(c.clone(), NamedGroup::secp384r1); // 容量满，驱逐最久未用的 b
    assert_eq!(cache.server_count(), 2);
    assert_eq!(cache.kx_hint(&b), None, "b 应被 LRU 驱逐");
    assert_eq!(cache.kx_hint(&a), Some(NamedGroup::X25519));
    assert_eq!(cache.kx_hint(&c), Some(NamedGroup::secp384r1));

    let missing = name("missing.example");
    assert_eq!(cache.kx_hint(&missing), None, "未命中返回 None");
    assert_eq!(cache.server_count(), 2, "未命中不得插入条目/驱逐他人");
    assert_eq!(cache.ticket_count(&missing), 0);
    assert_eq!(cache.ticket_count(&a), 0, "未插入票据时计数为 0");
    assert!(
        cache.take_tls13_ticket(&a).is_none(),
        "无票据时 take 返回 None"
    );

    cache.clear();
    assert_eq!(cache.server_count(), 0);

    let zero = MemorySessionCache::new(0);
    zero.set_kx_hint(a.clone(), NamedGroup::X25519);
    assert_eq!(zero.server_count(), 0, "容量 0 不存储任何条目");
    assert_eq!(cache.kx_hint(&a), None);
}
