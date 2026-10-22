/// 端口跳跃 + 混淆的**socket 层取证**（不需要网络）。
///
/// 用假 socket 驱动 [`MaskedUdpSocket`]：① `try_send` 的**目的端口**必须
/// 随跳变；② 发出的字节必须带 8 字节盐前缀；③ 收侧必须能解混淆还原明文，
/// 口令不符的包**不得**还原成原文。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hop_rotates_destination_port_on_the_wire() {
    /// 记录 `try_send` 的目的地址与内容，并可注入待收报文。
    #[derive(Debug, Default)]
    struct FakeSocket {
        sent: Mutex<Vec<(SocketAddr, Vec<u8>)>>,
        inbox: Mutex<Vec<(SocketAddr, Vec<u8>)>>,
    }

    impl AsyncUdpSocket for FakeSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            unimplemented!("本用例只驱动 try_send/poll_recv")
        }

        fn try_send(&self, transmit: &Transmit<'_>) -> std::io::Result<()> {
            let mut sent = self.sent.lock().expect("锁");
            sent.push((transmit.destination, transmit.contents.to_vec()));
            Ok(())
        }

        fn poll_recv(
            &self,
            _cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<std::io::Result<usize>> {
            let mut inbox = self.inbox.lock().expect("锁");
            if inbox.is_empty() {
                return Poll::Pending;
            }
            let (addr, data) = inbox.remove(0);
            bufs[0][..data.len()].copy_from_slice(&data);
            meta[0] = RecvMeta {
                addr,
                len: data.len(),
                stride: data.len(),
                ..RecvMeta::default()
            };
            Poll::Ready(Ok(1))
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().expect("固定地址"))
        }
    }

    /// 造一条待发报文。
    fn tx(dest: SocketAddr, contents: &'static [u8]) -> Transmit<'static> {
        Transmit {
            destination: dest,
            contents,
            segment_size: None,
            ecn: None,
            src_ip: None,
        }
    }

    /// 从包装 socket 收一条报文，返回 (条数, 明文字节)。
    fn recv_one(socket: &MaskedUdpSocket) -> Option<(usize, Vec<u8>)> {
        let mut store = [0u8; 2048];
        let mut bufs = [IoSliceMut::new(&mut store)];
        let mut meta = [RecvMeta::default(); 1];
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let ready = socket.poll_recv(&mut cx, &mut bufs, &mut meta);
        let Poll::Ready(Ok(n)) = ready else {
            return None;
        };
        Some((n, bufs[0][..meta[0].len].to_vec()))
    }

    /// 用给定口令造一份密文（模拟对端）。
    fn peer_cipher(psk: &str, plain: &[u8]) -> Vec<u8> {
        let o = Obfuscator::new(psk.as_bytes().to_vec(), Arc::new(OsRng)).expect("口令合法");
        let mut out = vec![0u8; plain.len() + 8];
        let n = o.obfuscate(plain, &mut out).expect("缓冲足够");
        out.truncate(n);
        out
    }

    let base: SocketAddr = "127.0.0.1:4433".parse().expect("固定地址");
    let other: u16 = 8443;
    let spec = HopSpec::new(vec![base.port(), other], 5, 5).expect("跳端口规格");
    let psk = PSK.as_bytes().to_vec();
    let rng = Arc::new(OsRng);
    let mask = Arc::new(WireMask::new(base, Some(psk), Some(spec), rng).expect("掩码构造"));
    let fake = Arc::new(FakeSocket::default());
    // 目标类型已知 ⇒ `Arc<FakeSocket>` 到 `Arc<dyn AsyncUdpSocket>` 的
    // 无形化协变在这里生效（`Arc::clone(&fake)` 反而会按期望类型推断
    // `T = dyn AsyncUdpSocket` 而不匹配）。
    let inner: Arc<dyn AsyncUdpSocket> = fake.clone();
    let socket = MaskedUdpSocket::new(inner, mask.clone());

    // ① 跳之前：目的端口 = 配置端口。
    socket.try_send(&tx(base, b"hello-obfs")).expect("发送");
    let sent = fake.sent.lock().expect("锁").clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, base, "跳之前目的端口必须是配置端口");
    assert_eq!(sent[0].1.len(), b"hello-obfs".len() + 8, "8 字节盐 + 明文");
    assert_ne!(&sent[0].1[..8], &b"hello-obf"[..], "盐前缀不得是明文");

    // ② 跳之后：目的端口必须换成端口集合里的另一个。
    let hopped = mask.next_hop().expect("应能跳一次");
    assert_eq!(mask.current_remote(), hopped, "当前目标应随跳更新");
    let ports = [base.port(), other];
    assert!(ports.contains(&hopped.port()), "端口必须来自端口集合");
    socket.try_send(&tx(base, b"after-hop")).expect("发送");
    let sent = fake.sent.lock().expect("锁").clone();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1].0.port(), hopped.port(), "跳后必须发往新的目的端口");

    // ③ 收侧：解混淆还原明文。
    let plain = b"payload-from-peer";
    let cipher = peer_cipher(PSK, plain);
    fake.inbox.lock().expect("锁").push((base, cipher));
    let (n, got) = recv_one(&socket).expect("应收到一条");
    assert_eq!(n, 1, "一条合法密文应解出");
    assert_eq!(got, plain, "解混淆应还原明文");

    // 错误口令的密文 ⇒ **不得**还原成原文。注意：Salamander **没有 MAC**
    // （参考 `salamander.go` 的 `Obfuscate`/`Deobfuscate` 只做 XOR，无校验），
    // 因此结构上无法判定「口令不符」；可判定的是「解出来的字节必然不是
    // 原文」。参考也是同样语义（`hub.go` 侧收到乱码后由 QUIC 层丢弃）。
    let wrong = peer_cipher(WRONG_PSK, plain);
    fake.inbox.lock().expect("锁").push((base, wrong));
    if let Some((n, got)) = recv_one(&socket) {
        assert_eq!(n, 1, "长度足够的密文在结构上仍会被解混淆（无 MAC）");
        assert_ne!(got, plain, "口令不符的密文不得被还原成原文");
    }

    // ④ 归一：同 IP 的回包地址归一到规范地址（quinn 客户端禁止迁移）。
    let same_ip = SocketAddr::from(([127, 0, 0, 1], other));
    let other_ip = SocketAddr::from(([10, 0, 0, 1], other));
    assert_eq!(mask.normalize_peer(same_ip), Some(base), "同 IP 应归一");
    assert_eq!(mask.normalize_peer(other_ip), None, "不同 IP 必须拒绝");
}
