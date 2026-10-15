# AnyTLS 服务端会话状态检查

基线为 anytls-go 完整 commit `fd6167acd6d73b9fa3e607659951847fbc9e6c50`，
依据 docs/protocol.md 和 proxy/session/session.go 自主实现。

ServerState 针对一条已认证连接检查入站方向、Settings 先行及一次性、
Stream ID 非零且严格递增、活跃流容量、数据与关闭的流归属、v2 心跳。
首个非法帧使状态失效，后续全部拒绝；Waste 不改状态，数据事件不复制载荷。
Settings 的 UTF-8、重复键、版本、client 和 padding-md5 格式均检查；
本实现设置 4096 字节上限，未知字段允许，不把该上限说成参考实现限制。

Claude Code 到轮次上限后由集成负责人复核。初始任务误要求心跳 id 为零，
与参考实现原样回传 sid 的行为不符。新增 sid=37 的回归测试先复现失败，
再修正为保留关联值；这不是用户身份或应用流路由依据。
测试按 Settings 与流状态分文件，避免超过 400 行软目标。

十五项状态测试覆盖非法设置、先后顺序、容量、单调编号、流关闭与混用、
方向、心跳、失效状态及载荷不复制。仅证明纯内存状态机，不代表 AnyTLS
网络服务、SYNACK 发送、心跳调度、padding 更新、连接复用池或 UDP 完成。
这些功能、双向参考互通及 Windows 浏览器网络仍在完整交付范围内。

Windows 原生验证：固定提交 `9180e0d59f952011e1e4419ea37c14a969bac7bf`，
Rust 1.93.0 / MSVC，`cargo test -p lengsuo-anytls --locked` 退出码 0，
五项原语与十五项状态测试通过。没有执行 AnyTLS 参考网络互通。
