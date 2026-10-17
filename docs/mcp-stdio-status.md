# MCP stdio真实夹具验收（2026-10-17）

原有18项只是协议serde测试，不能证明stdio、并发和超时；本次新增9项真实Python子进程测试。
覆盖行分隔/Content-Length握手、list/call/ping/shutdown、10个乱序并发响应关联、
超时后poison并拒绝复用、坏帧/截断EOF/意外退出、通知、超大帧、显式shutdown回收子进程。
每次网络/进程等待有外层timeout；生命周期用测试PID文件及/proc核验，不终止用户进程。
新增fixture钩子只用于测试；测试不用真实凭据，不连接第三方server。

实跑：cargo test -p agent-mcp --locked --offline：28 passed/0 failed/0 ignored，
含18协议单测、1启动配置Debug脱敏、9stdio验收；all-targets clippy -D warnings/fmt通过。
Linux python3/proc验证不代表Windows进程生命周期已验收；HTTP/SSE/resources/prompts仍不在v0范围。
证据：研究机mcp-stdio-tests.log、mcp-stdio-clippy.log；不提交日志。
