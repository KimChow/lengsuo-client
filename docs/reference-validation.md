# 固定参考互通门禁

普通 `cargo test --workspace --locked` 会忽略需要参考二进制的用例，不能作为
真实参考互通已执行的依据。独立工作流 reference-interop 在 Linux/Windows
先执行环境/包解析本地用例，再运行 scripts/run_reference_tests.py，
保存参考命令、退出码、实际通过数量与日志。

清单位于 scripts/reference_manifest.json，固定 Xray v26.3.27、完整源 commit
和两个官方 ZIP 的 SHA256。运行器通过 HTTPS 下载并核对哈希，只提取指定
可执行成员，不解压任意路径；随后核对版本。`--archive` 可复用已下载官方包，
同样检查固定哈希。不存在证书验证关闭或未知包回退。

```sh
python scripts/run_reference_tests.py --work-dir /绝对仓库外路径
python scripts/run_reference_tests.py --work-dir /绝对仓库外路径 --archive /已下载官方包.zip
```

当前清单为 VLESS 七项、Trojan 四项、SS2022 两项、传统 SS 两项参考测试。每个 crate 显式
指定测试目标及 --ignored，任一退出码非零、超时或通过数量不等于清单即失败，
防止零用例被误报成功。新增参考用例需要同步更新清单并审阅覆盖范围。

当前只覆盖各状态文档已确认的范围，不代表八协议、全部外层传输或浏览器 TUN
完成。AnyTLS、VMess、Hysteria、WireGuard 等尚待加入真实参考矩阵。
普通门禁与参考门禁职责独立，许可证自动检查仍未实现。

构建目录在 work-dir/target，两个编译任务，禁用增量与调试信息；各 crate 依次
执行，禁止对同一个目录并发运行此脚本。工作流只保留 JSON 和测试日志三天，
不上传构建目录、参考 ZIP、可执行文件或测试证书；文档变更不触发参考矩阵。

本地脚本验证通过只证明运行器及本地测试；GitHub 托管工作流是否成功必须查看
对应 commit 的实际 run，不能以配置文件存在代替执行证据。

运行器验证记录：Linux 与 Windows 均复用已核验官方 ZIP，三个 crate 分别报告
7/4/2 项通过、全部退出码 0；错误 ZIP 哈希被拒绝且未执行任何参考测试。
这些记录对应未提交运行器的工作区，报告包含源码 HEAD 与 dirty 标记，
没有将本地结果冒充 GitHub 托管执行。托管结果应按最终提交另行核验。
