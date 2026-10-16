# credential-ref 三项 file_store 测试失败：根因核查结论

工作目录：`wt-cred-ref`（分支 `agent/c-cred-ref`，基线 WIP 提交 a18aa44）。
基线复现命令：`cargo test -p credential-ref --locked --test file_store`
→ `15 passed; 3 failed`（失败项：`tampered_header_byte_breaks_record_binding`、
`each_write_rotates_salt_so_identical_values_differ_on_disk`、
`concurrent_reads_writes_and_deletes_do_not_panic`）。

**总结论：三项都不是「实现缺了密码学绑定/盐轮换/并发保护」，而是测试断言与库已声明的
语义冲突。**其中两项若按「只改 src、不动断言」执行，必须改变库的公开语义或制造自相矛盾
的断言，因此本文件记录核查证据并停在需用户拍板的分岔口，未提交任何改动。
工作树回到**交接时的原状**（`src/file.rs` 的 WIP 未提交补丁保留、`tests/file_store.rs` 仅含
交接时已存在的 3 行 `#![allow(dead_code)]` 头部、未提交探针 `write_race.rs` / `zz_stress.rs` 保留），
新增本文件记录证据与待决策分岔。

## 1. concurrent_reads_writes_and_deletes_do_not_panic —— 断言恒不成立（测试侧）

症状：`total == 0`，期望 54（file_store.rs:517）。

根因：统计口径与作用域匹配规则不一致。

- 记录 target 为 `env-{index}-{round}`（如 `env-0-3`）；
- 断言用 `store.list(&Scope::Env(format!("env-{index}")))`（如 `env-0`）累加；
- `Scope::same_scope` 是**类别 + target 字面量全等**（reference.rs:107-109），
  前缀不匹配，故累加值恒为 0——与实现是否正确无关，改任何 src 代码都不可能让它到 54。

库的既定语义与此一致，且已有通过的测试双向固定：

- lib.rs:13「`list` 只返回同作用域且未过期的引用」；
- `memory_store.rs:115-158`（通过）断言同 target 多条可**同时列出**（`len() == 2`），
  并断言 target 不同（`Scope::Env("nope")`）**必须为空**。

即「聚合查询不到」是设计行为。该用例名为 `..._do_not_panic`，真实意图是并发下
内存/磁盘视图不失真，应用完整 target 逐条核对——同目录未提交的 `write_race.rs` 正是
这一精确口径的回归（2 项通过）。

关于并发实现本身（代码审阅结论，附实测说明）：基线 `flush()` 在临时取锁快照后
**放开锁**再编码 + rename，rename 不在状态锁内，属真实丢失更新窗口。但本轮**未能实测复现**：
在基线 `flush()` 快照后插入 30ms 睡宽化窗口，`write_race`（2 项）与
`zz_stress`（4 轮 × 12 线程 × 30 轮，窗口内约有量级可观的并发插入）全部通过，
磁盘数 == 内存数（360/360 ×4）。原因是每次 `put`/`delete` 都按「当前完整内存视图」整库重写，
而内存视图单调增长，后续任一落盘都会修复早先被旧快照覆盖的记录，只有当**最后一次** rename
携带过期快照时才留下损失。WIP 补丁把「改视图 → 快照 → 编码 → rename」收拢到同一临界区
（`flush_locked(&state)`），关闭该窗口，属正确加固；但它不是这三项失败的原因。

## 2. each_write_rotates_salt_so_identical_values_differ_on_disk —— 盐轮换已生效（测试侧）

症状：断言在 file_store.rs:449 失败（`list(...).len()` 实得 3，期望 1），
而**同一用例内** 444/445 的 `assert_ne!(snapshots[0], snapshots[1])`、
`assert_ne!(snapshots[1], snapshots[2])` 均通过。

根因：轮换 salt 的功能已经工作（三轮头部 salt 互不相同，且明文不出现在文件中），
失败点在用例最后对「同作用域记录数」的期望。每轮都新建
`CredentialRef::env(TARGET, u64::MAX)`，id 为随机 UUID，故三轮是三条**不同 id** 的记录，
同 target 下合法共存为 3 条——正是 `memory_store.rs:128` 断言的行为。
「KDF salt 被复用为固定值」这一猜测与证据相反。

要让 `len() == 1` 成立，只有两条路：(a) 用例复用同一引用（数据准备改动，断言不动）；
(b) 把 `list` 改成同 target 只回一条（破坏 lib.rs 契约与 `memory_store.rs:115-158`，不可接受）。

## 3. tampered_header_byte_breaks_record_binding —— 绑定生效，失败在错误分类（测试侧）

症状：`offset 8 gave UnsupportedVersion { found: 0, expected: 1 }`（file_store.rs:180）。

根因：AAD 绑定是真实存在的——`record_aad = header || record_index`（container.rs:176-180），
且 `unknown_schema_version_refuses_to_decrypt`、`record_moved_to_other_file_fails_authentication`、
`tampered_metadata_length_fails_authentication` 等用例均通过。offset 8 正是
`schema_version` 字段，改它命中的是**更靠前的 fail-closed 分支**：
container.rs:218-225「版本不识别 → 直接拒绝读取，不尝试解密」（lib.rs:18 同样写明）。
该用例只允许 `WrongPassphrase | RecordAuthentication` 两种认证类结局，
而同一文件里另一条通过的用例（`unknown_schema_version_refuses_to_decrypt`）
恰恰断言版本域必须回 `UnsupportedVersion`——两条断言对同一字节互斥。

若「不改断言」强行满足：需让版本域篡改改报认证类错误，等于取消「不识别即拒读、
不尝试解密」的 fail-closed 分级，并把结构问题伪装成口令错误（误导用户换口令）。
按 AGENTS.md「fail-closed 不得静默回退」，不应这样改。

## 4. 需要拍板的分岔

三项失败无法在「只改 src、绝不动断言」下同时满足，且第 1/2/3 项的失败根因都在测试与
已声明语义的冲突上。可选路线：

- **A（建议）**：按测试缺陷修测试，但只改「数据准备与统计口径」，不改断言所表达的安全性质：
  第 2 项复用同一引用；第 1 项用完整 target 逐条核对（等价 `write_race`，可去重其一）；
  第 3 项按字段类别分级断言（版本/参数域 → 结构类错误；salt/verifier 域 → 认证类错误），
  并保留「必须失败、错误值脱敏」的硬性质。同时保留 WIP 的 `flush_locked` 加固。
  代价：`file_store.rs` 已 530 行 > 400 软目标，扩容后需按职责拆分文件。
- **B**：只合入 `flush_locked` 加固（真实但未被实测复现的竞态窗口），
  三项失败保留为「待产品语义确认」的显式红项，不假装全绿。
- **C**：改 `list` 或版本错误的 fail-closed 分级以满足原断言 —— 与 lib.rs 契约、
  `memory_store.rs` 既有通过用例、AGENTS.md fail-closed 规则冲突，不建议。

## 5. 本轮实际执行与门禁状态

- 复现并定位三项失败（证据见上），未凭猜测改码。
- 曾在 `tests/file_store.rs` 试写 A 方案改动（含新增 `debug_entries` 辅助与逐字节头部扫描），
  发现与「不改断言」约束冲突，已全部 `git checkout` 还原；`src/file.rs` 的 WIP 补丁经
  `git diff > /tmp/flush-locked.patch` 暂存后原样恢复（`flush_locked` 引用数 4，`git diff --stat`
  与交接时一致：1 file changed, 50 insertions(+), 40 deletions(-)）。
- 交接遗留的临时探针 `tests/zz_stress.rs` 仍在（文件头已注明「不提交」），提交前需剔除。
- 未提交、未 push：三项失败在「只改 src、不动断言」下无正确解，硬凑一个能让断言变绿的
  src 改动会破坏已声明语义，故不产出该提交，等路线拍板后再落。
- 基线门禁实测（`cargo test -p credential-ref --locked --no-fail-fast`）：
  container 单测 18/18、contract 10/10、memory_store 13/13、write_race 2/2、zz_stress 1/1 全绿；
  `file_store` **15 passed / 3 failed**——按 AGENTS.md「测试失败不能报全绿」如实记录，不谎称绿。
- `cargo clippy -p credential-ref --all-targets --locked -- -D warnings` exit=0（零告警）。
  注意：该结果依赖 `tests/file_store.rs` 头部那 3 行 `#![allow(dead_code)]`（交接时已在的未提交改动）；
  我误 revert 过一次，clippy 立刻以 5 条 dead-code 报错，已原样恢复。
- `cargo fmt -p credential-ref -- --check` **exit=1**：HEAD 版本 `file_store.rs` 单文件即有 24 处差异、
  未提交的 `zz_stress.rs` 3 处（共 27），属**既有欠账、非本轮引入**（对 `git show HEAD:` 的副本
  独立跑 `rustfmt --check` 同样 exit=1 复现）。因 `zz_stress.rs` 本就不打算提交、
  `file_store.rs` 待路线定后一起整理，本轮不做无关的全文件 reformat 以免混入噪声 diff。
  源码侧 `src/file.rs` 与其余 src 均 fmt 干净。
- `python scripts/check_line_limit.py`：硬上限失败 0；`container.rs` 650、`file_store.rs` 530 为
  \>400 软目标 WARN（A 方案扩容后需按职责拆分）。
