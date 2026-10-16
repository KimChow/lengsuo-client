# 轨道 C Skills 卡交付报告（agent-skills）

工作目录：`/home/ubuntu/lengsuo-client-dev/wt-agent-skills`（分支 `agent/c-skills`）。
规格源：worktree 根 `SKILLS-SPEC.md`（本卡唯一规格源，冻结）。

## 1. 门禁结果

- `cargo test -p agent-skills --locked`：26 项全绿（`tests/parse.rs` 16、`tests/registry.rs` 9、doc-test 1）。
  TDD 顺序：先建 crate 骨架与两份测试文件 → 编译期失败（`unresolved imports`，红）→ 再写实现转绿。
- `cargo clippy -p agent-skills --all-targets -- -D warnings`：通过。
- `cargo fmt -p agent-skills -- --check`：通过。
- 基线说明：`cargo fmt --all -- --check` 在**本 crate 之外**仍有既有失败
  （`crates/ss-core/tests/golden.rs`，我没有改动该文件；属于其它轨道/后续整理范围，
  按本卡「仅本 crate」的完成定义不在这里顺手改，避免混入无关提交）。
- `python scripts/check_line_limit.py`：hard-limit failures 0；本 crate 最大文件 199 行，全部低于 400 软目标。
- 隔离 target：`CARGO_TARGET_DIR=/home/ubuntu/lengsuo-client-dev/target-skills`，未触碰其它工作树构建锁。
- 依赖：运行时仅 `thiserror`（未需要 serde）；dev 依赖 `tempfile`。同步 fs IO，无 unsafe。
- 未 push（按卡要求）。

## 2. 交付内容

```text
crates/agent-skills/
  Cargo.toml            新 crate，workspace 继承版本/许可
  src/lib.rs            职责边界 + doctest 用法（站点级/用户级分层目录）
  src/skill.rs          Skill { name, description, body, path }
  src/error.rs          SkillsError：NotFound / Malformed{path,reason} / Io{path,source}
  src/parse.rs          parse_skill_md：front-matter 解析、32 KiB 上限、name 规则、正文非空
  src/registry.rs       SkillRegistry::with_dirs / load / find（后注册者优先）
  tests/parse.rs        解析行为 16 项
  tests/registry.rs     注册表行为 9 项
docs/agent-skills-status.md  状态文档（契约、验证、未实现项）
Cargo.toml              members 追加 crates/agent-skills
```

## 3. 规格落地的判断点（如实记录）

1. **大小检查在读取之前**：先 `fs::metadata` 比 32 KiB，超限直接 `Malformed`，不把超限文件读进内存；
   并校验 `is_file()`（`SKILL.md` 是目录/设备时也走 NotFound，不误判格式）。
2. **`NotFound` 的触发点**：`parse_skill_md` 在 `SKILL.md` 缺失时返回 `NotFound`；
   `load()` 扫描一级子目录时先用 `path.join(SKILL.md).is_file()` 过滤（无 `SKILL.md` 的子目录不算技能，
   静默忽略，与 WorkBuddy 目录式管理一致）；根目录缺失时 `load()`/`find()` 返回 `NotFound`
   （配置写错不静默当空目录；上层要容错可在注册前 `filter(is_dir)`，测试里已示范）。
   因此 `find()` 未命中返回 `Ok(None)`，不抛 `NotFound`——由调用方决定「技能不存在」的对外表述。
3. **重名语义**：注册表原则是「同名覆盖」，所以同目录内两个子目录声明同一 front-matter `name`
   也按覆盖处理（以名称升序扫描的后来者为准），不报 `Malformed`。
   规格里「Malformed 拒绝重名文件内声明缺失」一句文本不通，我的读法是
   *Malformed 拒绝「重名」以外的『文件内 name 声明缺失』*，即 front-matter 存在却缺 `name` ⇒ `Malformed`。
   若主理人原意是「同一目录内重名必须报错」，只需改 `load()` 的合并分支，测试点已覆盖两处行为，改动局部。
4. **name 不做大小写归一**：`[a-z0-9-]{1,64}` 严格校验（大写/下划线/点/斜杠/空/65 字符均拒绝），
   避免归一后两个不同技能撞名，也让 `find` 的大小写敏感有据。
5. **front-matter 解析自实现**：只取 `name`/`description`，忽略未知 key 与 `#` 注释，去成对引号，
   支持 LF/CRLF；不引入 YAML 依赖（符合「依赖仅 thiserror/serde」）。有开头无收尾 `---` ⇒ `Malformed`，
   不把正文误吞成元数据。
6. **`load()` 确定性**：返回按 `name` 升序、同目录内扫描次序固定 ⇒ 同输入同输出，便于上层逐字节比对与 UI 稳定排序。
7. **fail-closed**：任一技能非法即整次 `load()` 失败并带出坏文件路径，不静默跳过（AGENTS.md §3 认证/解码
   fail-closed 的同类要求，虽然技能不是凭据，但注入模型的内容不应「部分成功」）。
8. **body 全文不裁剪**：`body` 仅为去掉 front-matter 后 `trim()` 的正文，逐字保留（含 Markdown 结构、空行），
   32 KiB 上限是唯一的体量闸门；注入 system 消息由上层完成，本 crate 不做拼接。

## 4. 与 WorkBuddy 的对照与差异

- 一致：技能 = 目录 + `SKILL.md`；按 `skillName` 取全文注入；目录式管理；`name`/`description` 元数据。
- 自主设计（不声称与 WorkBuddy 行为相同）：多根目录 + 后注册者优先的分层覆盖；显式 32 KiB 与
  `[a-z0-9-]{1,64}` 硬约束；坏文件 fail-closed；`find` 未命中返回 `Ok(None)` 而非错误。
- 未做行为对照验收（没有 WorkBuddy 可执行环境），文档表述为「产品参考 + 自主实现」。

## 5. 未实现（下一卡范围，不在本卡偷做）

- `skill` 工具接入 `agent-core::ToolRegistry`，以及 body 拼进会话 system 消息的注入链路。
- 技能可见性/授权（哪些会话可用哪些技能）、启用开关与配置来源。
- 多租户与环境隔离的技能目录、远端技能包分发与校验（签名/归档）。
- front-matter 完整 YAML（列表、多行、锚点）——现只保证 name/description。

## 6. 复现命令

```sh
export CARGO_TARGET_DIR=/home/ubuntu/lengsuo-client-dev/target-skills
cargo test -p agent-skills --locked
cargo clippy -p agent-skills --all-targets -- -D warnings
cargo fmt -p agent-skills -- --check
python scripts/check_line_limit.py
```
