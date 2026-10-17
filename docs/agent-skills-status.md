# agent-skills 实现与验收状态

规格源：worktree 根 `SKILLS-SPEC.md`（本卡唯一规格源，冻结）。
产品对照：WorkBuddy 的 Skill 工具（`skillName` → 读 `SKILL.md` 全文注入 system
消息；技能 = 提示词包；目录式管理）。本仓自主设计实现，不声称与 WorkBuddy 一致。

## 已实现（`crates/agent-skills`）

- `Skill { name, description, body, path }`：`body` 是去掉 front-matter 的正文全文，
  调用方整段注入，本 crate 不裁剪、不改写。
- `parse_skill_md(dir)`：解析目录下的 `SKILL.md`。
  - front-matter 以 `---` 行开头并以 `---` 行收尾，只取 `name`/`description`
    两个 `key: value`（YAML 简式，自实现，不引入 YAML 依赖）；未知 key 与 `#` 注释忽略；
    简单成对引号去除，不实现 YAML 转义；LF/CRLF 均可。
  - 无 front-matter ⇒ `name` 取目录名、`description` 为空。
  - 有 front-matter 但缺 `name` ⇒ `Malformed`（name 是查找唯一键，不猜）。
  - front-matter 与目录名冲突 ⇒ 以 front-matter 为准（目录名非法也不影响）。
  - 约束：文件 ≤32 KiB 否则 `Malformed`；`name` 必须满足 `[a-z0-9-]{1,64}`，
    大小写敏感、不做归一；`body` 非空否则 `Malformed`；非 UTF-8 ⇒ `Malformed`（不 panic）。
- `SkillRegistry::with_dirs(dirs)`：目录有序，**后注册者优先**（同名覆盖），支持
  「站点级默认 + 用户级覆盖」分层；`load()` 扫描各根目录的一级子目录，忽略隐藏项、
  非目录与散落文件，按 `name` 升序返回（同输入同输出）；`find(name)` 大小写敏感，
  未命中返回 `Ok(None)`。
  `find()` 每次都重新扫描目录（v0 无缓存、无 watcher）：技能文件的改动能立即生效，
  代价是每次调用一轮同步 IO；若上层需要热点缓存，应在网关/运行时层做，不改本 API。
- `SkillsError`：`NotFound` / `Malformed { path, reason }` / `Io { path, source }`。
  `NotFound` 只在技能目录（根目录）缺失时产生；`SKILL.md` 本身缺失走
  `load()` 的跳过语义或 `find()` 的 `Ok(None)`。
- fail-closed：任一技能非法即整次 `load()` 失败并带出坏文件路径，不静默跳过坏文件。

## 验证

- `cargo test -p agent-skills --locked`：26 项通过（含 1 项 doctest）
  （`tests/parse.rs` 16 项：有/无 front-matter、front-matter 覆盖目录名、缺 name、
  未闭合分隔行、坏 name 六例、64 字符边界、引号、注释/未知 key、空正文两例、
  32 KiB 上下边界、缺文件 NotFound、非 UTF-8、CRLF、错误显示含路径；
  `tests/registry.rs` 9 项：扫描与忽略规则、目录间覆盖与反向顺序、目录内同名次序、
  大小写敏感、未命中 `Ok(None)`、空注册表、缺根目录 NotFound、
  坏技能 fail-closed、注入全文逐字一致）。
- 同步 IO、无 unsafe、依赖仅 `thiserror`（dev 依赖 `tempfile`）。
- `cargo fmt --check`、`cargo clippy -p agent-skills --all-targets -- -D warnings` 通过；
  行数门禁通过（最大单文件 250 行，均低于 400 软目标）。

## 未实现（待后续卡）

- 注入链路：把 `Skill.body` 拼进会话 system 消息、技能对会话的可见性筛选与授权
  （属 agent-core/网关职责，本 crate 不做）。
- 上层调用点：`agent-core` 工具注册表里的 `skill` 工具与 `Skill` 目录展示未接线。
- 多租户/环境隔离的技能目录来源、远端技能包分发与校验（zip/签名）均无。
- 未与 WorkBuddy 做过行为对照验收，仅按本卡规格实现。
