# 三层记忆系统规格 v0（agent-memory crate）

> **来源**：参照平台行为基线 §6（三层记忆 + 身份文件）+ [产品与协作约定](product-direction.md) §3（会话默认本地保存、跨会话记忆单独开启、可查看/删除/保留期限）。本文是 `agent-memory` crate 与 agent-core 集成的唯一规格源。
> **规则**：TDD 先失败再实现；单文件 ≤700（400 软）；no unsafe；凭据/密钥绝不写入任何记忆文件或日志。

## 1. 三层结构（目录约定）

| 层 | 位置 | 容量 | 写入方 |
|---|---|---|---|
| 身份层 | `~/.lengsuo/identity/{SOUL.md, USER.md}` | SOUL ≤8000 字符；USER ≤500 字符 | AI 显式写（identity 工具），用户可改文件 |
| 用户记忆 | `~/.lengsuo/memory/MEMORY.md` | ≤4000 字符 | AI 显式写（跨会话记忆，**默认关闭**） |
| 项目记忆 | `<workspace>/.lengsuo/memory/MEMORY.md` | ≤3000 字符 | AI 显式写 |
| 项目日志 | `<workspace>/.lengsuo/memory/YYYY-MM-DD.md` | 追加式（append-only，无上限） | AI 完成实质工作后追加摘要 |

- 目录名固定 `.lengsuo`（不是 参照平台 的 `.reference-dir`）；日期用本地日期（YYYY-MM-DD）。
- 所有文件 UTF-8；缺失文件 = 空内容（不是错误）。

## 2. 开关与隐私（冻结）

- `RuntimeConfig.memory.enabled: bool`，**默认 false**——跨会话记忆显式开启才工作（product-direction §3）。
- `enabled=false` 时：compose 返回空 bundle、所有写操作返回 `MemoryDisabled` 错误；身份层不受开关限制（SOUL/USER 是产品人格，非跨会话记忆）。
- 记忆文件路径必须落在授权 workspace 内（项目层）；用户层固定主目录。**路径遍历防护**：workspace 校验 `canonicalize` 前缀，`..` 拒绝。
- 记忆内容经脱敏过滤器（agent-core Redactor）后才落盘——写路径集成点在 agent-core，crate 自身提供 `redact: Option<Redactor>` 钩子位（v0 可不接）。
- 删除：`clear_project_memory()` / `clear_user_memory()` / `clear_daily(date)` 提供查看与删除能力（合规要求）。

## 3. agent-memory crate API（v0 冻结）

```rust
pub struct MemoryPaths { pub home: PathBuf, pub workspace: PathBuf }   // home=~/.lengsuo，workspace=会话工作区
pub struct Identity { pub ai_name: String, pub user_name: String, pub soul: String }

pub struct MemoryBundle {
    pub identity: Identity,            // 恒填充（缺省名：AI="Lengsuo"、用户="user"、soul 空）
    pub user_memory: Option<String>,   // enabled 且存在
    pub project_memory: Option<String>,// enabled 且存在
    pub daily_tail: Option<String>,    // enabled 且存在：当日日志尾部 ≤200 行
}

pub struct MemoryEngine { /* paths + enabled + caps */ }
impl MemoryEngine {
    pub fn new(paths: MemoryPaths, enabled: bool) -> Self;
    pub fn compose(&self) -> Result<MemoryBundle, MemoryError>;        // 只读；单层失败即整体 Err（fail-closed）
    pub fn append_daily(&self, date: NaiveDate, text: &str) -> Result<(), MemoryError>;  // 追加一行（自动加换行）；enabled=false ⇒ Err(Disabled)
    pub fn set_user_memory(&self, text: &str) -> Result<(), MemoryError>;   // >4000 字符 ⇒ Err(CapExceeded{cap, len})
    pub fn set_project_memory(&self, text: &str) -> Result<(), MemoryError>; // >3000 ⇒ 同上
    pub fn read_identity(&self) -> Result<Identity, MemoryError>;
    pub fn set_soul(&self, text: &str) -> Result<(), MemoryError>;     // >8000 ⇒ CapExceeded
    pub fn set_user_name(&self, name: &str) -> Result<(), MemoryError>; // ≤50 字符、非空
    pub fn set_ai_name(&self, name: &str) -> Result<(), MemoryError>;   // 同上
    pub fn clear_user_memory(&self) -> Result<(), MemoryError>;
    pub fn clear_project_memory(&self) -> Result<(), MemoryError>;
    pub fn clear_daily(&self, date: NaiveDate) -> Result<(), MemoryError>;
}
pub enum MemoryError { Disabled, CapExceeded { cap: usize, len: usize }, Io { path: PathBuf, source: std::io::Error }, PathEscape, EmptyName }
```

- 字符计数按 `chars().count()`（不是字节）。
- `append_daily` 幂等性不做（调用方去重）；文件不存在则创建（含父目录）。
- compose 的 daily_tail 取**当日**文件（非当日则 None——参照平台语义：只注入当日日志尾部）。

## 4. 注入语义（agent-core 集成，第二张卡）

- `create_session` 成功后：`engine.compose()` → 存入 `Session.memory_digest`（新字段：identity + 各层前 200 字符预览 + 全文引用 blob）；网关 `session:get` 返回。
- Prompt 组装顺序：SOUL（身份）→ 用户记忆 → 项目记忆 → 当日日志尾 → userRules。总注入上限 8000 字符，超限按层裁剪（身份层优先保留）。
- 工具面新增（全部过权限门，deny-by-default）：`memory.append_daily` / `memory.set_user` / `memory.set_project` / `identity.set_soul` / `identity.set_ai_name`——参数即 crate API 直映。
- 事件：每次记忆写操作发 `memory_update` 事件（审计 + UI 提示）。

## 5. 测试清单（TDD 先红）

1. compose：空目录 → 默认身份 + None 三层；三文件齐全 → 全填充。
2. 开关：enabled=false ⇒ compose 空记忆层 + 写操作 Disabled 错；身份层读写不受开关影响。
3. 容量：超限 CapExceeded 且**文件不被部分写入**；恰好等于上限通过。
4. append_daily：自动建目录/文件、追加不覆盖、两次追加顺序保持、date 隔离（不同日期不同文件）。
5. 身份：默认名、set 后读回一致、空名 EmptyName、超长拒绝。
6. 路径安全：workspace 内子路径穿越（`..`）拒绝 PathEscape。
7. clear：删除后 compose 对应层变 None。
8. 失败面：workspace 指向只读目录 ⇒ Io 错误上抛不 panic。
9. 性能锚：1000 行日志 tail 读取 < 10ms（标注不强制 CI）。

## 6. 集成状态

| 项 | 状态 |
|---|---|
| M1 agent-memory crate（§1–§3、§5） | 2026-10-16 开卡（agent/m-memory） |
| M2 agent-core 集成（§4） | 排 M1 收卡后 |
