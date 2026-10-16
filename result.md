# 卡 B 交付收据：当日日志与路径安全（agent-memory）

分支 `agent/m-memory`，规格源 `MEMORY-SPEC.md` v0（§5 第 4/6/7/8/9 组）。

## 1. 改动范围

| 文件 | 状态 | 行数 | 说明 |
|---|---|---|---|
| `crates/agent-memory/src/daily.rs` | 改写 | 150 | 填 `append_daily` / `read_daily_tail` / `clear_daily` 三个 `todo!()` |
| `crates/agent-memory/tests/daily_tests.rs` | 新建 | 392 | 卡 B 测试（12 例） |
| `result.md` | 新建 | — | 本收据 |

未触碰（卡 A 并行范围）：`engine.rs`、`identity.rs`、`engine_tests.rs`、`lib.rs`。
`Cargo.lock` 与 `MEMORY-SPEC.md` 在本卡开始前就已是工作树改动，不属本卡，未纳入提交。

## 2. 实现要点

- **顺序固定**：`append_daily` = 容量校验 → 路径校验 → 建父目录 → `O_APPEND` 打开写入。
  因此超限行**不留文件、不部分写入**（规格 §5.3 的容量语义在日志侧同样成立）。
- **换行**：追加内容后自动补 `\n`（规格 §3「自动加换行」）；单行上限 `CAP_DAILY_LINE = 8000` 字符。
- **只读当日**：`read_daily_tail` 只碰 `daily_file(date)`；`NotFound ⇒ Ok(None)`；
  其余 IO 错误 ⇒ `MemoryError::Io { path, source }` 上抛（fail-closed，不静默降级）。
- **尾部切片**：`tail_bounds` 自尾向前扫 `\n`，取 ≤`max_lines` 行的字节区间后直接切片，
  不构造全文件行向量；切点只落在 `\n` 之后或文件首，恒在字符边界上。
  行终止符语义与 `str::lines()` 对齐（文件尾的 `\n`/`\r\n` 不算内容，末行不留悬空 `\r`）。
  `max_lines = 0 ⇒ Some("")`；文件存在但为空 ⇒ `Some("")`（缺失才是 `None`）。
- **clear_daily**：`remove_file`；`NotFound`（文件或目录链缺失）视为成功 ⇒ 幂等。

## 3. 路径安全（规格 §2 的落地与边界）

写/读/删三条路径统一经 `guarded_daily_file`：

1. **词法级**：`MemoryPaths::ensure_within(workspace, daily_file)`——按路径组件比较（非字节前缀），
   拒绝 `..` 上跳，且 `/ws-evil` 不会因与 `/ws` 字符串同前缀被误判为授权内。
2. **真实路径复核** `check_real_prefix`：对 target 落在 workspace 内的祖先链，取最深存在实体
   `canonicalize`，要求仍在 `canonicalize(workspace)` 内。拦截「目录词法合法但被换成指向外部的
   symlink」——`.lengsuo/` 逃逸与「当日文件本身是外部 symlink」两种情形，读写删全部 `PathEscape`
   且**在触盘前**拒绝（测试断言外部目录保持空、外部文件仍在）。
   workspace 尚不存在（首次会话）⇒ `NotFound` 视为无需复核，交由自动建链。

显式记录的两处边界（未在本卡解决）：

- **TOCTOU**：校验与实际 IO 之间不具原子性；本卡不持句柄、不用 `openat(O_NOFOLLOW)`。
- **symlink 替换新建目录**：`append_daily` 先 `create_dir_all` 再复核会失败——即若
  `.lengsuo` 是被 symlink 指向外部的，`create_dir_all` 可能已在外部建出 `memory`。
  复核顺序保证的是**不写穿/不越权读删**已有实体；workspace 自身的授权（含规格 §2
  「canonicalize 前缀」校验）仍须在建立会话时兜底，本卡不重复该职责。

日期来自 `chrono::NaiveDate`（强类型），`{date}.md` 无法携带路径分隔符 ⇒ 文件名不可注入。
错误信息只带路径不带内容（测试断言 `Io` 的 source 文本不含记忆正文）。

## 4. 测试与门禁证据

TDD 先红（最终测试文件对 `cfa83ad` 的 `todo!()` 骨架运行）：

```
cargo test -p agent-memory --locked --test daily_tests   # 骨架版 daily.rs
test result: FAILED. 1 passed; 10 failed   ← 10 例 panic 于 daily.rs:20/30 todo!()
```
唯一通过的是 `path_traversal_with_dotdot_is_rejected`——它只断言骨架已实现的 `ensure_within`。

实现后（`CARGO_TARGET_DIR=/tmp/db-b`，隔离 target，不与他人构建锁互踩）：

| 命令 | 退出码 | 结果 |
|---|---|---|
| `cargo test -p agent-memory --locked` | 0 | `daily_tests` **12 passed; 0 failed**；lib/doctest 0 例 |
| `cargo test ... -- --test-threads=1` ×1、并行 ×3 | 0 | 全绿，无抖动；`/tmp` 残留临时目录 0 |
| `cargo clippy -p agent-memory --lib` | 0 | 5 warnings（骨架基线 7）；**不来自 daily.rs** |
| `cargo clippy -p agent-memory --all-targets` | 0 | 告警列表中无 `daily.rs` / `daily_tests.rs` |
| `rustfmt --check` 本卡两文件 | 0 | 干净（`error.rs`/`identity.rs`/`paths.rs`/`lib.rs` 的基线 fmt 漂移不属本卡范围，未改） |
| `python3 scripts/check_line_limit.py` | 0 | hard-limit failures: 0；本卡两文件均在 400 软目标内 |
| `cargo build --workspace --locked` | 0 | 通过（无其他 crate 依赖 agent-memory） |

lib 侧残留的 5 个告警为骨架既有（`read_identity` 未用 + `identity.rs` 的
`field_reassign_with_default` 等），随卡 A 填 `compose` 自然消解，本卡不新增也不越界修。

性能锚 §5.9（标注不强制 CI：始终测量打印，阈值断言仅非 CI 生效）：

```
1000 行日志 tail(200) 最快一次: 94 µs（预算 10000 µs）
```

## 5. 用例 ↔ 规格对照

| §5 组 | 测试 |
|---|---|
| 4 自动建目录/追加不覆盖/顺序保持 | `append_daily_creates_dirs_and_appends_in_order` |
| 4 日期隔离 | `append_daily_isolates_by_date` |
| 3 尾部 ≤max_lines、行序保持 | `read_daily_tail_returns_last_lines_in_order` |
| 3 尾部边界（CRLF / 空文件 Some("")） | `read_daily_tail_handles_crlf_and_empty_file` |
| 6 `..` 穿越拒绝、组件级前缀、文件名不可注入 | `path_traversal_with_dotdot_is_rejected` |
| 6 加固：`.lengsuo` symlink 逃逸（读写删） | `symlink_escaping_workspace_is_rejected` |
| 6 加固：当日文件 symlink 指向外部 | `daily_file_symlink_to_outside_is_not_touched` |
| 7 clear 后变 None、幂等、不误删他日 | `clear_daily_makes_tail_none_and_is_idempotent` |
| 8 容量超限不留部分写入 | `over_cap_append_writes_nothing` |
| 8 只读目录 ⇒ `Io` 上抛不 panic（环境豁免则跳过） | `read_only_directory_surfaces_io_error` |
| 9 1000 行 tail < 10ms | `perf_anchor_tail_of_1000_lines_under_10ms` |
| 附：workspace 缺失自动建链 | `append_creates_missing_workspace_chain` |

临时目录为自实现 `TempDir`（pid + 序号 + tag，`Drop` 清理前还原权限），
不新增 `tempfile` 依赖，保持本 crate `--locked` 依赖面不变。

## 6. 未做（留给后续卡）

- `MemoryEngine::append_daily` / `clear_daily` 的**开关语义**（`enabled=false ⇒ Err(Disabled)`）与
  `compose` 里 `daily_tail` 的当日判定：入口在 `engine.rs`（卡 A）；本卡的自由函数是它的实现底座。
- 脱敏钩子 `redact`（规格 §2，v0 可不接）与 agent-core 集成（规格 §4，M2）。
- §3 的 TOCTOU 加固（`O_NOFOLLOW` / 目录句柄）如要收口，需改 `paths.rs` 与 engine 的会话建立校验，
  超出本卡文件范围。
