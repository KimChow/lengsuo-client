# 访问策略匹配引擎规格 v0（policy-engine crate）

> 语义来源：资料仓 J-26/J-27 实证（特殊案例 > 白名单 > 黑名单；策略粒度 URL × 操作 × DOM）。本文件是唯一规格源；与任务卡冲突时以本文件为准并记录到 result.md。

## 1. 数据模型

```text
PolicySpec {
  policy_id, name,
  mode: ALL=1 | SomeBlack=2 | SomeWhite=3 | SpecialCase=4,   // 枚举数值冻结
  strategy_empty_default: Black,      // strategy 为空 ⇒ 默认黑名单模式（实证）
  targets: { user_ids, role_ids, dept_ids, account_ids },     // 生效对象（提交字段名冻结）
  rules: [ RuleItem ],
  active_range: Option<{ start_ms, end_ms }>,                  // 生效时间窗
}
RuleItem {
  url_pattern: String,          // 通配符模式（如 *.example.com/*），编译为正则匹配
  is_accessible: bool,          // 该 URL 是否可访问
  is_log: bool,                 // 记录访问行为（独立于 is_accessible；active_range 存在时禁用 is_log）
  actions: { access, clipboard, file_upload, file_download, print, console, click_dom },  // 7 操作，各自 bool
  dom_selectors: Vec<String>,   // click_dom 的 DOM 选择器粒度
}
```

## 2. 匹配算法（冻结）

1. 输入 `EvaluateRequest { url, action, now_ms, targets_ctx }`，输出 `Decision { allowed, matched_rule: Option<RuleItemId>, reasons: Vec<String> }`。
2. **fail-closed**：无任何策略命中 / 策略取不到 / active_range 不在窗内 ⇒ `allowed=false`，reason 标明 fail-closed。
3. 优先级：**SpecialCase > 白名单 > 黑名单**。
4. 白名单与黑名单同时存在时 **白优先**；白名单/黑名单各自覆盖"所有网页"通配（精确规则 > 通配规则；同精度时按规则序）。
5. URL 匹配：通配符转正则（`*` → `[^/]*` 段内、跨段由模式本身决定；编译期一次，匹配期零分配优先）；大小写敏感，scheme 归一化（缺省 https）。
6. 操作判定：URL 命中后看 `actions.<action>`；`click_dom` 需 selector 命中（本 crate 只做 selector 字符串传递，不做 DOM 解析）。
7. `is_log` 命中 ⇒ Decision 附 `should_log=true`。

## 3. 验收边界（测试必须覆盖）

- 四种模式的匹配序各至少 2 例；白>黑同存、白覆盖通配、精确>通配。
- strategy 为空走黑名单默认；空规则集 fail-closed。
- active_range 窗内外；窗内 is_log 被禁用。
- URL 通配编译：`*.example.com` 不匹配 `a.b.example.com`（除非模式写 `**`）；scheme 归一化。
- 7 操作逐一举例；click_dom 无 selector 时拒绝该操作（fail-closed）。
- 性能锚：1000 规则 × 单次 evaluate < 1ms（基准测试标注，不强制 CI 断言）。

## 4. 硬约束

- 纯域 crate：不依赖 tokio、不做 IO；`no unsafe`；单文件 ≤700（400 软）；TDD 先失败再实现。
- 只新增 `crates/policy-engine` + 根 Cargo.toml 的 members 一行；不改任何既有文件。
