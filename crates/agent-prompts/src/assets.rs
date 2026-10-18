//! 参考端 提示词与工具描述资产（调研资料转写件）的编译期加载面。
//!
//! 资产正文在 `assets/*.md`（忠实转写自 参考端 pc-devguide，来源册名写在文件头部），
//! 经 `include_str!` 编译期嵌入：运行时仍无 IO、无副作用，与 crate 纯域定位一致。
//! 本模块只提供只读访问（[`PromptAsset`] 常量与 [`assets`] 目录表），不参与 [`Composer`] 渲染。

/// 一项 参考端 资产：标识、标题、来源册目次与正文。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromptAsset {
    /// 稳定标识（kebab-case，同 assets/ 文件名主干）。
    pub name: &'static str,
    /// 中文标题。
    pub title: &'static str,
    /// 来源：参考端 pc-devguide 册名与章节（可追溯标注）。
    pub source: &'static str,
    /// 资产正文（Markdown，编译期嵌入）。
    pub content: &'static str,
}

/// quick 模式系统提示词全文（07 册 §3.2 原文转写）。
pub const SYSTEM_PROMPT_QUICK: PromptAsset = PromptAsset {
    name: "system-prompt-quick",
    title: "quick 模式系统提示词全文",
    source: "参考端 pc-devguide 07《提示词系统》§3.2-§3.3、05《交互模式与Agent运行时》§8",
    content: include_str!("../assets/system-prompt-quick.md"),
};

/// 提示词体系架构：分层组装 / 模板矩阵 / 片段 / 风格 / 变量（07/18/21 册）。
pub const PROMPT_ARCHITECTURE: PromptAsset = PromptAsset {
    name: "prompt-architecture",
    title: "提示词体系架构（分层组装 / 模板矩阵 / 片段 / 风格 / 变量）",
    source: "参考端 pc-devguide 07《提示词系统》§2-§7、18《Agent运行时深挖》§13、21《工具宇宙与Fragments全文收编》§5-§7",
    content: include_str!("../assets/prompt-architecture.md"),
};

/// 主守则：安全规则三层 + 工具管线规则 + 交付/任务/自动化纪律（18/05/21 册）。
pub const SAFETY_RULES: PromptAsset = PromptAsset {
    name: "safety-rules",
    title: "主守则（安全规则三层 / 工具管线规则 / 任务纪律）",
    source: "参考端 pc-devguide 18《Agent运行时深挖》§5-§10、05《交互模式与Agent运行时》§3/§7、21《工具宇宙与Fragments全文收编》§4",
    content: include_str!("../assets/safety-rules.md"),
};

/// 工具全集目录：模式清单 / 78 项工具宇宙 / 内置 MCP 54 工具 / file: 通道层。
pub const TOOL_CATALOG: PromptAsset = PromptAsset {
    name: "tool-catalog",
    title: "工具全集目录（模式工具清单 / 工具宇宙 78 项 / 内置 MCP 54 工具）",
    source: "参考端 pc-devguide 05《交互模式与Agent运行时》§2/§4/§8、21《工具宇宙与Fragments全文收编》§1-§2、24《模式指令全文与内置MCP全表》§2、06《工具系统与安全中心》§2-§6",
    content: include_str!("../assets/tool-catalog.md"),
};

/// LLM 工具描述原文：Bash schema / Agent / TaskOutput / Minimal how-to / CLI 五模式指令。
pub const TOOL_DESCRIPTIONS: PromptAsset = PromptAsset {
    name: "tool-descriptions",
    title: "LLM 工具描述原文（Bash schema / Agent / TaskOutput / CLI 五模式指令）",
    source: "参考端 pc-devguide 22《Bash工具完整规格与权限链》§1/§4-§5、19《Agent会话运行时与工具面深挖》§7/§9-§10、24《模式指令全文与内置MCP全表》§1、18《Agent运行时深挖》§5/§11",
    content: include_str!("../assets/tool-descriptions.md"),
};

/// Agent Loop 与权限链摘要：9 步 loop 两版并存 / 8-Phase 权限链 / plan 门禁。
pub const AGENT_LOOP_PERMISSIONS: PromptAsset = PromptAsset {
    name: "agent-loop-permissions",
    title: "Agent Loop 与权限链摘要（9 步两版并存 / 8-Phase 权限链 / plan 门禁）",
    source: "参考端 pc-devguide 18《Agent运行时深挖》§4/§11.3、21《工具宇宙与Fragments全文收编》§3、05《交互模式与Agent运行时》§3/§5-§6/§8、22《Bash工具完整规格与权限链》§2-§3/§5、06《工具系统与安全中心》§5、19《Agent会话运行时与工具面深挖》§9",
    content: include_str!("../assets/agent-loop-permissions.md"),
};

/// 全部 参考端 资产（固定顺序，便于遍历与快照测试）。
pub const ASSETS: [PromptAsset; 6] = [
    SYSTEM_PROMPT_QUICK,
    PROMPT_ARCHITECTURE,
    SAFETY_RULES,
    TOOL_CATALOG,
    TOOL_DESCRIPTIONS,
    AGENT_LOOP_PERMISSIONS,
];

/// 按标识取资产；未知标识返回 `None`。
pub fn asset(name: &str) -> Option<&'static PromptAsset> {
    ASSETS.iter().find(|asset| asset.name == name)
}
