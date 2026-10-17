//! 提示词引擎的域模型：模式、注入变量、模板段与渲染。

/// 提示词模式；能力面按 只答 → 只读 → 规划 → 全工具 → 专家 递增。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PromptMode {
    /// 只答不操作，无任何工具说明。
    Quick,
    /// 只读工具白名单说明。
    Ask,
    /// 复用 craft 模板并追加规划门禁。
    Plan,
    /// 全工具说明。
    Craft,
    /// craft 之上追加专家协作段。
    Expert,
}

impl PromptMode {
    /// 固定顺序，便于遍历与快照测试。
    pub const ALL: [PromptMode; 5] = [
        PromptMode::Quick,
        PromptMode::Ask,
        PromptMode::Plan,
        PromptMode::Craft,
        PromptMode::Expert,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            PromptMode::Quick => "quick",
            PromptMode::Ask => "ask",
            PromptMode::Plan => "plan",
            PromptMode::Craft => "craft",
            PromptMode::Expert => "expert",
        }
    }
}

/// 注入模板的变量集。全部由调用方提供（引擎不取时钟、不读环境、不做 IO）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PromptVars {
    /// 助手名称。
    pub ai_name: String,
    /// 用户称呼。
    pub user_name: String,
    /// 人格设定文本。
    pub soul: String,
    /// 工作区路径或描述。
    pub workspace: String,
    /// 日期文本（来源由调用方决定，保证输出确定性）。
    pub date: String,
    /// 用户自定义规则；非空时追加为独立段。
    pub user_rules: String,
    /// 三层记忆组装后的摘要文本；可为空。
    pub memory_digest: String,
}

impl PromptVars {
    /// 按变量名取值；未知键返回 `None`。
    pub fn get(&self, key: &str) -> Option<&str> {
        let value = match key {
            "ai_name" => &self.ai_name,
            "user_name" => &self.user_name,
            "soul" => &self.soul,
            "workspace" => &self.workspace,
            "date" => &self.date,
            "user_rules" => &self.user_rules,
            "memory_digest" => &self.memory_digest,
            _ => return None,
        };
        Some(value.as_str())
    }
}

/// 模板的一段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    /// 字面文本，可含 `{{key}}` 注入点。
    Text(String),
    /// 独立段落槽位：`soul` / `memory_digest` / `user_rules` 带各自标题成段，
    /// 其余已知变量输出裸值，未知键与空值整段省略。
    Var(&'static str),
    /// 规划门禁片段（仅 plan 模板使用）。
    Gate,
}

/// 一个模式的模板：模式 + 段序列。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptTemplate {
    mode: PromptMode,
    segments: Vec<Segment>,
}

impl PromptTemplate {
    pub fn new(mode: PromptMode, segments: Vec<Segment>) -> Self {
        Self { mode, segments }
    }

    pub fn mode(&self) -> PromptMode {
        self.mode
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// 渲染为提示词文本：段间以空行分隔，空槽位整段省略，末尾保留单个换行。
    pub fn render(&self, vars: &PromptVars) -> String {
        let mut parts: Vec<String> = Vec::with_capacity(self.segments.len());
        for segment in &self.segments {
            let rendered = match segment {
                Segment::Text(text) => Some(substitute(text, vars)),
                Segment::Var(key) => slot(key, vars),
                Segment::Gate => trim(crate::template::PLAN_GATE),
            };
            if let Some(part) = rendered {
                if !part.trim().is_empty() {
                    parts.push(part);
                }
            }
        }
        let mut out = parts.join("\n\n");
        out.push('\n');
        out
    }
}

/// 单遍替换 `{{key}}`：未知键与值中的花括号原样保留，不递归展开。
fn substitute(text: &str, vars: &PromptVars) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("}}") {
            Some(end) => {
                let key = &after[..end];
                match vars.get(key) {
                    Some(value) => out.push_str(value),
                    // 未知键：原样保留花括号（内置模板不含未知键，注入值不再被替换）。
                    None => {
                        out.push_str("{{");
                        out.push_str(key);
                        out.push_str("}}");
                    }
                }
                rest = &after[end + 2..];
            }
            None => {
                out.push_str("{{");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// 槽位渲染：值非空（且非纯空白）时成段，否则整段省略，不留空洞标记。
/// 三段可独立成节（人格设定 / 记忆摘要 / 用户自定义规则）；
/// 其余已知变量作为独立段时输出裸值；未知键省略。
fn slot(key: &'static str, vars: &PromptVars) -> Option<String> {
    let value = vars.get(key).and_then(trim)?;
    match key {
        "soul" => Some(format!("人格设定：\n{value}")),
        "memory_digest" => Some(format!("## 记忆摘要\n{value}")),
        "user_rules" => Some(format!("## 用户自定义规则\n{value}")),
        _ => Some(value),
    }
}

/// 去掉首尾空白；全空白视为空（返回 `None`）。
fn trim(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}
