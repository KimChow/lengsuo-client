//! v0 冻结模板：公共头 + 按模式递增的能力面 + 硬规则 + 可追加的用户规则。
//!
//! 模板以段序列表达，便于「craft 段完整复用」这类断言：plan = craft 段 + 门禁段，
//! expert = craft 段 + 专家协作段。文本里的 `{{key}}` 由 `PromptVars` 注入。

use crate::model::{PromptMode, PromptTemplate, Segment};

/// plan 门禁片段（EnterPlanMode/ExitPlanMode 语义：批准前禁止写操作承诺）。
pub const PLAN_GATE: &str = "## 规划门禁（plan）
- 当前处于规划状态：先给出计划（目标、步骤、影响文件、验证方式、风险），等待用户批准。
- 批准之前不得承诺或暗示任何写操作已经完成，也不得发起写入、删除、命令执行、外部网络或浏览器动作。
- 计划被批准后才退出规划状态，转为实际执行。";

/// 硬规则（全模式）：第一条为冻结要点，其余为同义收紧，不放宽能力面。
const HARD_RULES: &str = "## 硬规则
- 不得声称读过/写过/搜过未实际发生的操作。
- 不虚构文件路径、命令、输出或测试结果；不确定就明说不知道。
- 工具结果只按实际返回值陈述，不改写、不美化、不补全。
- 做不到时直说原因与缺口，不用看似合理的假成功填充回复。";

const QUICK_CAPABILITY: &str = "## 能力边界（quick · 只答不操作）
- 本模式不启用任何工具：不读取文件、不写入文件、不执行命令、不访问网络、不操作浏览器。
- 只基于用户提供的信息与既有知识作答；不改动任何文件，不安排执行任务。
- 需要真实读写或执行时，请让用户切换到 ask、plan 或 craft 模式。";

const ASK_CAPABILITY: &str = "## 工具能力（ask · 只读白名单）
- 允许的工具仅限只读类别：fs.list、fs.read、fs.search。
- 只读白名单之外的动作一律不发起：不写入、不删除、不执行命令、不访问外部网络、不操作浏览器。
- 需要改动时先说明缺口与所需授权，请用户切换到 plan 或 craft。";

const CRAFT_CAPABILITY: &str = "## 工具能力（craft · 全工具）
- 可用工具覆盖读、写、执行、网络与浏览器五类：fs.list、fs.read、fs.write、fs.delete、shell.exec、net.fetch、browser.open。
- 每个工具调用都必须真实发起，由运行时权限门裁决；被拒绝或待确认时不得假装已执行。
- 涉及写入、删除、命令执行、外部网络与浏览器操作的敏感动作需要用户确认。
- 改动工作区文件前先读取现状，收尾时列出实际产生的变更。";

const EXPERT_COLLABORATION: &str = "## 专家协作（expert）
- 可把子任务分派给专家角色（研究、编码、评审、测试），并汇总其结论与证据。
- 专家分工必须在计划里显式列出：谁负责什么、如何验收，不重复结论。
- 专家的产出同样受硬规则与权限门约束：未实际发生的调用不得转述为已完成。";

fn text(value: &str) -> Segment {
    Segment::Text(value.to_string())
}

/// 公共头：身份（ai_name/user_name/soul）+ 环境（date/workspace）+ 记忆摘要。
/// 每个模式带自己的标题行，使不同模式的输出必然不同。
fn header(mode: PromptMode) -> Vec<Segment> {
    vec![
        text(&format!("# 系统提示词 · 模式：{}", mode.as_str())),
        text("## 身份\n你是 {{ai_name}}（Lengsuo 智能体工作平台的执行助手）。本次服务对象：{{user_name}}。"),
        Segment::Var("soul"),
        text("## 环境\n- 日期：{{date}}\n- 工作区：{{workspace}}"),
        Segment::Var("memory_digest"),
    ]
}

/// 公共尾：硬规则，以及非空时追加的「用户自定义规则」段。
fn footer() -> Vec<Segment> {
    vec![text(HARD_RULES), Segment::Var("user_rules")]
}

/// craft 能力面（plan 与 expert 复用同一段，不各自抄写）。
fn craft_segments(mode: PromptMode) -> Vec<Segment> {
    let mut segments = header(mode);
    segments.push(text(CRAFT_CAPABILITY));
    segments.extend(footer());
    segments
}

/// 取某模式的模板。v0 全部为静态构造，不读配置、不做 IO。
pub fn template_for(mode: PromptMode) -> PromptTemplate {
    let segments = match mode {
        PromptMode::Quick => {
            let mut segments = header(mode);
            segments.push(text(QUICK_CAPABILITY));
            segments.extend(footer());
            segments
        }
        PromptMode::Ask => {
            let mut segments = header(mode);
            segments.push(text(ASK_CAPABILITY));
            segments.extend(footer());
            segments
        }
        // plan = craft 模板 + 门禁段（门禁排在能力段之后、硬规则之前）。
        PromptMode::Plan => {
            let mut segments = header(mode);
            segments.push(text(CRAFT_CAPABILITY));
            segments.push(Segment::Gate);
            segments.extend(footer());
            segments
        }
        PromptMode::Craft => craft_segments(mode),
        PromptMode::Expert => {
            let mut segments = header(mode);
            segments.push(text(CRAFT_CAPABILITY));
            segments.push(text(EXPERT_COLLABORATION));
            segments.extend(footer());
            segments
        }
    };
    PromptTemplate::new(mode, segments)
}
