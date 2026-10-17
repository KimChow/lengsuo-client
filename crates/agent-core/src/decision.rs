//! 决策模型抽象（StartLux-Decision 形态）。
//!
//! 架构先行（选项 A，决策记录见私有仓 `docs/jev-startlux-research.md`）：
//! 本模块只冻结 trait 与语义（三题型 + 校准概率 + 置信门），权重接入等
//! F3 专项与商用授权（权重 CC BY-NC，禁商用）。[`RuleBasedDecider`] 是
//! 占位桩：**永不自动放行**——审批语义由权限门权威裁定，桩输出仅作建议。

use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// 缺省置信门（AutoThink 默认 0.6）。
pub const DEFAULT_CONFIDENCE_GATE: f32 = 0.6;

/// 「都不合适」标签（choice 题型专用，StartLux 的 none_probability 语义）。
pub const NONE_LABEL: &str = "NONE";

/// 决策题型（StartLux-Decision 三题型语义）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum DecisionQuestion {
    /// 单选：从选项中选一个；NONE 表示列出的选项都不合适。
    Choice { state: String, options: Vec<String> },
    /// 是/否判断（yes = 肯定侧）。
    Noul { state: String, question: String },
    /// 量表打分：levels 为升序等级标签。
    Score { state: String, levels: Vec<String> },
}

/// 校准答案：标签序列上的概率分布（总和 ≈1，浮点误差内）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionAnswer {
    /// 与题型对齐的标签序列（choice=选项+NONE；noul=[no,yes]；score=levels）。
    pub labels: Vec<String>,
    /// 与 labels 等长的概率（各值 ∈ [0,1]，总和 ≈1）。
    pub probabilities: Vec<f32>,
    /// 置信门判定（AutoThink 语义）：top 概率 ≥ 门 ⇒ true；false 表示需要
    /// 「深思」或人工介入——门语义只是标注，不放行任何操作。
    pub confident: bool,
    /// 决策依据的可读摘要（桩给规则名；真实模型给模型自述）。不得含凭据或明文敏感值。
    pub rationale: String,
}

impl DecisionAnswer {
    /// 构造并规范化：概率截断到 [0,1] 后归一化（和为 1），按 AutoThink 门标注置信。
    pub fn normalized(
        labels: Vec<String>,
        mut probabilities: Vec<f32>,
        gate: f32,
        rationale: impl Into<String>,
    ) -> Result<Self, CoreError> {
        if labels.len() != probabilities.len() || labels.is_empty() {
            return Err(CoreError::InvalidConfig(
                "决策答案标签与概率数量不一致".into(),
            ));
        }
        for p in &mut probabilities {
            // 权重是加性打分（可 >1）；只拒负数与非有限值——先 clamp 到 [0,1]
            // 会把高分压平成均匀分布（v0 实测踩坑：1.5→1.0 ⇒ 全 0.5）。
            if !p.is_finite() || *p < 0.0 {
                return Err(CoreError::InvalidConfig("决策权重必须为非负有限值".into()));
            }
        }
        let sum: f32 = probabilities.iter().sum();
        if sum <= 0.0 {
            return Err(CoreError::InvalidConfig("决策概率总和必须为正".into()));
        }
        for p in &mut probabilities {
            *p /= sum;
        }
        let mut answer = Self {
            labels,
            probabilities,
            confident: false,
            rationale: rationale.into(),
        };
        answer.confident = answer.top().is_some_and(|(_, p)| p >= gate);
        Ok(answer)
    }

    /// 最高概率项（标签下标，概率）。
    pub fn top(&self) -> Option<(usize, f32)> {
        self.probabilities
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.total_cmp(b.1))
            .map(|(i, p)| (i, *p))
    }

    /// 按标签取概率。
    pub fn probability_of(&self, label: &str) -> Option<f32> {
        self.labels
            .iter()
            .position(|l| l == label)
            .map(|i| self.probabilities[i])
    }

    /// 结构校验（对远程/外部提供方的返回做 fail-closed 校验用）。
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.labels.is_empty() || self.labels.len() != self.probabilities.len() {
            return Err(CoreError::InvalidConfig(
                "决策答案标签与概率数量不一致".into(),
            ));
        }
        let sum: f32 = self.probabilities.iter().sum();
        if !(0.99..=1.01).contains(&sum) {
            return Err(CoreError::InvalidConfig(format!(
                "决策概率总和应为 1，实际 {sum:.4}"
            )));
        }
        if self.probabilities.iter().any(|p| !(0.0..=1.0).contains(p)) {
            return Err(CoreError::InvalidConfig("决策概率越界".into()));
        }
        Ok(())
    }
}

/// 决策提供方（未来实现：llama.cpp 本地权重 / 远程 API / 规则桩）。
pub trait DecisionProvider: Send + Sync {
    fn decide(&self, question: &DecisionQuestion) -> Result<DecisionAnswer, CoreError>;
}

/// 规则桩（选项 A 占位实现）：关键词命中加成 + 归一化；noul 默认保守偏 no；
/// score 均匀分布。输出仅作建议——审批与工具放行由权限门权威裁定。
#[derive(Debug, Clone)]
pub struct RuleBasedDecider {
    gate: f32,
}

impl RuleBasedDecider {
    pub fn new(gate: f32) -> Self {
        Self {
            gate: gate.clamp(0.0, 1.0),
        }
    }
}

impl Default for RuleBasedDecider {
    fn default() -> Self {
        Self::new(DEFAULT_CONFIDENCE_GATE)
    }
}

impl DecisionProvider for RuleBasedDecider {
    fn decide(&self, question: &DecisionQuestion) -> Result<DecisionAnswer, CoreError> {
        match question {
            DecisionQuestion::Choice { state, options } => {
                if options.is_empty() {
                    return Err(CoreError::InvalidConfig("choice 选项不能为空".into()));
                }
                let state_lower = state.to_lowercase();
                let mut labels: Vec<String> = options.clone();
                labels.push(NONE_LABEL.into());
                let mut weights: Vec<f32> = options
                    .iter()
                    .map(|o| {
                        let hits = o
                            .to_lowercase()
                            .split(|c: char| !c.is_alphanumeric() && c != '_')
                            .filter(|w| w.len() >= 2 && state_lower.contains(w))
                            .count() as f32;
                        1.0 + 4.0 * hits
                    })
                    .collect();
                let best = weights.iter().cloned().fold(0.0f32, f32::max);
                // 无任何命中 ⇒ NONE 主导（defer 语义）
                weights.push(if best <= 1.0 { 2.0 } else { 1.0 });
                let why = if best > 1.0 {
                    "关键词命中"
                } else {
                    "无命中，建议都不合适"
                };
                DecisionAnswer::normalized(labels, weights, self.gate, format!("规则桩：{why}"))
            }
            DecisionQuestion::Noul { state, question } => {
                // 保守缺省：偏 no（1.5 vs 1.0）；状态/问题含明确肯定语义词才翻转。
                let text = format!("{state} {question}").to_lowercase();
                let affirmative = ["已授权", "已确认", "白名单", "approved", "allowlisted"]
                    .iter()
                    .any(|w| text.contains(w));
                let (no, yes) = if affirmative { (1.0, 1.5) } else { (1.5, 1.0) };
                let ans = DecisionAnswer::normalized(
                    vec!["no".into(), "yes".into()],
                    vec![no, yes],
                    self.gate,
                    format!("规则桩：保守缺省偏 no（affirmative={affirmative}）"),
                )?;
                Ok(ans)
            }
            DecisionQuestion::Score { state: _, levels } => {
                if levels.is_empty() {
                    return Err(CoreError::InvalidConfig("score 等级不能为空".into()));
                }
                let n = levels.len() as f32;
                DecisionAnswer::normalized(
                    levels.clone(),
                    vec![1.0 / n; levels.len()],
                    self.gate,
                    "规则桩：score 均匀分布（无排序信号）".to_string(),
                )
            }
        }
    }
}
