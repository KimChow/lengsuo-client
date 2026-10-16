//! 环境管理视图状态（GPUI 渲染的数据源，纯逻辑）。
//!
//! v0 的 `config:get` 返回值形态未定（见 PROTOCOL-NOTES.md 缺口 2），因此这里以
//! JSON 为中立载体，并**显式记录解析失败**而不是静默跳过：坏条目进 `invalid`
//! 计数与 `last_error`，界面能呈现「有 N 条环境数据读不出来」，不假装健康。

use serde_json::Value;

/// 单个环境条目：保留原始 JSON 供渲染取用，同时抽出界面必需的 `id`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvEntry {
    /// 环境标识（来自 `id`、`env_id` 或 `uuid` 字段）。
    pub id: String,
    /// 展示名；缺失时为 `None`，由界面决定占位文案。
    pub name: Option<String>,
    /// 原始条目，渲染层按需取字段。
    pub raw: Value,
}

/// 环境视图的整体健康态：界面据此选渲染分支，判定顺序严格 fail-closed。
///
/// 判定次序（先匹配先生效）：加载中 → 有失败记录 → 有不可解析条目 → 就绪。
/// 拿不准时一律往更不健康的方向靠，不假装一切正常。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvStatus {
    /// 正在拉取（或尚未拉取过）。
    Loading,
    /// 就绪：最近一次加载无错误且无坏条目。
    Ready,
    /// 降级：列表可用，但有 N 条环境数据读不出来。
    Degraded,
    /// 失败：最近一次拉取或整体格式解析失败。
    Failed,
}

/// 环境列表视图状态。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvListViewState {
    entries: Vec<EnvEntry>,
    /// 无法解析的条目个数（fail-closed 的可见性）。
    invalid: usize,
    selected: Option<String>,
    loading: bool,
    last_error: Option<String>,
}

impl EnvListViewState {
    /// 空列表：尚未拉取，或权威结果就是零条。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前条目，按网关返回顺序。
    #[must_use]
    pub fn entries(&self) -> &[EnvEntry] {
        &self.entries
    }

    /// 解析失败的条目数。
    #[must_use]
    pub fn invalid_count(&self) -> usize {
        self.invalid
    }

    /// 选中的环境 id。
    #[must_use]
    pub fn selected(&self) -> Option<&str> {
        self.selected.as_deref()
    }

    /// 视图健康态（单点判定，避免界面各处重复拼 loading/error/invalid）。
    #[must_use]
    pub fn status(&self) -> EnvStatus {
        if self.loading {
            return EnvStatus::Loading;
        }
        if self.last_error.is_some() {
            // 有坏条目（其余条目仍可用）算降级；整体解不出来才是失败。
            return if self.invalid > 0 {
                EnvStatus::Degraded
            } else {
                EnvStatus::Failed
            };
        }
        if self.invalid > 0 {
            return EnvStatus::Degraded;
        }
        EnvStatus::Ready
    }

    /// 是否正在拉取。
    #[must_use]
    pub fn is_loading(&self) -> bool {
        self.loading
    }

    /// 最近一次错误。
    #[must_use]
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// 标为加载中，清空上一次错误（保留旧列表，避免界面闪烁成空）。
    pub fn begin_load(&mut self) {
        self.loading = true;
        self.last_error = None;
    }

    /// 用 `config:get` 的 `data` 整体替换列表，并结算加载状态。
    ///
    /// 接受三种形态：数组本身、`{"environments": [...]}`、`{"data": [...]}`；
    /// 其余形态记为错误。条目缺 `id` 时不猜，计入 `invalid`。
    pub fn finish_load(&mut self, data: Option<Value>) {
        self.loading = false;
        self.entries.clear();
        self.invalid = 0;

        let Some(data) = data else {
            self.last_error = None;
            return;
        };
        let items = match extract_items(&data) {
            Some(items) => items,
            None => {
                self.last_error = Some("环境列表格式无法识别".to_owned());
                return;
            }
        };

        for item in items {
            match entry_from_value(&item) {
                Some(entry) => self.entries.push(entry),
                None => self.invalid += 1,
            }
        }
        if self.invalid > 0 {
            self.last_error = Some(format!("{} 条环境数据缺少标识，已跳过", self.invalid));
        } else {
            self.last_error = None;
        }
        // 选中项已不在列表里就清除，界面不显示幽灵选中。
        if let Some(sel) = &self.selected {
            if !self.entries.iter().any(|e| &e.id == sel) {
                self.selected = None;
            }
        }
    }

    /// 记录一次拉取失败（RPC 或解析错误），列表维持原状。
    pub fn record_error(&mut self, error: impl Into<String>) {
        self.loading = false;
        self.last_error = Some(error.into());
    }

    /// 选中环境；传 `None` 取消选中。选中不存在的 id 会被拒绝并记错。
    pub fn select(&mut self, id: Option<&str>) -> Result<(), String> {
        match id {
            None => {
                self.selected = None;
                Ok(())
            }
            Some(id) => {
                if self.entries.iter().any(|e| e.id == id) {
                    self.selected = Some(id.to_owned());
                    Ok(())
                } else {
                    let msg = format!("环境 {id} 不在列表中");
                    self.last_error = Some(msg.clone());
                    Err(msg)
                }
            }
        }
    }

    /// 把 `data` 数组整体当作错误呈现（例如网关返回 403）。
    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

/// 从 `config:get` 的 data 里取出条目数组。
fn extract_items(data: &Value) -> Option<Vec<Value>> {
    match data {
        Value::Array(items) => Some(items.clone()),
        Value::Object(map) => {
            for key in ["environments", "envs", "list", "data", "items"] {
                if let Some(Value::Array(items)) = map.get(key) {
                    return Some(items.clone());
                }
            }
            None
        }
        _ => None,
    }
}

/// 解析单条目；缺可识别标识即返回 `None`。
fn entry_from_value(value: &Value) -> Option<EnvEntry> {
    let map = value.as_object()?;
    let id = ["id", "env_id", "uuid"]
        .iter()
        .find_map(|k| map.get(*k))
        .and_then(|v| match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        })?;
    if id.is_empty() {
        return None;
    }
    let name = map
        .get("name")
        .or_else(|| map.get("title"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Some(EnvEntry {
        id,
        name,
        raw: value.clone(),
    })
}
