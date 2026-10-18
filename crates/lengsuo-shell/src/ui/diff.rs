//! 行级 diff：自写 LCS 简版（纯逻辑，不依赖 gpui，不新增外部 crate）。
//!
//! 语义约定（对照 参照平台 D4 的红绿行呈现）：
//! - 输出按“先删除（红）后新增（绿）”的分块顺序，与 git 的并排阅读习惯一致。
//! - 行尾换行不构成额外空行：`"a\n"` 与 `"a"` 视为同一份内容。
//! - `\r` 统一剥离，避免 CRLF 文件渲染出看不见的差异。
//! - 规模保护：LCS 是 O(n·m) 时空。超过 [`MAX_LCS_CELLS`] 时**不失败也不截断**，
//!   而是退化为「整段旧内容标红 + 整段新内容标绿」——仍然是正确（只是非最小）的 diff，
//!   并通过 [`Diff::minimal`] 如实告知调用方。

/// 单行的差异类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffKind {
    /// 两侧相同（不上色）。
    Equal,
    /// 只在旧侧存在（红）。
    Removed,
    /// 只在新侧存在（绿）。
    Added,
}

/// 一行 diff 结果，携带两侧的行号（1 起，供 UI 显示 `12 → —`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    /// 差异类别。
    pub kind: DiffKind,
    /// 行文本（不含行尾换行）。
    pub text: String,
    /// 旧文件行号；`Added` 为 `None`。
    pub old_line: Option<u32>,
    /// 新文件行号；`Removed` 为 `None`。
    pub new_line: Option<u32>,
}

/// 一次 diff 的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diff {
    /// 顺序渲染的行。
    pub lines: Vec<DiffLine>,
    /// 是否为最小 LCS 结果（`false` 表示触发规模保护后的整段替换呈现）。
    pub minimal: bool,
}

// 阶段二 GPUI 渲染层消费（summary 徽标）；逻辑与测试已先行冻结。
#[allow(dead_code)]
impl Diff {
    /// 新增行数。
    #[must_use]
    pub fn added(&self) -> usize {
        self.count(DiffKind::Added)
    }

    /// 删除行数。
    #[must_use]
    pub fn removed(&self) -> usize {
        self.count(DiffKind::Removed)
    }

    /// 变更行合计（红 + 绿）。
    #[must_use]
    pub fn changed(&self) -> usize {
        self.added() + self.removed()
    }

    fn count(&self, kind: DiffKind) -> usize {
        self.lines.iter().filter(|l| l.kind == kind).count()
    }

    /// `+n / -m` 形态的摘要文本（工具卡片折叠态用）。
    #[must_use]
    pub fn summary(&self) -> String {
        format!("+{} -{}", self.added(), self.removed())
    }
}

/// LCS 动态表的最大格子数（约 4M 单元格 ≈ 16MB `u32`）。
pub const MAX_LCS_CELLS: usize = 4_000_000;

/// 按 `\n` 切行；去掉尾部空段（即末尾换行不算一行），并剥离行尾 `\r`。
fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<&str> = text.split('\n').collect();
    if lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    for line in lines.iter_mut() {
        *line = line.strip_suffix('\r').unwrap_or(line);
    }
    lines
}

/// 计算两个文本的行级 diff。
pub fn diff(old: &str, new: &str) -> Diff {
    let (o, n) = (split_lines(old), split_lines(new));
    // 规模保护：行数乘积超限直接整段替换。
    if o.len().saturating_mul(n.len()) > MAX_LCS_CELLS {
        return Diff {
            lines: block_replace(&o, &n),
            minimal: false,
        };
    }
    let matched = lcs_lines(&o, &n);
    Diff {
        lines: group_changes(matched),
        minimal: true,
    }
}

/// 便捷入口：只要行列表时用它。
pub fn diff_lines(old: &str, new: &str) -> Vec<DiffLine> {
    diff(old, new).lines
}

/// 整段替换（删除全部旧行 + 新增全部新行），行号连续。
fn block_replace<'a>(old: &[&'a str], new: &[&'a str]) -> Vec<DiffLine> {
    let mut lines = Vec::with_capacity(old.len() + new.len());
    lines.extend(old.iter().enumerate().map(|(i, t)| DiffLine {
        kind: DiffKind::Removed,
        text: (*t).to_string(),
        old_line: Some(i as u32 + 1),
        new_line: None,
    }));
    lines.extend(new.iter().enumerate().map(|(i, t)| DiffLine {
        kind: DiffKind::Added,
        text: (*t).to_string(),
        old_line: None,
        new_line: Some(i as u32 + 1),
    }));
    lines
}

/// LCS 匹配：返回按顺序对齐的行序列（未分块整理）。
fn lcs_lines(old: &[&str], new: &[&str]) -> Vec<DiffLine> {
    let (m, n) = (old.len(), new.len());
    // dp[i][j] = old[..i] 与 new[..j] 的 LCS 长度。用一维滚动表回溯需要完整表，
    // 这里保留二维表（单元格数已在 `diff` 里限过）。
    let width = n + 1;
    let mut dp = vec![0u32; (m + 1) * width];
    for i in 1..=m {
        for j in 1..=n {
            dp[i * width + j] = if old[i - 1] == new[j - 1] {
                dp[(i - 1) * width + (j - 1)] + 1
            } else {
                dp[(i - 1) * width + j].max(dp[i * width + (j - 1)])
            };
        }
    }
    // 自后向前回溯。
    let mut out: Vec<DiffLine> = Vec::with_capacity(m + n);
    let (mut i, mut j) = (m, n);
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && old[i - 1] == new[j - 1] {
            out.push(DiffLine {
                kind: DiffKind::Equal,
                text: old[i - 1].to_string(),
                old_line: Some(i as u32),
                new_line: Some(j as u32),
            });
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || dp[(i - 1) * width + (j - 1)] < dp[i * width + (j - 1)]) {
            out.push(DiffLine {
                kind: DiffKind::Added,
                text: new[j - 1].to_string(),
                old_line: None,
                new_line: Some(j as u32),
            });
            j -= 1;
        } else {
            out.push(DiffLine {
                kind: DiffKind::Removed,
                text: old[i - 1].to_string(),
                old_line: Some(i as u32),
                new_line: None,
            });
            i -= 1;
        }
    }
    out.reverse();
    out
}

/// 把交错的变更行整理为「同块内红行在前、绿行在后」，等号行原样保留位置。
fn group_changes(lines: Vec<DiffLine>) -> Vec<DiffLine> {
    let mut out = Vec::with_capacity(lines.len());
    let mut removed: Vec<DiffLine> = Vec::new();
    let mut added: Vec<DiffLine> = Vec::new();
    for line in lines {
        match line.kind {
            DiffKind::Equal => {
                flush(&mut removed, &mut added, &mut out);
                out.push(line);
            }
            DiffKind::Removed => removed.push(line),
            DiffKind::Added => added.push(line),
        }
    }
    flush(&mut removed, &mut added, &mut out);
    out
}

fn flush(removed: &mut Vec<DiffLine>, added: &mut Vec<DiffLine>, out: &mut Vec<DiffLine>) {
    out.append(removed);
    out.append(added);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(lines: &[DiffLine]) -> Vec<DiffKind> {
        lines.iter().map(|l| l.kind).collect()
    }

    fn text_of(lines: &[DiffLine]) -> Vec<(DiffKind, String)> {
        lines.iter().map(|l| (l.kind, l.text.clone())).collect()
    }

    #[test]
    fn identical_text_is_all_equal() {
        let d = diff("a\nb\nc\n", "a\nb\nc\n");
        assert!(d.minimal);
        assert_eq!(d.lines.len(), 3);
        assert!(kinds(&d.lines).iter().all(|k| *k == DiffKind::Equal));
        assert_eq!(d.changed(), 0);
        assert_eq!(d.summary(), "+0 -0");
    }

    #[test]
    fn trailing_newline_does_not_create_a_line() {
        assert_eq!(split_lines("a\n"), vec!["a"]);
        assert_eq!(split_lines("a"), vec!["a"]);
        assert_eq!(split_lines(""), Vec::<&str>::new());
        assert_eq!(split_lines("a\nb\n"), vec!["a", "b"]);
        assert_eq!(split_lines("a\r\nb\r\n"), vec!["a", "b"]);
        // 空行仍然是行（只是文本为空）。
        assert_eq!(split_lines("a\n\nb"), vec!["a", "", "b"]);
        let d = diff("a\n", "a");
        assert_eq!(d.changed(), 0, "尾部换行差异不算变更");
    }

    #[test]
    fn one_changed_line_yields_minus_then_plus() {
        let d = diff("a\nb\nc\n", "a\nB\nc\n");
        assert_eq!(
            text_of(&d.lines),
            vec![
                (DiffKind::Equal, "a".into()),
                (DiffKind::Removed, "b".into()),
                (DiffKind::Added, "B".into()),
                (DiffKind::Equal, "c".into()),
            ]
        );
        assert_eq!((d.removed(), d.added()), (1, 1));
        assert_eq!(d.summary(), "+1 -1");
    }

    #[test]
    fn insert_and_delete_only_side_has_line_number() {
        let d = diff("a\nc\n", "a\nb\nc\n");
        assert_eq!(d.lines.len(), 3);
        let added = d
            .lines
            .iter()
            .find(|l| l.kind == DiffKind::Added)
            .expect("应有新增行");
        assert_eq!((added.old_line, added.new_line), (None, Some(2)));
        let equal = d.lines.iter().find(|l| l.text == "c").expect("c 行存在");
        assert_eq!((equal.old_line, equal.new_line), (Some(2), Some(3)));

        let d = diff("a\nb\nc\n", "a\nc\n");
        let removed = d
            .lines
            .iter()
            .find(|l| l.kind == DiffKind::Removed)
            .expect("应有删除行");
        assert_eq!((removed.old_line, removed.new_line), (Some(2), None));
    }

    #[test]
    fn empty_sides_are_pure_add_or_remove() {
        let d = diff("", "x\ny\n");
        assert_eq!(kinds(&d.lines), vec![DiffKind::Added, DiffKind::Added]);
        assert_eq!((d.removed(), d.added()), (0, 2));
        let d = diff("x\ny\n", "");
        assert_eq!(kinds(&d.lines), vec![DiffKind::Removed, DiffKind::Removed]);
        assert_eq!((d.removed(), d.added()), (2, 0));
        let d = diff("", "");
        assert!(d.lines.is_empty());
    }

    #[test]
    fn lcs_picks_longest_match_not_greedy_first_line() {
        // 旧：a b c，新：a x c。最小 diff 只应改中间一行。
        let d = diff("a\nb\nc\n", "a\nx\nc\n");
        assert_eq!(d.changed(), 2, "应只有一红一绿：{:?}", text_of(&d.lines));
        assert_eq!(
            d.lines.iter().filter(|l| l.kind == DiffKind::Equal).count(),
            2
        );
    }

    #[test]
    fn repeated_lines_stay_reversible_and_consistent() {
        // 两侧行序列可由结果重建（Equal/Removed 拼回旧，Equal/Added 拼回新）。
        for (o, n) in [
            ("a\nb\na\n", "a\na\n"),
            ("x\nx\nx\n", "x\ny\nx\n"),
            ("1\n2\n3\n4\n", "2\n4\n5\n"),
        ] {
            let d = diff(o, n);
            let old_rebuilt: Vec<&str> = d
                .lines
                .iter()
                .filter(|l| l.kind != DiffKind::Added)
                .map(|l| l.text.as_str())
                .collect();
            let new_rebuilt: Vec<&str> = d
                .lines
                .iter()
                .filter(|l| l.kind != DiffKind::Removed)
                .map(|l| l.text.as_str())
                .collect();
            assert_eq!(old_rebuilt, split_lines(o), "{o:?} 旧侧重建失败");
            assert_eq!(new_rebuilt, split_lines(n), "{n:?} 新侧重建失败");
        }
    }

    #[test]
    fn oversized_input_degrades_to_block_replace_but_stays_correct() {
        let old = "a\n".repeat(3000);
        let new = "b\n".repeat(3000);
        // 3000×3000 = 9e6 > 4e6，触发规模保护。
        let d = diff(&old, &new);
        assert!(!d.minimal, "超规模应标记非最小结果");
        assert_eq!(d.removed(), 3000);
        assert_eq!(d.added(), 3000);
        assert_eq!(
            kinds(&d.lines)
                .iter()
                .take(3000)
                .filter(|k| **k == DiffKind::Removed)
                .count(),
            3000,
            "红行应全部在前"
        );
        assert_eq!(d.lines[3000].new_line, Some(1));
        assert_eq!(d.lines[2999].old_line, Some(3000));
    }

    #[test]
    fn change_block_is_grouped_minus_before_plus() {
        let d = diff("a\nb\nc\nd\n", "a\nX\nY\nd\n");
        let texts = text_of(&d.lines);
        assert_eq!(
            texts,
            vec![
                (DiffKind::Equal, "a".into()),
                (DiffKind::Removed, "b".into()),
                (DiffKind::Removed, "c".into()),
                (DiffKind::Added, "X".into()),
                (DiffKind::Added, "Y".into()),
                (DiffKind::Equal, "d".into()),
            ]
        );
    }

    #[test]
    fn summary_counts_are_right() {
        let d = diff("a\nb\nc\n", "a\nB\nD\nc\ne\n");
        // LCS 最小语义：b→B 为替换（-1+1），另新增 D、e ⇒ 删 1 增 3。
        assert_eq!((d.removed(), d.added(), d.changed()), (1, 3, 4));
        assert_eq!(d.summary(), "+3 -1");
    }
}
