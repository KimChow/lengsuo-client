//! TOML 读取器的文档级解析：表头、键路径、数组、内联表。
//!
//! 标量（字符串 / 整数 / 布尔）的解析在 `super::scalar`。

use std::collections::BTreeMap;

use super::{ParseError, Value};

/// TOML 读取器。逐字符推进，跟踪行号（错误只报行号，不报源行）。
pub(super) struct Parser {
    pub(super) chars: Vec<char>,
    pub(super) pos: usize,
    pub(super) line: usize,
}

impl Parser {
    pub(super) fn new(text: &str) -> Self {
        Self {
            chars: text.chars().collect(),
            pos: 0,
            line: 1,
        }
    }

    pub(super) fn err<T>(&self, message: impl Into<String>) -> Result<T, ParseError> {
        Err(ParseError {
            line: self.line,
            message: message.into(),
        })
    }

    pub(super) fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    pub(super) fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    pub(super) fn bump(&mut self) -> Option<char> {
        let ch = self.chars.get(self.pos).copied();
        if let Some(value) = ch {
            self.pos += 1;
            if value == '\n' {
                self.line += 1;
            }
        }
        ch
    }

    pub(super) fn starts_with(&self, prefix: &str) -> bool {
        prefix
            .chars()
            .enumerate()
            .all(|(offset, ch)| self.peek_at(offset) == Some(ch))
    }

    /// 跳过行内空白（空格 / 制表）。
    pub(super) fn skip_inline_ws(&mut self) {
        while matches!(self.peek(), Some(' ') | Some('\t')) {
            self.bump();
        }
    }

    pub(super) fn skip_comment(&mut self) {
        if self.peek() == Some('#') {
            while !matches!(self.peek(), None | Some('\n')) {
                self.bump();
            }
        }
    }

    /// 跳过空白、换行与注释（数组内部与表头之间用）。
    pub(super) fn skip_trivia(&mut self) {
        loop {
            match self.peek() {
                Some(' ') | Some('\t') | Some('\r') | Some('\n') => {
                    self.bump();
                }
                Some('#') => self.skip_comment(),
                _ => break,
            }
        }
    }

    /// 解析整份文档。
    pub(super) fn parse_document(&mut self) -> Result<BTreeMap<String, Value>, ParseError> {
        let mut root: BTreeMap<String, Value> = BTreeMap::new();
        let mut current: Vec<String> = Vec::new();
        let mut seen_tables: Vec<Vec<String>> = Vec::new();

        loop {
            self.skip_trivia();
            if self.peek().is_none() {
                break;
            }
            if self.peek() == Some('[') {
                self.bump();
                let is_array = self.peek() == Some('[');
                if is_array {
                    self.bump();
                }
                let path = self.parse_key_path()?;
                self.skip_inline_ws();
                if self.peek() != Some(']') {
                    return self.err("expected `]` to close table header");
                }
                self.bump();
                if is_array {
                    if self.peek() != Some(']') {
                        return self.err("expected `]]` to close array-of-tables header");
                    }
                    self.bump();
                    push_array_table(&mut root, &path, self.line)?;
                } else {
                    if seen_tables.contains(&path) {
                        return self.err("duplicate table header");
                    }
                    seen_tables.push(path.clone());
                    ensure_table(&mut root, &path, self.line)?;
                }
                current = path;
                continue;
            }

            let path = self.parse_key_path()?;
            self.skip_inline_ws();
            if self.peek() != Some('=') {
                return self.err("expected `=` after key");
            }
            self.bump();
            self.skip_inline_ws();
            let value = self.parse_value()?;
            let table = ensure_table(&mut root, &current, self.line)?;
            let (last, parents) = path.split_last().expect("key path is never empty");
            let parent = if parents.is_empty() {
                table
            } else {
                ensure_table(table, parents, self.line)?
            };
            if parent.contains_key(last) {
                return self.err("duplicate key");
            }
            parent.insert(last.clone(), value);
        }
        Ok(root)
    }

    fn parse_key_path(&mut self) -> Result<Vec<String>, ParseError> {
        let mut path = Vec::new();
        loop {
            self.skip_inline_ws();
            path.push(self.parse_key()?);
            self.skip_inline_ws();
            if self.peek() == Some('.') {
                self.bump();
                continue;
            }
            break;
        }
        Ok(path)
    }

    fn parse_key(&mut self) -> Result<String, ParseError> {
        match self.peek() {
            Some('"') => self.parse_basic_string(),
            Some('\'') => self.parse_literal_string(),
            Some(ch) if is_bare_key_char(ch) => {
                let mut out = String::new();
                while let Some(ch) = self.peek() {
                    if is_bare_key_char(ch) {
                        out.push(ch);
                        self.bump();
                    } else {
                        break;
                    }
                }
                Ok(out)
            }
            _ => self.err("expected a key"),
        }
    }

    fn parse_value(&mut self) -> Result<Value, ParseError> {
        match self.peek() {
            Some('"') if self.starts_with("\"\"\"") => self.parse_multiline_basic().map(Value::Str),
            Some('\'') if self.starts_with("'''") => self.parse_multiline_literal().map(Value::Str),
            Some('"') => self.parse_basic_string().map(Value::Str),
            Some('\'') => self.parse_literal_string().map(Value::Str),
            Some('[') => self.parse_array(),
            Some('{') => self.parse_inline_table(),
            Some('t') if self.starts_with("true") => {
                self.pos += 4;
                Ok(Value::Bool(true))
            }
            Some('f') if self.starts_with("false") => {
                self.pos += 5;
                Ok(Value::Bool(false))
            }
            Some(ch) if ch.is_ascii_digit() || ch == '+' || ch == '-' => self.parse_number(),
            _ => self.err("expected a value"),
        }
    }

    fn parse_array(&mut self) -> Result<Value, ParseError> {
        self.bump();
        let mut items = Vec::new();
        loop {
            self.skip_trivia();
            if self.peek() == Some(']') {
                self.bump();
                return Ok(Value::Array(items));
            }
            if self.peek().is_none() {
                return self.err("unterminated array");
            }
            items.push(self.parse_value()?);
            self.skip_trivia();
            match self.peek() {
                Some(',') => {
                    self.bump();
                }
                Some(']') => {
                    self.bump();
                    return Ok(Value::Array(items));
                }
                _ => return self.err("expected `,` or `]` in array"),
            }
        }
    }

    fn parse_inline_table(&mut self) -> Result<Value, ParseError> {
        self.bump();
        let mut entries = BTreeMap::new();
        loop {
            self.skip_inline_ws();
            if self.peek() == Some('}') {
                self.bump();
                return Ok(Value::Table(entries));
            }
            if self.peek().is_none() {
                return self.err("unterminated inline table");
            }
            let path = self.parse_key_path()?;
            self.skip_inline_ws();
            if self.peek() != Some('=') {
                return self.err("expected `=` after key");
            }
            self.bump();
            self.skip_inline_ws();
            let value = self.parse_value()?;
            let (last, parents) = path.split_last().expect("key path is never empty");
            let parent = if parents.is_empty() {
                &mut entries
            } else {
                ensure_table(&mut entries, parents, self.line)?
            };
            if parent.contains_key(last) {
                return self.err("duplicate key");
            }
            parent.insert(last.clone(), value);
            self.skip_inline_ws();
            match self.peek() {
                Some(',') => {
                    self.bump();
                }
                Some('}') => {
                    self.bump();
                    return Ok(Value::Table(entries));
                }
                _ => return self.err("expected `,` or `}` in inline table"),
            }
        }
    }
}

fn is_bare_key_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'
}

/// 定位（或创建）`path` 对应的表。
///
/// 路径中途若是表数组，按 TOML 语义进入**最后一个**表数组元素。
fn ensure_table<'a>(
    root: &'a mut BTreeMap<String, Value>,
    path: &[String],
    line: usize,
) -> Result<&'a mut BTreeMap<String, Value>, ParseError> {
    let mut cursor = root;
    for key in path {
        let entry = cursor
            .entry(key.clone())
            .or_insert_with(|| Value::Table(BTreeMap::new()));
        cursor = match entry {
            Value::Table(inner) => inner,
            Value::Array(items) => match items.last_mut() {
                Some(Value::Table(inner)) => inner,
                _ => {
                    return Err(ParseError {
                        line,
                        message: format!("`{key}` is not a table"),
                    })
                }
            },
            _ => {
                return Err(ParseError {
                    line,
                    message: format!("`{key}` is not a table"),
                })
            }
        };
    }
    Ok(cursor)
}

/// 处理 `[[a.b]]`：在 `a.b` 处追加一张新表。
fn push_array_table(
    root: &mut BTreeMap<String, Value>,
    path: &[String],
    line: usize,
) -> Result<(), ParseError> {
    let Some((last, parents)) = path.split_last() else {
        return Err(ParseError {
            line,
            message: "empty array-of-tables header".to_owned(),
        });
    };
    let parent = ensure_table(root, parents, line)?;
    let entry = parent
        .entry(last.clone())
        .or_insert_with(|| Value::Array(Vec::new()));
    match entry {
        Value::Array(items) => {
            items.push(Value::Table(BTreeMap::new()));
            Ok(())
        }
        _ => Err(ParseError {
            line,
            message: format!("`{last}` is not an array of tables"),
        }),
    }
}
