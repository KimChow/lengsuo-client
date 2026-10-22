//! TOML 读取器的标量解析：字符串、转义、整数。

use super::parser::Parser;
use super::{ParseError, Value};

impl Parser {
    pub(super) fn parse_basic_string(&mut self) -> Result<String, ParseError> {
        self.bump();
        let mut out = String::new();
        loop {
            let Some(ch) = self.bump() else {
                return self.err("unterminated string");
            };
            match ch {
                '"' => return Ok(out),
                '\n' => return self.err("unterminated string"),
                '\\' => out.push(self.parse_escape()?),
                other => out.push(other),
            }
        }
    }

    pub(super) fn parse_literal_string(&mut self) -> Result<String, ParseError> {
        self.bump();
        let mut out = String::new();
        loop {
            let Some(ch) = self.bump() else {
                return self.err("unterminated literal string");
            };
            match ch {
                '\'' => return Ok(out),
                '\n' => return self.err("unterminated literal string"),
                other => out.push(other),
            }
        }
    }

    pub(super) fn parse_multiline_basic(&mut self) -> Result<String, ParseError> {
        self.pos += 3;
        self.skip_first_newline();
        let mut out = String::new();
        loop {
            if self.starts_with("\"\"\"") {
                self.pos += 3;
                return Ok(out);
            }
            let Some(ch) = self.bump() else {
                return self.err("unterminated multi-line string");
            };
            if ch == '\\' {
                if self.peek() == Some('\r') || self.peek() == Some('\n') {
                    self.skip_line_ending_backslash();
                    continue;
                }
                out.push(self.parse_escape()?);
            } else {
                out.push(ch);
            }
        }
    }

    pub(super) fn parse_multiline_literal(&mut self) -> Result<String, ParseError> {
        self.pos += 3;
        self.skip_first_newline();
        let mut out = String::new();
        loop {
            if self.starts_with("'''") {
                self.pos += 3;
                return Ok(out);
            }
            let Some(ch) = self.bump() else {
                return self.err("unterminated multi-line literal string");
            };
            out.push(ch);
        }
    }

    pub(super) fn skip_first_newline(&mut self) {
        if self.peek() == Some('\r') {
            self.bump();
        }
        if self.peek() == Some('\n') {
            self.bump();
        }
    }

    /// 行尾反斜杠：吞掉换行与其后的空白（TOML 的续行语义）。
    pub(super) fn skip_line_ending_backslash(&mut self) {
        while matches!(self.peek(), Some(' ') | Some('\t') | Some('\r')) {
            self.bump();
        }
        if self.peek() == Some('\n') {
            self.bump();
        }
        while matches!(
            self.peek(),
            Some(' ') | Some('\t') | Some('\r') | Some('\n')
        ) {
            self.bump();
        }
    }

    pub(super) fn parse_escape(&mut self) -> Result<char, ParseError> {
        let Some(esc) = self.bump() else {
            return self.err("unterminated escape sequence");
        };
        Ok(match esc {
            '"' => '"',
            '\\' => '\\',
            'b' => '\u{8}',
            'f' => '\u{c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'u' => {
                let code = self.parse_hex(4)?;
                char::from_u32(code).ok_or_else(|| ParseError {
                    line: self.line,
                    message: "invalid unicode escape".to_owned(),
                })?
            }
            'U' => {
                let code = self.parse_hex(8)?;
                char::from_u32(code).ok_or_else(|| ParseError {
                    line: self.line,
                    message: "invalid unicode escape".to_owned(),
                })?
            }
            _ => {
                return self.err("invalid escape sequence");
            }
        })
    }

    pub(super) fn parse_hex(&mut self, width: usize) -> Result<u32, ParseError> {
        let mut code = 0_u32;
        for _ in 0..width {
            let Some(ch) = self.bump() else {
                return self.err("truncated unicode escape");
            };
            let Some(digit) = ch.to_digit(16) else {
                return self.err("invalid unicode escape");
            };
            code = code * 16 + digit;
        }
        Ok(code)
    }

    pub(super) fn parse_number(&mut self) -> Result<Value, ParseError> {
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '_' | '.') {
                self.bump();
            } else {
                break;
            }
        }
        let token: String = self.chars[start..self.pos].iter().collect();
        if token.is_empty() {
            return self.err("expected a number");
        }
        if let Some(hex) = token.strip_prefix("0x") {
            return Ok(Value::Int(parse_radix(hex, 16, &token, self.line)? as i64));
        }
        if let Some(oct) = token.strip_prefix("0o") {
            return Ok(Value::Int(parse_radix(oct, 8, &token, self.line)? as i64));
        }
        if let Some(bin) = token.strip_prefix("0b") {
            return Ok(Value::Int(parse_radix(bin, 2, &token, self.line)? as i64));
        }
        let cleaned = strip_underscores(&token);
        if cleaned.contains('.') || cleaned.contains('e') || cleaned.contains('E') {
            return self.err("float values are not supported in this config format");
        }
        cleaned
            .parse::<i64>()
            .map(Value::Int)
            .map_err(|_| ParseError {
                line: self.line,
                message: "invalid integer".to_owned(),
            })
    }
}

fn strip_underscores(token: &str) -> String {
    token.replace('_', "")
}

fn parse_radix(digits: &str, radix: u32, token: &str, line: usize) -> Result<u64, ParseError> {
    let cleaned = strip_underscores(digits);
    if cleaned.is_empty() {
        return Err(ParseError {
            line,
            message: "invalid integer".to_owned(),
        });
    }
    u64::from_str_radix(&cleaned, radix).map_err(|_| ParseError {
        line,
        message: format!("invalid integer `{token}`"),
    })
}
