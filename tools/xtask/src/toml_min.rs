//! toml_min —— 受约束 TOML 子集解析器（xtask 内建，零外部依赖）。
//!
//! 本仓 workspace 十八包零外部依赖（Cargo.lock 全内部包，离线可构建）是既定
//! 纪律；xtask 引入 `toml`/`serde` 会破坏该属性。IDL 契约（M24-M2）与 lint
//! 台账（M24-X1）的 schema 由本仓自定义，Cargo.toml 的消费面又极窄，故内建
//! 一个严格报错的子集解析器（~300 行）是纪律内的最优解。
//!
//! 语法面（超出即报错，不做静默容忍）：
//! - `[a.b.c]` 节头与 `[[a.b]]` 表数组节头（点分路径）；
//! - 裸键 + 点分键赋值（`k = v`、`k.sub = v`）；
//! - 值：基本字符串（五转义）、整数（十进制/0x 十六进制/下划线分隔）、
//!   布尔、数组（可跨行/尾逗号）、内联表（可尾逗号）；
//! - `#` 行注释。
//!
//! 明确不支持（报错）：多行字符串、字面量字符串（'…'）、日期时间、
//! `\uXXXX` 转义——仓内三处消费面（idl/*.toml、allowlist.toml、各 crate
//! Cargo.toml）均不使用。

use std::fmt;

/// 解析错误：行号（1 起）+ 消息。
#[derive(Debug, Clone)]
pub struct ParseError {
    /// 错误所在行（1 起）。
    pub line: usize,
    /// 错误描述。
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

/// TOML 值（本解析器支持的子集）。
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// 基本字符串。
    Str(String),
    /// 整数（i64）。
    Int(i64),
    /// 布尔。
    Bool(bool),
    /// 数组（元素可异构，消费面自行校验）。
    Array(Vec<Value>),
    /// 表（保持出现序）。
    Table(Table),
}

/// 表：键值对的有序序列（小表线性查找即可）。
pub type Table = Vec<(String, Value)>;

// ---------------------------------------------------------------- 查找助手

/// 取键对应值（Table 为类型别名，用自由函数而非 inherent impl）。
pub fn table_get<'a>(t: &'a Table, key: &str) -> Option<&'a Value> {
    t.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// 取子表（值必须为 Table）。
pub fn get_table<'a>(t: &'a Table, key: &str) -> Option<&'a Table> {
    match table_get(t, key) {
        Some(Value::Table(inner)) => Some(inner),
        _ => None,
    }
}

/// 取字符串值。
pub fn get_str<'a>(t: &'a Table, key: &str) -> Option<&'a str> {
    match table_get(t, key) {
        Some(Value::Str(s)) => Some(s.as_str()),
        _ => None,
    }
}

/// 取整数值。
pub fn get_int(t: &Table, key: &str) -> Option<i64> {
    match table_get(t, key) {
        Some(Value::Int(i)) => Some(*i),
        _ => None,
    }
}

/// 取布尔值。
pub fn get_bool(t: &Table, key: &str) -> Option<bool> {
    match table_get(t, key) {
        Some(Value::Bool(b)) => Some(*b),
        _ => None,
    }
}

/// 取数组值。
pub fn get_array<'a>(t: &'a Table, key: &str) -> Option<&'a [Value]> {
    match table_get(t, key) {
        Some(Value::Array(a)) => Some(a.as_slice()),
        _ => None,
    }
}

/// 取表数组值（`[[x]]` 产物：元素全为 Table；混入非表元素即 None）。
pub fn get_table_array<'a>(t: &'a Table, key: &str) -> Option<Vec<&'a Table>> {
    let arr = match table_get(t, key) {
        Some(Value::Array(a)) => a,
        _ => return None,
    };
    let mut tables = Vec::with_capacity(arr.len());
    for v in arr {
        match v {
            Value::Table(t) => tables.push(t),
            _ => return None,
        }
    }
    Some(tables)
}

// ---------------------------------------------------------------- 解析器

/// 当前节定位：根 / `[a.b]` 路径 / `[[a]]` 数组元素（路径 + 下标）。
enum Cur {
    Root,
    Section(Vec<String>),
    ArrayElem(Vec<String>, usize),
}

struct Parser<'a> {
    chars: &'a [char],
    pos: usize,
    line: usize,
}

/// 解析入口：整个输入必须消费完（尾部仅注释/空白）。
pub fn parse(input: &str) -> Result<Table, ParseError> {
    let chars: Vec<char> = input.chars().collect();
    let mut p = Parser {
        chars: &chars,
        pos: 0,
        line: 1,
    };
    let mut root: Table = Vec::new();
    let mut defined_sections: Vec<String> = Vec::new();
    let mut cur = Cur::Root;
    loop {
        p.skip_blank();
        if p.eof() {
            break;
        }
        if p.peek() == '[' {
            let is_array = p.chars.get(p.pos + 1) == Some(&'[');
            p.bump();
            if is_array {
                p.bump();
            }
            let path = p.parse_key_path()?;
            p.skip_inline_ws();
            p.expect(']')?;
            if is_array {
                p.expect(']')?;
            }
            p.end_of_line()?;
            let canon = path.join("\u{1}");
            if !is_array {
                if defined_sections.contains(&canon) {
                    return Err(p.err(format!("节 [{}] 重复定义", path.join("."))));
                }
                defined_sections.push(canon.clone());
            }
            if is_array {
                // 表数组：追加新元素并以之为当前节。
                let idx = push_array_table(&mut root, &path, &p)?;
                cur = Cur::ArrayElem(path, idx);
            } else {
                // 节：冲突检测（父路径若为数组元素地址则报错——本子集不支持）。
                let exists = probe_table(&root, &path);
                if exists {
                    return Err(p.err(format!("节 [{}] 与既有键冲突", path.join("."))));
                }
                cur = Cur::Section(path);
            }
        } else {
            // 键赋值（点分键展开为嵌套表）。
            let path = p.parse_key_path()?;
            p.skip_inline_ws();
            p.expect('=')?;
            p.skip_inline_ws();
            let value = p.parse_value()?;
            p.end_of_line()?;
            let (stem, leaf) = path.split_at(path.len() - 1);
            let host = cur_table_mut(&mut root, &cur, stem, &p)?;
            if host.iter().any(|(k, _)| *k == leaf[0]) {
                return Err(p.err(format!("键 {} 重复定义", leaf[0])));
            }
            host.push((leaf[0].clone(), value));
        }
    }
    Ok(root)
}

impl<'a> Parser<'a> {
    fn eof(&self) -> bool {
        self.pos >= self.chars.len()
    }

    fn peek(&self) -> char {
        self.chars[self.pos]
    }

    fn bump(&mut self) -> char {
        let c = self.chars[self.pos];
        self.pos += 1;
        if c == '\n' {
            self.line += 1;
        }
        c
    }

    fn err(&self, message: String) -> ParseError {
        ParseError {
            line: self.line,
            message,
        }
    }

    /// 跳过空白、注释与换行（跨行定位下一有效 token）。
    fn skip_blank(&mut self) {
        while !self.eof() {
            match self.peek() {
                ' ' | '\t' | '\r' | '\n' => {
                    self.bump();
                }
                '#' => {
                    while !self.eof() && self.peek() != '\n' {
                        self.pos += 1;
                    }
                }
                _ => break,
            }
        }
    }

    /// 跳过行内空白。
    fn skip_inline_ws(&mut self) {
        while !self.eof() && matches!(self.peek(), ' ' | '\t' | '\r') {
            self.pos += 1;
        }
    }

    /// 行尾校验：注释或换行或 EOF，其余报错。
    fn end_of_line(&mut self) -> Result<(), ParseError> {
        self.skip_inline_ws();
        match self.eof() {
            true => Ok(()),
            false => match self.peek() {
                '\n' => {
                    self.bump();
                    Ok(())
                }
                '#' => {
                    while !self.eof() && self.peek() != '\n' {
                        self.pos += 1;
                    }
                    Ok(())
                }
                other => Err(self.err(format!("行尾出现意外字符 {other:?}"))),
            },
        }
    }

    fn expect(&mut self, want: char) -> Result<(), ParseError> {
        match self.eof() {
            true => Err(self.err(format!("期望 {want:?}，输入提前结束"))),
            false if self.peek() == want => {
                self.bump();
                Ok(())
            }
            false => Err(self.err(format!("期望 {want:?}，实得 {:?}", self.peek()))),
        }
    }

    /// 裸键点分路径（`a.b.c`，允许键内 `-`/`_`）。
    fn parse_key_path(&mut self) -> Result<Vec<String>, ParseError> {
        let mut path = Vec::new();
        loop {
            self.skip_inline_ws();
            let mut key = String::new();
            if self.eof() {
                return Err(self.err("键名缺失".into()));
            }
            while !self.eof()
                && (self.peek().is_ascii_alphanumeric() || self.peek() == '_' || self.peek() == '-')
            {
                key.push(self.bump());
            }
            if key.is_empty() {
                return Err(self.err(format!("非法键名起点 {:?}", self.peek())));
            }
            path.push(key);
            self.skip_inline_ws();
            if self.eof() {
                break;
            }
            if self.peek() == '.' {
                self.bump();
            } else {
                break;
            }
        }
        Ok(path)
    }

    fn parse_value(&mut self) -> Result<Value, ParseError> {
        if self.eof() {
            return Err(self.err("值缺失".into()));
        }
        match self.peek() {
            '"' => self.parse_string().map(Value::Str),
            't' => self.parse_literal("true", true).map(Value::Bool),
            'f' => self.parse_literal("false", false).map(Value::Bool),
            '[' => self.parse_array(),
            '{' => self.parse_inline_table(),
            c if c == '-' || c.is_ascii_digit() => self.parse_number(),
            other => Err(self.err(format!("非法值起点 {other:?}"))),
        }
    }

    /// 基本字符串（五转义；不支持 \uXXXX 与跨行）。
    fn parse_string(&mut self) -> Result<String, ParseError> {
        self.expect('"')?;
        let mut out = String::new();
        loop {
            if self.eof() {
                return Err(self.err("字符串未闭合".into()));
            }
            match self.peek() {
                '"' => {
                    self.bump();
                    return Ok(out);
                }
                '\n' => return Err(self.err("字符串内出现裸换行（不支持多行字符串）".into())),
                '\\' => {
                    self.bump();
                    let esc = match self.eof() {
                        true => return Err(self.err("转义序列截断".into())),
                        false => self.bump(),
                    };
                    match esc {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        'r' => out.push('\r'),
                        other => {
                            return Err(self.err(format!(
                                "不支持的转义 \\{other}（仅 \\\" \\\\ \\n \\t \\r）"
                            )))
                        }
                    }
                }
                _ => out.push(self.bump()),
            }
        }
    }

    /// 字面量（true/false），并要求词边界。
    fn parse_literal(&mut self, word: &str, val: bool) -> Result<bool, ParseError> {
        for want in word.chars() {
            if self.eof() {
                return Err(self.err(format!("字面量 {word} 截断")));
            }
            if self.peek() != want {
                return Err(self.err(format!("非法字面量（期望 {word}）")));
            }
            self.bump();
        }
        match self.eof() {
            true => Ok(val),
            false => match self.peek() {
                c if c.is_ascii_alphanumeric() || c == '_' => {
                    Err(self.err(format!("非法字面量（期望 {word}）")))
                }
                _ => Ok(val),
            },
        }
    }

    /// 整数：十进制 / 0x 十六进制 / 下划线分隔。
    fn parse_number(&mut self) -> Result<Value, ParseError> {
        let mut text = String::new();
        if self.peek() == '-' {
            text.push(self.bump());
        }
        if self.chars.get(self.pos) == Some(&'0') && self.chars.get(self.pos + 1) == Some(&'x') {
            text.push(self.bump());
            text.push(self.bump());
            while !self.eof() && (self.peek().is_ascii_hexdigit() || self.peek() == '_') {
                text.push(self.bump());
            }
        } else {
            while !self.eof() && (self.peek().is_ascii_digit() || self.peek() == '_') {
                text.push(self.bump());
            }
        }
        match self.eof() {
            true => {}
            false => match self.peek() {
                c if c.is_ascii_alphanumeric() || c == '.' => {
                    return Err(self.err(format!("非法数字 {text}{}", self.peek())))
                }
                _ => {}
            },
        }
        let cleaned: String = text.chars().filter(|c| *c != '_').collect();
        let radix = match cleaned.starts_with("0x") || cleaned.starts_with("-0x") {
            true => 16,
            false => 10,
        };
        let digits = match radix {
            16 => cleaned.trim_start_matches('-').trim_start_matches("0x"),
            _ => cleaned.trim_start_matches('-'),
        };
        let magnitude = i64::from_str_radix(digits, radix)
            .map_err(|_| self.err(format!("整数越界或非法：{text}")))?;
        let val = match cleaned.starts_with('-') {
            true => magnitude
                .checked_neg()
                .ok_or_else(|| self.err(format!("整数越界或非法：{text}")))?,
            false => magnitude,
        };
        Ok(Value::Int(val))
    }

    /// 数组：可跨行、可尾逗号、元素异构。
    fn parse_array(&mut self) -> Result<Value, ParseError> {
        self.expect('[')?;
        let mut items = Vec::new();
        loop {
            self.skip_blank();
            if self.eof() {
                return Err(self.err("数组未闭合".into()));
            }
            if self.peek() == ']' {
                self.bump();
                return Ok(Value::Array(items));
            }
            items.push(self.parse_value()?);
            self.skip_blank();
            if self.eof() {
                return Err(self.err("数组未闭合".into()));
            }
            match self.peek() {
                ',' => {
                    self.bump();
                }
                ']' => {
                    self.bump();
                    return Ok(Value::Array(items));
                }
                other => return Err(self.err(format!("数组内期望 , 或 ]，实得 {other:?}"))),
            }
        }
    }

    /// 内联表：键值对逗号分隔（宽容尾逗号与行内空白）。
    fn parse_inline_table(&mut self) -> Result<Value, ParseError> {
        self.expect('{')?;
        let mut table: Table = Vec::new();
        loop {
            self.skip_inline_ws();
            if self.eof() {
                return Err(self.err("内联表未闭合".into()));
            }
            if self.peek() == '}' {
                self.bump();
                return Ok(Value::Table(table));
            }
            let path = self.parse_key_path()?;
            self.skip_inline_ws();
            self.expect('=')?;
            self.skip_inline_ws();
            let value = self.parse_value()?;
            let (stem, leaf) = path.split_at(path.len() - 1);
            // 内联表内点分键：本子集仅一层展开（消费面未用更深）。
            let mut host = &mut table;
            for key in stem {
                let pos = match host.iter().position(|(k, _)| k == key) {
                    Some(p) => p,
                    None => {
                        host.push((key.clone(), Value::Table(Vec::new())));
                        host.len() - 1
                    }
                };
                match &mut host[pos].1 {
                    Value::Table(inner) => host = inner,
                    _ => return Err(self.err(format!("点分键 {key} 与既有值冲突"))),
                }
            }
            if host.iter().any(|(k, _)| *k == leaf[0]) {
                return Err(self.err(format!("键 {} 重复定义", leaf[0])));
            }
            host.push((leaf[0].clone(), value));
            self.skip_inline_ws();
            if self.eof() {
                return Err(self.err("内联表未闭合".into()));
            }
            match self.peek() {
                ',' => {
                    self.bump();
                }
                '}' => {
                    self.bump();
                    return Ok(Value::Table(table));
                }
                other => return Err(self.err(format!("内联表内期望 , 或 }}，实得 {other:?}"))),
            }
        }
    }
}

// ---------------------------------------------------------------- 节寻址

/// 递归走表路径，缺失即建（仅 Table 分支；撞上非表值报错）。
fn walk_mut<'t>(
    t: &'t mut Table,
    path: &[String],
    p: &Parser<'_>,
) -> Result<&'t mut Table, ParseError> {
    match path.split_first() {
        None => Ok(t),
        Some((key, rest)) => {
            let pos = match t.iter().position(|(k, _)| k == key) {
                Some(pos) => pos,
                None => {
                    t.push((key.clone(), Value::Table(Vec::new())));
                    t.len() - 1
                }
            };
            match &mut t[pos].1 {
                Value::Table(inner) => walk_mut(inner, rest, p),
                _ => Err(p.err(format!("路径 {} 上存在非表值", path.join(".")))),
            }
        }
    }
}

/// 探测路径是否已存在 Table（不建）。
fn probe_table(t: &Table, path: &[String]) -> bool {
    match path.split_first() {
        None => true,
        Some((key, rest)) => match table_get(t, key) {
            Some(Value::Table(inner)) => probe_table(inner, rest),
            _ => false,
        },
    }
}

/// `[[a.b]]`：向路径末键的表数组追加元素，返回新元素表与下标。
fn push_array_table(
    root: &mut Table,
    path: &[String],
    p: &Parser<'_>,
) -> Result<usize, ParseError> {
    let (stem, leaf) = match path.split_last() {
        Some((last, rest)) => (rest, last),
        None => return Err(p.err("空节路径".into())),
    };
    let host = walk_mut(root, stem, p)?;
    let pos = match host.iter().position(|(k, _)| k == leaf) {
        Some(pos) => pos,
        None => {
            host.push((leaf.clone(), Value::Array(Vec::new())));
            host.len() - 1
        }
    };
    match &mut host[pos].1 {
        Value::Array(items) => {
            items.push(Value::Table(Vec::new()));
            Ok(items.len() - 1)
        }
        _ => Err(p.err(format!("[[{}]] 与既有键冲突", path.join(".")))),
    }
}

/// 定位当前节（或其点分键宿主表）：根 / 节路径 / 表数组元素。
fn cur_table_mut<'t>(
    root: &'t mut Table,
    cur: &Cur,
    stem: &[String],
    p: &Parser<'_>,
) -> Result<&'t mut Table, ParseError> {
    match cur {
        Cur::Root => walk_mut(root, stem, p),
        Cur::Section(path) => {
            let section = walk_mut(root, path, p)?;
            walk_mut(section, stem, p)
        }
        Cur::ArrayElem(path, idx) => {
            let (arr_stem, arr_leaf) = match path.split_last() {
                Some((last, rest)) => (rest, last),
                None => return Err(p.err("空节路径".into())),
            };
            let host = walk_mut(root, arr_stem, p)?;
            let pos = host
                .iter()
                .position(|(k, _)| k == arr_leaf)
                .ok_or_else(|| p.err(format!("表数组 {} 缺失", path.join("."))))?;
            let elem = match &mut host[pos].1 {
                Value::Array(items) => match items.get_mut(*idx) {
                    Some(Value::Table(t)) => t,
                    _ => return Err(p.err("表数组元素缺失".into())),
                },
                _ => return Err(p.err("表数组退化".into())),
            };
            walk_mut(elem, stem, p)
        }
    }
}

// ---------------------------------------------------------------- 自测

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        get_array, get_bool, get_int, get_str, get_table, get_table_array, parse, table_get, Value,
    };

    #[test]
    fn sections_arrays_and_inline_tables() {
        let src = r#"
# 注释行
[contract]
name = "vfs-registry"
family_version = 1

[[messages]]
name = "Register"
number = 0x0001
errors = ["A", "B"]
request = [
    { reg = 0, name = "path_ptr", doc = "路径" },
    { reg = 1, name = "flags", doc = "旗标" },
]

[[messages]]
name = "Statfs"
number = 2
"#;
        let root = parse(src).expect("parse ok");
        let contract = get_table(&root, "contract").expect("contract");
        assert_eq!(get_str(contract, "name"), Some("vfs-registry"));
        assert_eq!(get_int(contract, "family_version"), Some(1));

        let msgs = get_table_array(&root, "messages").expect("messages");
        assert_eq!(msgs.len(), 2);
        assert_eq!(get_str(msgs[0], "name"), Some("Register"));
        assert_eq!(get_int(msgs[0], "number"), Some(1), "0x 十六进制");
        let errors = get_array(msgs[0], "errors").expect("errors");
        assert_eq!(errors.len(), 2);
        let req = get_table_array(msgs[0], "request").expect("request");
        assert_eq!(req.len(), 2);
        assert_eq!(get_str(req[1], "name"), Some("flags"));
    }

    #[test]
    fn dotted_keys_and_bools() {
        let src = "[dependencies]\nostd.workspace = true\nharbor = { workspace = true }\n";
        let root = parse(src).expect("parse ok");
        let deps = get_table(&root, "dependencies").expect("deps");
        let ostd = get_table(deps, "ostd").expect("ostd");
        assert_eq!(get_bool(ostd, "workspace"), Some(true));
        let harbor = get_table(deps, "harbor").expect("harbor");
        assert_eq!(get_bool(harbor, "workspace"), Some(true));
    }

    #[test]
    fn escapes_and_underscores() {
        let src = "a = \"x\\n\\t\\\"y\\\"\"\nb = 1_000\nc = -42\n";
        let root = parse(src).expect("parse ok");
        assert_eq!(
            table_get(&root, "a"),
            Some(&Value::Str("x\n\t\"y\"".into()))
        );
        assert_eq!(table_get(&root, "b"), Some(&Value::Int(1000)));
        assert_eq!(table_get(&root, "c"), Some(&Value::Int(-42)));
    }

    #[test]
    fn duplicate_key_rejected() {
        let src = "a = 1\na = 2\n";
        assert!(parse(src).is_err(), "同表重复键必须报错");
    }

    #[test]
    fn unsupported_escape_rejected() {
        let src = "a = \"\\u{41}\"\n";
        assert!(parse(src).is_err(), "不支持 \\u 转义");
    }

    #[test]
    fn unclosed_array_rejected() {
        let src = "a = [1, 2\n";
        assert!(parse(src).is_err(), "数组未闭合必须报错");
    }

    #[test]
    fn duplicate_section_rejected() {
        let src = "[x]\na = 1\n[x]\nb = 2\n";
        assert!(parse(src).is_err(), "节重复定义必须报错");
    }
}
