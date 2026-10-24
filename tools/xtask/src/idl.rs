//! idl —— IDL 契约模型 + 校验 + Rust 代码生成器（M24-M2）。
//!
//! 纪律链：契约（crates/meridian/idl/*.toml）→ 本模块校验（schema 严格 +
//! 跨面一致）→ 发射 Rust 源 → rustfmt（与 S1 同源工具链/配置）→ 落盘
//! `crates/meridian/src/idl_gen.rs`。`idl-check` 以字节级比对拒绝一切手编
//! 漂移（ci S5b-idl 阶段挂闸）。
//!
//! 依赖面：xtask 零外部依赖（workspace 十八包全内部），TOML 解析走内建
//! [`crate::toml_min`]。

use std::io::Write as _;
use std::process::{Command, Stdio};

use crate::toml_min::{self, Table};

/// 契约目录（相对 workspace 根）。
pub const IDL_DIR: &str = "crates/meridian/idl";
/// 生成物落位（相对 workspace 根）。
pub const GEN_PATH: &str = "crates/meridian/src/idl_gen.rs";
/// 错误集契约文件名（共享，非消息契约）。
const ERRORS_FILE: &str = "errors.toml";

// ---------------------------------------------------------------- 模型

/// 消息契约（单文件）。
pub struct Contract {
    /// 契约名（kebab-case，须与文件名主干一致）。
    pub name: String,
    /// 接口族版本（dispatcher::MsgHeader 高 16 位）。
    pub family_version: u16,
    /// 契约描述。
    pub description: String,
    /// 消息面（按消息号升序）。
    pub messages: Vec<MessageDef>,
}

/// 单条消息定义。
pub struct MessageDef {
    /// 消息名（CamelCase）。
    pub name: String,
    /// 消息号（族内单调，1..）。
    pub number: u16,
    /// 消息描述（生成物文档承载）。
    pub description: String,
    /// 请求寄存器面（4 槽全列）。
    pub request: Vec<RegField>,
    /// 应答寄存器面（4 槽全列）。
    pub response: Vec<RegField>,
    /// 引用的组错误名（须存在于 errors.toml）。
    pub errors: Vec<String>,
}

/// 寄存器字段绑定。
pub struct RegField {
    /// 寄存器槽位（0..4）。
    pub reg: u8,
    /// 字段名（snake_case；`reserved` 前缀 = 保留槽，不落结构体字段）。
    pub name: String,
    /// 字段文档。
    pub doc: String,
    /// 是否保留槽（strict 解码强制为零）。
    pub reserved: bool,
}

/// 服务组错误集（errors.toml）。
pub struct ErrorGroup {
    /// 所属服务（须与 contract.name 一致）。
    pub service: String,
    /// 错误码前缀（如 M-VFS）。
    pub prefix: String,
    /// 错误项。
    pub errors: Vec<ErrorDef>,
}

/// 单条组错误定义。
pub struct ErrorDef {
    /// 错误名（CamelCase）。
    pub name: String,
    /// 错误码名（prefix + "-" + 后缀）。
    pub code: String,
    /// 可重试标记。
    pub retryable: bool,
    /// 建议重试间隔（毫秒；不可重试 MUST 为 0）。
    pub interval_ms: u64,
    /// Linux errno 绑定（x86_64 5.15；组内唯一）。
    pub errno: i32,
    /// 错误文档。
    pub doc: String,
}

// ---------------------------------------------------------------- 命令

/// `idl-gen`：契约 → 校验 → 发射 → rustfmt → 落盘。返回落位路径。
///
/// # Errors
/// 契约缺失/schema 违约/校验失败/rustfmt 失败均返回描述性 Err。
pub fn cmd_gen(root: &str) -> Result<String, String> {
    let src = generate(root)?;
    let path = format!("{root}/{GEN_PATH}");
    std::fs::write(&path, src.as_bytes()).map_err(|e| format!("写生成物失败：{e}"))?;
    Ok(path)
}

/// `idl-check`：重新生成并与落盘产物字节级比对；漂移即 Err。
///
/// # Errors
/// 生成失败 / 生成物缺失 / 字节级漂移（附首处分叉行诊断）。
pub fn cmd_check(root: &str) -> Result<(), String> {
    let src = generate(root)?;
    let path = format!("{root}/{GEN_PATH}");
    let on_disk =
        std::fs::read_to_string(&path).map_err(|e| format!("读生成物失败（先跑 idl-gen）：{e}"))?;
    if on_disk != src {
        let a: Vec<&str> = on_disk.lines().collect();
        let b: Vec<&str> = src.lines().collect();
        let mut i = 0;
        while i < a.len() && i < b.len() && a[i] == b[i] {
            i += 1;
        }
        return Err(format!(
            "生成物漂移：契约与 {GEN_PATH} 自第 {} 行起不一致（磁盘 {} 行 / 生成 {} 行）\
             —— 生成物禁止手编；改契约后执行 `cargo run -p xtask -- idl-gen` 重新生成",
            i + 1,
            a.len(),
            b.len()
        ));
    }
    Ok(())
}

/// 生成全流程：加载 → 校验 → 发射 → rustfmt。
fn generate(root: &str) -> Result<String, String> {
    let (contract, errors) = load(root)?;
    validate(&contract, &errors)?;
    let raw = emit(&contract, &errors);
    rustfmt_source(&raw, root)
}

// ---------------------------------------------------------------- 加载

/// 加载契约目录：`errors.toml` 为错误集；其余 `.toml` 为消息契约
/// （M2 面单契约：多文件即报错）。
fn load(root: &str) -> Result<(Contract, ErrorGroup), String> {
    let dir = format!("{root}/{IDL_DIR}");
    let mut contract_files: Vec<String> = Vec::new();
    let entries = std::fs::read_dir(&dir).map_err(|e| format!("读契约目录 {dir} 失败：{e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("遍历契约目录失败：{e}"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".toml") && name != ERRORS_FILE {
            contract_files.push(name);
        }
    }
    contract_files.sort();
    match contract_files.len() {
        0 => return Err(format!("{IDL_DIR} 下无消息契约（M2 面至少一份）")),
        1 => {}
        n => {
            return Err(format!(
                "{IDL_DIR} 下存在 {n} 份消息契约（{contract_files:?}）——多契约面 M2 未启用"
            ))
        }
    }
    let contract_name = contract_files.remove(0);

    let contract_text = std::fs::read_to_string(format!("{dir}/{contract_name}"))
        .map_err(|e| format!("读契约 {contract_name} 失败：{e}"))?;
    let contract_root = toml_min::parse(&contract_text)
        .map_err(|e| format!("契约 {contract_name} 解析失败：{e}"))?;
    let mut contract = parse_contract(&contract_root)?;
    let stem = contract_name.trim_end_matches(".toml");
    if contract.name != stem {
        return Err(format!(
            "契约名 {} 与文件名主干 {stem} 不一致（canonical 纪律）",
            contract.name
        ));
    }

    let errors_text = std::fs::read_to_string(format!("{dir}/{ERRORS_FILE}"))
        .map_err(|e| format!("读错误集 {ERRORS_FILE} 失败：{e}"))?;
    let errors_root =
        toml_min::parse(&errors_text).map_err(|e| format!("{ERRORS_FILE} 解析失败：{e}"))?;
    let errors = parse_errors(&errors_root)?;

    if errors.service != contract.name {
        return Err(format!(
            "错误集 service={} 与契约 name={} 不一致（组绑定断裂）",
            errors.service, contract.name
        ));
    }
    contract.messages.sort_by_key(|m| m.number);
    Ok((contract, errors))
}

/// schema 键白名单校验（防拼写漂移静默吞键）。
fn check_keys(t: &Table, allowed: &[&str], ctx: &str) -> Result<(), String> {
    for (k, _) in t {
        if !allowed.contains(&k.as_str()) {
            return Err(format!("{ctx}：非法键 {k}（允许 {allowed:?}）"));
        }
    }
    Ok(())
}

/// 蛇形命名校验：首字符小写字母或下划线，其余字母/数字/下划线。
fn is_snake_case(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// 驼峰命名校验：首字符大写字母，其余字母/数字。
fn is_camel_case(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_uppercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric())
}

fn parse_contract(root: &Table) -> Result<Contract, String> {
    let c = toml_min::get_table(root, "contract").ok_or("缺 [contract] 节")?;
    check_keys(
        c,
        &[
            "name",
            "family_version",
            "description",
            "payload",
            "decoding",
        ],
        "[contract]",
    )?;
    let name = toml_min::get_str(c, "name")
        .ok_or("contract.name 缺失或非字符串")?
        .to_string();
    if !is_snake_case(&name.replace('-', "_")) && !name.contains('-') {
        return Err(format!("contract.name {name} 非 kebab-case"));
    }
    let fv = toml_min::get_int(c, "family_version").ok_or("contract.family_version 缺失")?;
    if !(1..=i64::from(u16::MAX)).contains(&fv) {
        return Err(format!("contract.family_version {fv} 越界（1..=65535）"));
    }
    let description = toml_min::get_str(c, "description")
        .ok_or("contract.description 缺失")?
        .to_string();
    match toml_min::get_str(c, "payload") {
        Some("regs4") => {}
        other => return Err(format!("contract.payload = {other:?}（M2 仅支持 regs4）")),
    }
    match toml_min::get_str(c, "decoding") {
        Some("strict") => {}
        other => return Err(format!("contract.decoding = {other:?}（M2 仅支持 strict）")),
    }

    let mut messages = Vec::new();
    let marr = toml_min::get_table_array(root, "messages").ok_or("缺 [[messages]] 消息面")?;
    for mt in marr {
        messages.push(parse_message(mt)?);
    }
    if messages.is_empty() {
        return Err("契约无消息面（[[messages]] 为空）".into());
    }
    Ok(Contract {
        name,
        family_version: fv as u16,
        description,
        messages,
    })
}

fn parse_message(mt: &Table) -> Result<MessageDef, String> {
    let name = toml_min::get_str(mt, "name")
        .ok_or("messages[].name 缺失")?
        .to_string();
    let ctx = format!("消息 {name}");
    check_keys(
        mt,
        &[
            "name",
            "number",
            "description",
            "request",
            "response",
            "errors",
        ],
        &ctx,
    )?;
    if !is_camel_case(&name) {
        return Err(format!("{ctx}：消息名非 CamelCase"));
    }
    let number = toml_min::get_int(mt, "number").ok_or(format!("{ctx}：number 缺失"))?;
    if !(1..=i64::from(u16::MAX)).contains(&number) {
        return Err(format!("{ctx}：number {number} 越界（1..=65535）"));
    }
    let description = toml_min::get_str(mt, "description")
        .ok_or(format!("{ctx}：description 缺失"))?
        .to_string();
    let request = parse_fields(mt, "request", &ctx)?;
    let response = parse_fields(mt, "response", &ctx)?;
    let mut errors = Vec::new();
    if let Some(arr) = toml_min::get_array(mt, "errors") {
        for v in arr {
            match v {
                toml_min::Value::Str(s) => errors.push(s.clone()),
                _ => return Err(format!("{ctx}：errors 数组元素须为字符串")),
            }
        }
    }
    Ok(MessageDef {
        name,
        number: number as u16,
        description,
        request,
        response,
        errors,
    })
}

fn parse_fields(mt: &Table, key: &str, ctx: &str) -> Result<Vec<RegField>, String> {
    let arr = toml_min::get_table_array(mt, key)
        .ok_or(format!("{ctx}：缺 {key} 面（四寄存器必须全列）"))?;
    if arr.len() != 4 {
        return Err(format!("{ctx}：{key} 面须恰好 4 槽（实得 {}）", arr.len()));
    }
    let mut fields: Vec<RegField> = Vec::new();
    let mut seen = [false; 4];
    for ft in arr {
        check_keys(ft, &["reg", "name", "doc"], &format!("{ctx}：{key}[]"))?;
        let reg = toml_min::get_int(ft, "reg").ok_or(format!("{ctx}：{key}[].reg 缺失"))?;
        if !(0..4).contains(&reg) || seen[reg as usize] {
            return Err(format!(
                "{ctx}：{key}[].reg {reg} 越界或重复（0..4 槽各恰一次）"
            ));
        }
        seen[reg as usize] = true;
        let name = toml_min::get_str(ft, "name")
            .ok_or(format!("{ctx}：{key}[].name 缺失"))?
            .to_string();
        if !is_snake_case(&name) {
            return Err(format!("{ctx}：{key}[].name {name} 非 snake_case"));
        }
        let doc = toml_min::get_str(ft, "doc")
            .ok_or(format!("{ctx}：{key}[].doc 缺失"))?
            .to_string();
        let reserved = name.starts_with("reserved");
        if reserved && !doc.contains("MUST 为 0") {
            return Err(format!(
                "{ctx}：{key}[].name {name} 为保留槽但 doc 未声明「MUST 为 0」"
            ));
        }
        fields.push(RegField {
            reg: reg as u8,
            name,
            doc,
            reserved,
        });
    }
    fields.sort_by_key(|f| f.reg);
    Ok(fields)
}

fn parse_errors(root: &Table) -> Result<ErrorGroup, String> {
    let meta = toml_min::get_table(root, "meta").ok_or("错误集缺 [meta] 节")?;
    check_keys(meta, &["service", "prefix"], "[meta]")?;
    let service = toml_min::get_str(meta, "service")
        .ok_or("meta.service 缺失")?
        .to_string();
    let prefix = toml_min::get_str(meta, "prefix")
        .ok_or("meta.prefix 缺失")?
        .to_string();

    let mut errors = Vec::new();
    let earr = toml_min::get_table_array(root, "errors").ok_or("错误集缺 [[errors]] 项")?;
    if earr.is_empty() {
        return Err("错误集为空（组错误至少一项）".into());
    }
    for et in earr {
        let name = toml_min::get_str(et, "name")
            .ok_or("errors[].name 缺失")?
            .to_string();
        let ctx = format!("错误 {name}");
        check_keys(
            et,
            &["name", "code", "retryable", "interval_ms", "errno", "doc"],
            &ctx,
        )?;
        if !is_camel_case(&name) {
            return Err(format!("{ctx}：错误名非 CamelCase"));
        }
        let code = toml_min::get_str(et, "code").ok_or(format!("{ctx}：code 缺失"))?;
        if !code.starts_with(&format!("{prefix}-")) {
            return Err(format!("{ctx}：code {code} 未按前缀 {prefix}- 分层"));
        }
        let retryable =
            toml_min::get_bool(et, "retryable").ok_or(format!("{ctx}：retryable 缺失"))?;
        let interval =
            toml_min::get_int(et, "interval_ms").ok_or(format!("{ctx}：interval_ms 缺失"))?;
        if interval < 0 || interval > i64::from(u32::MAX) {
            return Err(format!("{ctx}：interval_ms {interval} 越界"));
        }
        match retryable {
            true if interval == 0 => {
                return Err(format!("{ctx}：可重试错误的 interval_ms 必须为正"))
            }
            false if interval != 0 => {
                return Err(format!("{ctx}：不可重试错误的 interval_ms 必须为 0"))
            }
            _ => {}
        }
        let errno = toml_min::get_int(et, "errno").ok_or(format!("{ctx}：errno 缺失"))?;
        if !(1..=133).contains(&errno) {
            return Err(format!("{ctx}：errno {errno} 越出 Linux 值域（1..=133）"));
        }
        let doc = toml_min::get_str(et, "doc")
            .ok_or(format!("{ctx}：doc 缺失"))?
            .to_string();
        errors.push(ErrorDef {
            name,
            code: code.to_string(),
            retryable,
            interval_ms: interval as u64,
            errno: errno as i32,
            doc,
        });
    }
    Ok(ErrorGroup {
        service,
        prefix,
        errors,
    })
}

// ---------------------------------------------------------------- 校验

/// 跨面一致性校验（加载面已做 per-item schema，此处做集合关系）。
fn validate(c: &Contract, eg: &ErrorGroup) -> Result<(), String> {
    // 消息号严格递增（canonical 纪律）+ 名称唯一。
    for w in c.messages.windows(2) {
        if w[0].number >= w[1].number {
            return Err(format!(
                "消息号非严格递增：{}({}) → {}({})",
                w[0].name, w[0].number, w[1].name, w[1].number
            ));
        }
    }
    let mut names: Vec<&str> = Vec::new();
    for m in &c.messages {
        if names.contains(&m.name.as_str()) {
            return Err(format!("消息名 {} 重复", m.name));
        }
        names.push(&m.name);
    }
    // 错误项唯一性：名/码/errno。
    let mut enames: Vec<&str> = Vec::new();
    let mut ecodes: Vec<&str> = Vec::new();
    let mut errno: Vec<i32> = Vec::new();
    for e in &eg.errors {
        if enames.contains(&e.name.as_str()) {
            return Err(format!("错误名 {} 重复", e.name));
        }
        if ecodes.contains(&e.code.as_str()) {
            return Err(format!("错误码 {} 重复", e.code));
        }
        if errno.contains(&e.errno) {
            return Err(format!(
                "errno {} 重复（{}）——组内 errno 单射是客户端可辨识性底线",
                e.errno, e.name
            ));
        }
        enames.push(&e.name);
        ecodes.push(&e.code);
        errno.push(e.errno);
    }
    // 消息引用的错误 ⊆ 组错误集。
    for m in &c.messages {
        for r in &m.errors {
            if !enames.contains(&r.as_str()) {
                return Err(format!("消息 {} 引用未定义错误 {}", m.name, r));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- rustfmt

/// 发射源过 rustfmt（S1 同源工具链 + 仓根 rustfmt.toml），保证与
/// `cargo fmt --all -- --check` 门禁恒一致。
fn rustfmt_source(src: &str, root: &str) -> Result<String, String> {
    let mut child = Command::new("rustfmt")
        .arg("--edition")
        .arg("2021")
        .arg("--config-path")
        .arg(format!("{root}/rustfmt.toml"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("rustfmt 启动失败（S1 门禁同源工具链）：{e}"))?;
    {
        let mut stdin = match child.stdin.take() {
            Some(s) => s,
            None => return Err("rustfmt stdin 管道缺失".into()),
        };
        stdin
            .write_all(src.as_bytes())
            .map_err(|e| format!("rustfmt 写入失败：{e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("rustfmt 等待失败：{e}"))?;
    if !out.status.success() {
        return Err(format!(
            "rustfmt 失败：{}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    String::from_utf8(out.stdout).map_err(|_| "rustfmt 输出非 UTF-8".into())
}

// ---------------------------------------------------------------- 命名助手

/// CamelCase → SCREAMING_SNAKE（Register → REGISTER）。
fn camel_to_upper_snake(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(c.to_ascii_uppercase());
    }
    out
}

/// CamelCase → snake_case（Register → register）。
fn camel_to_snake(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

/// kebab-case → CamelCase（vfs-registry → VfsRegistry）。
fn kebab_to_camel(s: &str) -> String {
    s.split('-')
        .map(|seg| {
            let mut cs = seg.chars();
            match cs.next() {
                Some(c) => c.to_ascii_uppercase().to_string() + cs.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

// ---------------------------------------------------------------- 发射器

/// 发射 Rust 源（未格式化；rustfmt_source 统一归约）。
fn emit(c: &Contract, eg: &ErrorGroup) -> String {
    let mut out = String::with_capacity(48 * 1024);
    emit_header(&mut out, c);
    emit_consts(&mut out, c);
    emit_messages(&mut out, c);
    emit_error_enum(&mut out, eg);
    emit_service(&mut out, c, eg);
    emit_tests(&mut out, c, eg);
    out
}

/// 错误枚举类型名（vfs-registry → VfsRegistryError）。
fn error_type_name(service: &str) -> String {
    format!("{}Error", kebab_to_camel(service))
}

/// 服务 trait 名（vfs-registry → VfsRegistryService）。
fn trait_name(service: &str) -> String {
    format!("{}Service", kebab_to_camel(service))
}

fn emit_header(out: &mut String, c: &Contract) {
    // 头注逐行显式拼装（续行符会吞行首空白，`//! ` 前缀必须逐行落实）。
    let lines = [
        format!("//! {} 契约生成物（IDL 纪律，M24-M2 起步）。", c.name),
        "//!".to_string(),
        "//! 本文件由 `cargo run -p xtask -- idl-gen` 生成 —— 禁止手编。".to_string(),
        format!(
            "//! 契约源：{IDL_DIR}/{}.toml（消息面）与 {IDL_DIR}/{ERRORS_FILE}（组错误集）。",
            c.name
        ),
        "//! 一致性由 `cargo run -p xtask -- idl-check`（ci S5b-idl 阶段）以字节级".to_string(),
        "//! 比对守护：任何手编在下一轮 ci 即被拒绝。契约变更流程：改 toml →".to_string(),
        "//! idl-gen → 生成物随契约同批提交。".to_string(),
        "//!".to_string(),
        format!("//! {}", c.description),
        "//!".to_string(),
        "//! 载荷模型：dispatcher::Payload = [u64; 4]（四寄存器；消息标识字高 16 位".to_string(),
        "//! 族版本 / 低 16 位消息号，见 dispatcher::MsgHeader）。解码纪律 strict：".to_string(),
        "//! 保留寄存器 MUST 为 0，非零即拒（DecodeError::ReservedNonZero）。".to_string(),
        "//! 组错误映射：errno 绑定 → DispatchError::Compat（草案；开放问题见契约头注）。"
            .to_string(),
        String::new(),
        "use crate::dispatcher::{".to_string(),
        "    CompatErrno, DispatchError, Dispatcher, Payload, ServiceError, ServiceHandler,"
            .to_string(),
        "};".to_string(),
        "use alloc::boxed::Box;".to_string(),
        "use alloc::sync::Arc;".to_string(),
        String::new(),
    ];
    out.push_str(&lines.join("\n"));
    out.push('\n');
}

fn emit_consts(out: &mut String, c: &Contract) {
    out.push_str(&format!(
        "/// 接口族版本（契约 family_version；版本闸语义见 dispatcher）。\n\
         pub const FAMILY_VERSION: u16 = {};\n\n",
        c.family_version
    ));
    for m in &c.messages {
        out.push_str(&format!(
            "/// 消息号：{} —— {}\n\
             pub const MSG_{}: u16 = 0x{:04X};\n\n",
            m.name,
            m.description,
            camel_to_upper_snake(&m.name),
            m.number
        ));
    }
    out.push_str(
        "/// 消息描述条目（自省表元素：注册面与诊断共用）。\n\
         #[derive(Debug, Clone, Copy, PartialEq, Eq)]\n\
         pub struct MessageInfo {\n    \
             /// 消息号。\n    \
             pub number: u16,\n    \
             /// 消息名（契约原文）。\n    \
             pub name: &'static str,\n\
         }\n\n\
         /// 全消息自省表（按消息号升序；与常量一致性由生成物测试锁定）。\n\
         pub const MESSAGES: &[MessageInfo] = &[\n",
    );
    for m in &c.messages {
        out.push_str(&format!(
            "    MessageInfo {{ number: MSG_{}, name: \"{}\" }},\n",
            camel_to_upper_snake(&m.name),
            m.name
        ));
    }
    out.push_str("];\n\n");
}

/// 单槽编码表达式：非保留 = self.{name}，保留 = 0。
fn encode_slot(f: Option<&RegField>) -> String {
    match f {
        Some(f) => format!("self.{}", f.name),
        None => "0".into(),
    }
}

fn emit_struct(out: &mut String, m: &MessageDef, side: &str) {
    let fields = match side {
        "request" => &m.request,
        _ => &m.response,
    };
    let struct_name = format!(
        "{}{}",
        m.name,
        match side {
            "request" => "Request",
            _ => "Response",
        }
    );
    out.push_str(&format!(
        "/// {}（{}面）。\n\
         #[derive(Debug, Clone, Copy, PartialEq, Eq)]\n\
         pub struct {struct_name} {{\n",
        m.description, side
    ));
    for f in fields.iter().filter(|f| !f.reserved) {
        out.push_str(&format!(
            "    /// {}（寄存器 {}）。\n    pub {}: u64,\n",
            f.doc, f.reg, f.name
        ));
    }
    out.push_str("}\n\n");
    out.push_str(&format!("impl {struct_name} {{\n"));
    // encode：按 reg 序展开，保留槽补零。
    out.push_str(
        "    /// 编码为四寄存器载荷（保留槽补零）。\n    pub fn encode(self) -> Payload {\n        [",
    );
    let slots: Vec<String> = (0..4usize)
        .map(|i| {
            encode_slot(
                fields
                    .iter()
                    .find(|f| f.reg == i as u8)
                    .filter(|f| !f.reserved),
            )
        })
        .collect();
    out.push_str(&slots.join(", "));
    out.push_str("]\n    }\n\n");
    // decode：保留槽非零即拒。
    out.push_str("    /// 从载荷严格解码。\n    ///\n    /// # Errors\n");
    let reserved: Vec<&RegField> = fields.iter().filter(|f| f.reserved).collect();
    if reserved.is_empty() {
        out.push_str("    /// 本消息无保留槽，当前恒 `Ok`（签名统一以稳适配器面）。\n");
    } else {
        out.push_str(
            "    /// 保留寄存器非零时返回 [`DecodeError::ReservedNonZero`]（strict 纪律）。\n",
        );
    }
    out.push_str("    pub fn decode(p: &Payload) -> Result<Self, DecodeError> {\n");
    for f in &reserved {
        out.push_str(&format!(
            "        if p[{}] != 0 {{\n            return Err(DecodeError::ReservedNonZero {{ reg: {} }});\n        }}\n",
            f.reg, f.reg
        ));
    }
    let loads: Vec<String> = (0..4usize)
        .map(|i| {
            match fields
                .iter()
                .find(|f| f.reg == i as u8)
                .filter(|f| !f.reserved)
            {
                Some(f) => format!("{}: p[{}]", f.name, i),
                None => String::new(),
            }
        })
        .filter(|s| !s.is_empty())
        .collect();
    out.push_str(&format!(
        "        Ok(Self {{ {} }})\n    }}\n}}\n\n",
        loads.join(", ")
    ));
}

fn emit_messages(out: &mut String, c: &Contract) {
    for m in &c.messages {
        out.push_str(&format!(
            "// ---------------------------------------------------------------- {}\n\n",
            m.name
        ));
        emit_struct(out, m, "request");
        emit_struct(out, m, "response");
    }
    out.push_str(
        "/// 严格解码错误（生成面统一）。\n\
         #[derive(Debug, Clone, Copy, PartialEq, Eq)]\n\
         pub enum DecodeError {\n    \
             /// 保留寄存器非零（strict 纪律：保留位 MUST 为 0，防语义漂移夹带）。\n    \
             ReservedNonZero {\n        \
                 /// 违约寄存器槽位。\n        \
                 reg: u8,\n    \
             },\n\
         }\n\n",
    );
}

fn emit_error_enum(out: &mut String, eg: &ErrorGroup) {
    let ty = error_type_name(&eg.service);
    out.push_str(&format!(
        "/// {} 服务组错误集（idl/{ERRORS_FILE} 生成；细则 §3.3 按服务分组）。\n\
         #[derive(Debug, Clone, Copy, PartialEq, Eq)]\n\
         pub enum {ty} {{\n",
        eg.service
    ));
    for e in &eg.errors {
        out.push_str(&format!("    /// {}\n    {},\n", e.doc, e.name));
    }
    out.push_str("}\n\n");
    out.push_str(&format!("impl {ty} {{\n"));
    // code
    out.push_str(&format!(
        "    /// 错误码名（{}-* 前缀分层；日志与错误一一对应）。\n    \
         pub fn code(self) -> &'static str {{\n        match self {{\n",
        eg.prefix
    ));
    for e in &eg.errors {
        out.push_str(&format!(
            "            Self::{} => \"{}\",\n",
            e.name, e.code
        ));
    }
    out.push_str("        }\n    }\n\n");
    // is_retryable
    out.push_str(
        "    /// 可重试标记（崩溃恢复路径的客户端语义依据）。\n    \
         pub fn is_retryable(self) -> bool {\n        match self {\n",
    );
    for e in &eg.errors {
        out.push_str(&format!(
            "            Self::{} => {},\n",
            e.name, e.retryable
        ));
    }
    out.push_str("        }\n    }\n\n");
    // retry_interval_ms
    out.push_str(
        "    /// 建议重试间隔（毫秒；不可重试项为 `None`）。\n    \
         pub fn retry_interval_ms(self) -> Option<u64> {\n        match self {\n",
    );
    for e in &eg.errors {
        let rhs = match e.retryable {
            true => format!("Some({})", e.interval_ms),
            false => "None".into(),
        };
        out.push_str(&format!("            Self::{} => {},\n", e.name, rhs));
    }
    out.push_str("        }\n    }\n\n");
    // errno
    out.push_str(
        "    /// Linux errno 绑定（x86_64 5.15；与 conduit::errno_name 快照对账）。\n    \
         pub fn errno(self) -> i32 {\n        match self {\n",
    );
    for e in &eg.errors {
        out.push_str(&format!("            Self::{} => {},\n", e.name, e.errno));
    }
    out.push_str(
        "        }\n    }\n\n\
         \x20   /// 草案映射：经 errno 绑定走兼容级面（[`DispatchError::Compat`]）。\n\
         \x20   ///\n\
         \x20   /// 组内 errno 唯一（契约校验器强制）保客户端可辨识性；组 code 名在\n\
         \x20   /// 分发层载体的身份保全为开放问题（契约头注，Conduit 接入批次裁决）。\n\
         \x20   pub fn into_dispatch_error(self) -> DispatchError {\n        \
             DispatchError::Compat(CompatErrno {\n            \
                 errno: self.errno(),\n            \
                 retryable: self.is_retryable(),\n        \
             })\n    }\n\
         }\n\n",
    );
}

fn emit_tests(out: &mut String, c: &Contract, eg: &ErrorGroup) {
    let ty = error_type_name(&eg.service);
    let tr = trait_name(&eg.service);
    let n = c.messages.len();
    out.push_str(
        "// ---------------------------------------------------------------- 生成物自测\n\n",
    );
    out.push_str(
        "#[cfg(test)]\n\
         #[allow(clippy::unwrap_used, clippy::expect_used)]\n\
         mod tests {\n    use alloc::boxed::Box;\n\n    use super::{\n",
    );
    // 导入面：消息常量 + 结构体 + 错误面（全量，未用即 S2 拦）。
    for m in &c.messages {
        out.push_str(&format!(
            "        MSG_{}, {}Request, {}Response,\n",
            camel_to_upper_snake(&m.name),
            m.name,
            m.name
        ));
    }
    out.push_str(&format!(
        "        attach, DecodeError, FAMILY_VERSION, MESSAGES, {ty}, {tr},\n    }};\n\
         use crate::dispatcher::{{CapabilityGate, DispatchError, Dispatcher, MsgHeader}};\n\n"
    ));
    // 假闸 + 假服务（末位消息 = 错误路径取证位）。
    out.push_str(
        "    /// 测试闸：全放行（能力面语义由 dispatcher 自测覆盖）。\n\
         struct AllowGate;\n\
         impl CapabilityGate for AllowGate {\n        \
             fn check(&self, _cap: u64, _msg_id: u16) -> Result<(), u64> {\n            \
                 Ok(())\n        \
             }\n    }\n\n",
    );
    let last = n - 1;
    out.push_str(&format!(
        "    /// 假服务：逐操作固定应答；末位消息（{}）恒返 NotRegistered（错误路径取证）。\n\
         struct FakeService;\n\
         impl {tr} for FakeService {{\n",
        c.messages[last].name
    ));
    for (i, m) in c.messages.iter().enumerate() {
        let method = camel_to_snake(&m.name);
        match i == last {
            true => out.push_str(&format!(
                "        fn {method}(&self, _req: {}Request) -> Result<{}Response, {ty}> {{\n            \
                 Err({ty}::NotRegistered)\n        }}\n",
                m.name, m.name
            )),
            false => {
                let resp_fields = sample_fields(&m.response);
                out.push_str(&format!(
                    "        fn {method}(&self, _req: {}Request) -> Result<{}Response, {ty}> {{\n            \
                     Ok({}Response {{ {resp_fields} }})\n        }}\n",
                    m.name, m.name, m.name
                ));
            }
        }
    }
    out.push_str("    }\n\n");
    // ① 族版本冻结 + ② 自省表一致。
    out.push_str(&format!(
        "    #[test]\n    fn family_version_frozen() {{\n        \
             assert_eq!(FAMILY_VERSION, {});\n    }}\n\n",
        c.family_version
    ));
    out.push_str(&format!(
        "    #[test]\n    fn message_table_matches_constants() {{\n        \
             assert_eq!(MESSAGES.len(), {n});\n"
    ));
    for (i, m) in c.messages.iter().enumerate() {
        out.push_str(&format!(
            "        assert_eq!(MESSAGES[{i}].number, MSG_{});\n        \
             assert_eq!(MESSAGES[{i}].name, \"{}\");\n",
            camel_to_upper_snake(&m.name),
            m.name
        ));
    }
    out.push_str("        assert!(MESSAGES.windows(2).all(|w| w[0].number < w[1].number), \"自省表升序\");\n    }\n\n");
    // ③ 逐消息往返。
    for m in &c.messages {
        let method = camel_to_snake(&m.name);
        let req_fields = sample_fields(&m.request);
        let resp_fields = sample_fields(&m.response);
        out.push_str(&format!(
            "    #[test]\n    fn {method}_roundtrip() {{\n        \
                 let req = {}Request {{ {req_fields} }};\n        \
                 assert_eq!({}Request::decode(&req.encode()), Ok(req));\n        \
                 let resp = {}Response {{ {resp_fields} }};\n        \
                 assert_eq!({}Response::decode(&resp.encode()), Ok(resp));\n    }}\n\n",
            m.name, m.name, m.name, m.name
        ));
    }
    // ④ strict 解码：保留槽非零即拒（仅存在保留槽时发射）。
    let has_reserved = c
        .messages
        .iter()
        .any(|m| m.request.iter().any(|f| f.reserved) || m.response.iter().any(|f| f.reserved));
    if has_reserved {
        out.push_str("    #[test]\n    fn strict_decode_rejects_nonzero_reserved() {\n");
        for m in &c.messages {
            for (side, fields) in [("request", &m.request), ("response", &m.response)] {
                let Some(f) = fields.iter().find(|f| f.reserved) else {
                    continue;
                };
                let name = format!(
                    "{}{}",
                    m.name,
                    match side {
                        "request" => "Request",
                        _ => "Response",
                    }
                );
                let samples = sample_fields(fields);
                out.push_str(&format!(
                    "        let mut p = {name} {{ {samples} }}.encode();\n        \
                         p[{}] = 9;\n        \
                         assert_eq!(\n            \
                             {name}::decode(&p),\n            \
                             Err(DecodeError::ReservedNonZero {{ reg: {} }})\n        \
                         );\n",
                    f.reg, f.reg
                ));
            }
        }
        out.push_str("    }\n\n");
    }
    // ⑤ 错误表对照 + ⑥ errno 单射 + ⑦ Compat 映射。
    out.push_str(&format!(
        "    #[test]\n    fn error_table_matches_contract() {{\n        \
             let table: [({ty}, &'static str, i32, bool, Option<u64>); {}] = [\n",
        eg.errors.len()
    ));
    for e in &eg.errors {
        let interval = match e.retryable {
            true => format!("Some({})", e.interval_ms),
            false => "None".into(),
        };
        out.push_str(&format!(
            "            ({ty}::{}, \"{}\", {}, {}, {interval}),\n",
            e.name, e.code, e.errno, e.retryable
        ));
    }
    out.push_str("        ];\n        for (e, code, errno, retryable, interval) in table {\n            assert_eq!(e.code(), code);\n            assert_eq!(e.errno(), errno);\n            assert_eq!(e.is_retryable(), retryable);\n            assert_eq!(e.retry_interval_ms(), interval);\n        }\n    }\n\n");
    out.push_str("    #[test]\n    fn errno_bindings_unique_in_group() {\n        let all = [\n");
    for e in &eg.errors {
        out.push_str(&format!("            {ty}::{},\n", e.name));
    }
    out.push_str(
        "        ];\n        for (i, a) in all.iter().enumerate() {\n            \
                 for (j, b) in all.iter().enumerate() {\n                \
                     if i < j {\n                    \
                         assert_ne!(a.errno(), b.errno(), \"组内 errno 单射\");\n                \
                     }\n            \
                 }\n        }\n    }\n\n",
    );
    out.push_str("    #[test]\n    fn into_dispatch_maps_compat_layer() {\n        let all = [\n");
    for e in &eg.errors {
        out.push_str(&format!("            {ty}::{},\n", e.name));
    }
    out.push_str(
        "        ];\n        for e in all {\n            \
                 match e.into_dispatch_error() {\n                \
                     DispatchError::Compat(c) => {\n                    \
                         assert_eq!(c.errno, e.errno());\n                    \
                         assert_eq!(c.retryable, e.is_retryable());\n                \
                     }\n                \
                     other => panic!(\"期望 Compat 载体，实得 {other:?}\"),\n            \
                 }\n        }\n    }\n\n",
    );
    // ⑧ attach 冒烟：全链（编码 → dispatch → 解码）+ 末位消息错误路径。
    out.push_str(&format!(
        "    #[test]\n    fn attach_demuxes_typed_roundtrip() {{\n        \
             let mut d = Dispatcher::new(FAMILY_VERSION, Box::new(AllowGate));\n        \
             attach(&mut d, std::sync::Arc::new(FakeService));\n        \
             assert_eq!(d.route_count(), {n});\n\n"
    ));
    for (i, m) in c.messages.iter().enumerate() {
        let method = camel_to_snake(&m.name);
        let req_fields = sample_fields(&m.request);
        let resp_fields = sample_fields(&m.response);
        match i == last {
            true => out.push_str(&format!(
                "        // {} 错误路径：NotRegistered → Compat ENOENT(2)。\n        \
                     let req = {}Request {{ {req_fields} }};\n        \
                     let word = MsgHeader::encode(FAMILY_VERSION, MSG_{});\n        \
                     let err = d\n            \
                         .dispatch(word, 0, &req.encode())\n            \
                         .expect_err(\"FakeService 对末位消息恒返 NotRegistered\");\n        \
                     assert_eq!(err.as_errno(), Some(2));\n\n",
                m.name,
                m.name,
                camel_to_upper_snake(&m.name)
            )),
            false => out.push_str(&format!(
                "        // {} 全链：类型化请求 → dispatch → 类型化应答。\n        \
                     let req = {}Request {{ {req_fields} }};\n        \
                     let word = MsgHeader::encode(FAMILY_VERSION, MSG_{});\n        \
                     let out = d\n            \
                         .dispatch(word, 0, &req.encode())\n            \
                         .expect(\"{method} 应成功\");\n        \
                     assert_eq!(\n            \
                         {}Response::decode(&out),\n            \
                         Ok({}Response {{ {resp_fields} }})\n        \
                     );\n\n",
                m.name,
                m.name,
                camel_to_upper_snake(&m.name),
                m.name,
                m.name
            )),
        }
    }
    out.push_str("    }\n}\n");
}

/// 测试样本字段串：非保留字段 reg i → 值 i+1（确定性互异）。
fn sample_fields(fields: &[RegField]) -> String {
    fields
        .iter()
        .filter(|f| !f.reserved)
        .map(|f| format!("{}: {}", f.name, f.reg + 1))
        .collect::<Vec<_>>()
        .join(", ")
}

fn emit_service(out: &mut String, c: &Contract, eg: &ErrorGroup) {
    let ty = error_type_name(&eg.service);
    let tr = trait_name(&eg.service);
    out.push_str(&format!(
        "/// {} 服务实现面（生成骨架：实现方提供类型化操作；错误面为组错误集\n\
         /// [`{ty}`]）。\n\
         pub trait {tr} {{\n",
        eg.service
    ));
    for m in &c.messages {
        out.push_str(&format!(
            "    /// {}\n    \
             ///\n    \
             /// # Errors\n    \
             /// 组错误集语义（逐项标注见 [`{ty}`] 变体文档）。\n    \
             fn {}(&self, req: {}Request) -> Result<{}Response, {ty}>;\n\n",
            m.description,
            camel_to_snake(&m.name),
            m.name,
            m.name
        ));
    }
    out.push_str("}\n\n");
    // Op 标签
    out.push_str(
        "/// 消息操作标签（适配器分派用）。\n\
         #[derive(Debug, Clone, Copy, PartialEq, Eq)]\n\
         enum Op {\n",
    );
    for m in &c.messages {
        out.push_str(&format!("    {},\n", m.name));
    }
    out.push_str("}\n\n");
    // Adapter
    out.push_str(
        &"/// 类型化服务 → 分发器的适配器（生成物注册面的执行体）。\n\
          struct Adapter {\n    \
              op: Op,\n    \
              svc: Arc<dyn Service>,\n\
          }\n\n"
            .replace("Service", &tr),
    );
    out.push_str("impl ServiceHandler for Adapter {\n");
    out.push_str(
        "    fn handle(&self, msg_id: u16, payload: &Payload) -> Result<Payload, DispatchError> {\n        \
             match self.op {\n",
    );
    for m in &c.messages {
        out.push_str(&format!(
            "            Op::{} => {{\n                \
                 let req = {}Request::decode(payload)\n                    \
                     .map_err(|_| DispatchError::Service(ServiceError::MalformedPayload {{ msg_id }}))?;\n                \
                 let resp = self\n                    \
                     .svc\n                    \
                     .{}(req)\n                    \
                     .map_err(|e| e.into_dispatch_error())?;\n                \
                 Ok(resp.encode())\n            \
             }}\n",
            m.name,
            m.name,
            camel_to_snake(&m.name)
        ));
    }
    out.push_str("        }\n    }\n}\n\n");
    // attach
    out.push_str(&format!(
        "/// 生成物注册面：把四操作接入分发器（M1 前向声明「以生成物替换手写注册」\n\
         /// 的落位接口；消息号与族版本取自契约常量）。\n\
         pub fn attach(d: &mut Dispatcher, svc: Arc<dyn {tr}>) {{\n"
    ));
    let last = c.messages.len() - 1;
    for (i, m) in c.messages.iter().enumerate() {
        // 末位消息走字段简写（clippy::redundant_field_names 纪律）。
        let svc_field = match i == last {
            true => "svc".to_string(),
            false => "svc: Arc::clone(&svc)".to_string(),
        };
        out.push_str(&format!(
            "    d.register(\n        \
                 MSG_{},\n        \
                 Box::new(Adapter {{ op: Op::{}, {svc_field} }}),\n    \
             );\n",
            camel_to_upper_snake(&m.name),
            m.name
        ));
    }
    out.push_str("}\n\n");
}
