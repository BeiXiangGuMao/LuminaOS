//! lint —— lint-deps 依赖矩阵对照 + unsafe 白名单扫描（M24-X1）。
//!
//! 两面机检：
//! - **lint-deps**：解析 workspace 依赖图（各 crate Cargo.toml 的
//!   [dependencies]，内部边 = 依赖名 ∈ workspace 成员名），对照
//!   `tools/xtask/allowlist.toml` 的允许矩阵（政策面）与豁免台账（债务面，
//!   每项引 ADR）；[dev-dependencies] 不入图（不随产物发布，见台账头注）。
//! - **unsafe 扫描**：逐 crate 扫描 src/**/*.rs 的 unsafe 使用行（词边界 +
//!   后随 `{`/`fn `/`impl `/`trait `/`mod `；注释行跳过——行级近似，硬保证
//!   仍靠 forbid attribute 随批次落地），对照台账容忍面：全 crate 允许层
//!   （ostd/lumina-kernel/bedrock）、其余零 unsafe 层（含 harbor——ADR-0003
//!   M29-N1 重铸后 forbid(unsafe_code)；pulse——ADR-0005 M27-N1 同款）。
//!
//! 台账自检：债务面条目（dep_exemptions / module_overreach / 带 until 的
//! unsafe_allow）缺 adr 字段即 lint 失败——无裁决背书的债务不入账。

use crate::toml_min::{self, Table};

/// 台账路径（相对 workspace 根）。
pub const ALLOWLIST: &str = "tools/xtask/allowlist.toml";

// ---------------------------------------------------------------- 台账模型

/// 政策面允许边。
pub struct AllowedEdge {
    /// 依赖方 crate 名。
    pub from: String,
    /// 被依赖方 crate 名。
    pub to: String,
    /// 政策依据（展示用）。
    pub note: String,
}

/// 债务面依赖豁免（MUST 有 adr + until）。
pub struct DepExemption {
    /// 依赖方。
    pub from: String,
    /// 被依赖方。
    pub to: String,
    /// 豁免原因。
    pub reason: String,
    /// 裁决引用（docs/adr/ 篇目）。
    pub adr: String,
    /// 清账窗口（里程碑号）。
    pub until: String,
}

/// 债务面模块越界豁免（MUST 有 adr + until）。
pub struct ModuleOverreach {
    /// 模块路径（如 bedrock::vfs）。
    pub module: String,
    /// 越界原因与冻结令。
    pub reason: String,
    /// 裁决引用。
    pub adr: String,
    /// 清账窗口。
    pub until: String,
}

/// unsafe 容忍面条目。
pub struct UnsafeAllow {
    /// crate 名。
    pub crate_name: String,
    /// 文件级白名单路径（None = 全 crate 允许层）。
    pub path: Option<String>,
    /// 说明。
    pub note: String,
    /// 裁决引用（债务条目 MUST 有）。
    pub adr: Option<String>,
    /// 清账窗口（债务条目 MUST 有）。
    pub until: Option<String>,
}

/// 台账全集。
pub struct Allowlist {
    /// 政策面允许边。
    pub allowed_edges: Vec<AllowedEdge>,
    /// 债务面依赖豁免。
    pub dep_exemptions: Vec<DepExemption>,
    /// 债务面模块越界。
    pub module_overreach: Vec<ModuleOverreach>,
    /// unsafe 容忍面。
    pub unsafe_allow: Vec<UnsafeAllow>,
}

fn req_str(t: &Table, key: &str, ctx: &str) -> Result<String, String> {
    toml_min::get_str(t, key)
        .map(|s| s.to_string())
        .ok_or(format!("{ctx}：{key} 缺失"))
}

fn opt_str(t: &Table, key: &str) -> Option<String> {
    toml_min::get_str(t, key).map(|s| s.to_string())
}

/// 加载并自检台账。
pub fn load_allowlist(root: &str) -> Result<Allowlist, String> {
    let text = std::fs::read_to_string(format!("{root}/{ALLOWLIST}"))
        .map_err(|e| format!("读台账 {ALLOWLIST} 失败：{e}"))?;
    let parsed = toml_min::parse(&text).map_err(|e| format!("台账 {ALLOWLIST} 解析失败：{e}"))?;

    let mut allowed_edges = Vec::new();
    if let Some(arr) = toml_min::get_table_array(&parsed, "allowed_edges") {
        for t in arr {
            toml_min_check_keys(t, &["from", "to", "note"], "allowed_edges[]")?;
            allowed_edges.push(AllowedEdge {
                from: req_str(t, "from", "allowed_edges[]")?,
                to: req_str(t, "to", "allowed_edges[]")?,
                note: opt_str(t, "note").unwrap_or_default(),
            });
        }
    }

    let mut dep_exemptions = Vec::new();
    if let Some(arr) = toml_min::get_table_array(&parsed, "dep_exemptions") {
        for t in arr {
            toml_min_check_keys(
                t,
                &["from", "to", "reason", "adr", "until"],
                "dep_exemptions[]",
            )?;
            dep_exemptions.push(DepExemption {
                from: req_str(t, "from", "dep_exemptions[]")?,
                to: req_str(t, "to", "dep_exemptions[]")?,
                reason: req_str(t, "reason", "dep_exemptions[]")?,
                adr: req_str(t, "adr", "dep_exemptions[]（债务 MUST 有裁决）")?,
                until: req_str(t, "until", "dep_exemptions[]（债务 MUST 有清账窗）")?,
            });
        }
    }

    let mut module_overreach = Vec::new();
    if let Some(arr) = toml_min::get_table_array(&parsed, "module_overreach") {
        for t in arr {
            toml_min_check_keys(
                t,
                &["module", "reason", "adr", "until"],
                "module_overreach[]",
            )?;
            module_overreach.push(ModuleOverreach {
                module: req_str(t, "module", "module_overreach[]")?,
                reason: req_str(t, "reason", "module_overreach[]")?,
                adr: req_str(t, "adr", "module_overreach[]（债务 MUST 有裁决）")?,
                until: req_str(t, "until", "module_overreach[]（债务 MUST 有清账窗）")?,
            });
        }
    }

    let mut unsafe_allow = Vec::new();
    if let Some(arr) = toml_min::get_table_array(&parsed, "unsafe_allow") {
        for t in arr {
            toml_min_check_keys(
                t,
                &["crate", "path", "note", "adr", "until"],
                "unsafe_allow[]",
            )?;
            let crate_name = req_str(t, "crate", "unsafe_allow[]")?;
            let path = opt_str(t, "path");
            let until = opt_str(t, "until");
            let adr = opt_str(t, "adr");
            // 文件级白名单 = 债务：MUST 有 adr + until。
            if path.is_some() && (adr.is_none() || until.is_none()) {
                return Err(format!(
                    "unsafe_allow[{crate_name}]：文件级白名单为债务面，MUST 携带 adr 与 until"
                ));
            }
            unsafe_allow.push(UnsafeAllow {
                crate_name,
                path,
                note: opt_str(t, "note").unwrap_or_default(),
                adr,
                until,
            });
        }
    }

    Ok(Allowlist {
        allowed_edges,
        dep_exemptions,
        module_overreach,
        unsafe_allow,
    })
}

/// 键白名单校验（防拼写漂移静默吞键；重导出避免 use 冲突别名）。
fn toml_min_check_keys(t: &Table, allowed: &[&str], ctx: &str) -> Result<(), String> {
    for (k, _) in t {
        if !allowed.contains(&k.as_str()) {
            return Err(format!("{ctx}：非法键 {k}（允许 {allowed:?}）"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- 依赖图

/// workspace 成员（crate 名 → 相对目录）。
fn workspace_members(root: &str) -> Result<Vec<(String, String)>, String> {
    let text = std::fs::read_to_string(format!("{root}/Cargo.toml"))
        .map_err(|e| format!("读根清单失败：{e}"))?;
    let parsed = toml_min::parse(&text).map_err(|e| format!("根清单解析失败：{e}"))?;
    let ws = toml_min::get_table(&parsed, "workspace").ok_or("根清单缺 [workspace]")?;
    let members = toml_min::get_array(ws, "members").ok_or("[workspace] 缺 members")?;
    let mut out = Vec::new();
    for m in members {
        let path = match m {
            toml_min::Value::Str(s) => s,
            _ => return Err("workspace.members 元素须为字符串".into()),
        };
        let manifest = std::fs::read_to_string(format!("{root}/{path}/Cargo.toml"))
            .map_err(|e| format!("读成员清单 {path} 失败：{e}"))?;
        let mt =
            toml_min::parse(&manifest).map_err(|e| format!("成员清单 {path} 解析失败：{e}"))?;
        let pkg = toml_min::get_table(&mt, "package").ok_or(format!("{path} 缺 [package]"))?;
        let name = toml_min::get_str(pkg, "name")
            .ok_or(format!("{path} 缺 package.name"))?
            .to_string();
        out.push((name, path.clone()));
    }
    Ok(out)
}

/// crate 的内部依赖名集（[dependencies] 中 ∈ 成员名集的键）。
fn internal_deps(root: &str, dir: &str, member_names: &[String]) -> Result<Vec<String>, String> {
    let manifest = std::fs::read_to_string(format!("{root}/{dir}/Cargo.toml"))
        .map_err(|e| format!("读 {dir}/Cargo.toml 失败：{e}"))?;
    let parsed =
        toml_min::parse(&manifest).map_err(|e| format!("{dir}/Cargo.toml 解析失败：{e}"))?;
    let Some(deps) = toml_min::get_table(&parsed, "dependencies") else {
        return Ok(Vec::new());
    };
    Ok(deps
        .iter()
        .filter(|(k, _)| member_names.contains(k))
        .map(|(k, _)| k.clone())
        .collect())
}

// ---------------------------------------------------------------- unsafe 扫描

/// 是否为 unsafe 使用行（词边界 + 后随 `{`/`fn `/`impl `/`trait `/`mod `）。
fn is_unsafe_usage(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = line[from..].find("unsafe") {
        let abs = from + rel;
        let before_ok = abs == 0 || !is_word_byte(bytes[abs - 1]);
        let after = abs + "unsafe".len();
        let after_ok = after < bytes.len() && !is_word_byte(bytes[after]);
        if before_ok && after_ok {
            let rest = line[after..].trim_start();
            let hit = rest.starts_with('{')
                || rest.starts_with("fn ")
                || rest.starts_with("impl ")
                || rest.starts_with("trait ")
                || rest.starts_with("mod ");
            if hit {
                return true;
            }
        }
        from = abs + "unsafe".len();
    }
    false
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// 递归收集 .rs 文件（相对 root 的路径）。
fn walk_rs(base: &str, dir: &str, out: &mut Vec<String>) {
    let full = format!("{base}/{dir}");
    let Ok(entries) = std::fs::read_dir(&full) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = match dir.is_empty() {
            true => name.clone(),
            false => format!("{dir}/{name}"),
        };
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => walk_rs(base, &rel, out),
            Ok(_) => {
                if name.ends_with(".rs") {
                    out.push(rel);
                }
            }
            Err(_) => {}
        }
    }
}

/// 单文件 unsafe 使用行计数。
fn count_unsafe_lines(root: &str, rel: &str) -> usize {
    let Ok(content) = std::fs::read_to_string(format!("{root}/{rel}")) else {
        return 0;
    };
    content
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//") && is_unsafe_usage(trimmed)
        })
        .count()
}

// ---------------------------------------------------------------- 主流程

/// lint 主入口：打印报告，返回违规数（0 = 通过）。
pub fn run(root: &str) -> usize {
    match run_inner(root) {
        Ok(violations) => violations,
        Err(e) => {
            eprintln!("[S5c-lint] {e}");
            1
        }
    }
}

fn run_inner(root: &str) -> Result<usize, String> {
    let allowlist = load_allowlist(root)?;
    let members = workspace_members(root)?;
    let member_names: Vec<String> = members.iter().map(|(n, _)| n.clone()).collect();
    let mut violations = Vec::new();

    // ---- 面 1：依赖图对照 ----
    println!("━━ lint-deps：workspace 依赖图对照（台账 {ALLOWLIST}）");
    let mut edge_count = 0usize;
    for (name, dir) in &members {
        for dep in internal_deps(root, dir, &member_names)? {
            edge_count += 1;
            let edge = (name.as_str(), dep.as_str());
            if let Some(a) = allowlist
                .allowed_edges
                .iter()
                .find(|a| (a.from.as_str(), a.to.as_str()) == edge)
            {
                println!("[边] {name} → {dep}  政策内（{}）", a.note);
            } else if let Some(x) = allowlist
                .dep_exemptions
                .iter()
                .find(|x| (x.from.as_str(), x.to.as_str()) == edge)
            {
                println!(
                    "[边] {name} → {dep}  豁免（{}，至 {}）：{}",
                    x.adr, x.until, x.reason
                );
            } else {
                println!("[边] {name} → {dep}  违规（无政策面/债务面背书）");
                violations.push(format!("依赖边 {name} → {dep} 未登记（先改 {ALLOWLIST}）"));
            }
        }
    }
    println!("[边] 合计 {edge_count} 条内部依赖边");

    // 模块越界豁免：在案展示 + 失效探测（软警告）。
    for m in &allowlist.module_overreach {
        let (crate_name, mod_path) = match m.module.split_once("::") {
            Some((c, p)) => (c, p),
            None => (m.module.as_str(), ""),
        };
        let probe = match members.iter().find(|(n, _)| n == crate_name) {
            Some((_, d)) if mod_path.is_empty() => format!("{root}/{d}/src"),
            Some((_, d)) => format!("{root}/{d}/src/{mod_path}"),
            None => format!("<未知 crate {crate_name}>"),
        };
        if std::path::Path::new(&probe).exists() {
            println!(
                "[模块] {}  越界豁免在案（{}，至 {}）：{}",
                m.module, m.adr, m.until, m.reason
            );
        } else {
            println!(
                "[模块] {}  台账条目疑似失效（{probe} 不存在）——请核对清账",
                m.module
            );
        }
    }

    // ---- 面 2：unsafe 扫描 ----
    println!("━━ unsafe 扫描（行级近似：词边界 + 后随 {{/fn/impl/trait/mod；注释行不计）");
    for (name, dir) in &members {
        let mut files = Vec::new();
        walk_rs(root, &format!("{dir}/src"), &mut files);
        files.sort();
        let allow = allowlist
            .unsafe_allow
            .iter()
            .find(|a| a.crate_name == *name);

        let mut total = 0usize;
        let mut outside = Vec::new();
        for f in &files {
            let hits = count_unsafe_lines(root, f);
            if hits == 0 {
                continue;
            }
            total += hits;
            let rel_in_crate = f
                .strip_prefix(&format!("{dir}/"))
                .unwrap_or(f.as_str())
                .to_string();
            let covered = match allow {
                // 全 crate 允许层。
                Some(a) if a.path.is_none() => true,
                // 文件级白名单。
                Some(a) => a.path.as_deref() == Some(rel_in_crate.as_str()),
                None => false,
            };
            if !covered {
                outside.push(format!("{rel_in_crate} ({hits} 行)"));
            }
        }

        match (allow, total) {
            (None, 0) => println!("[unsafe] {name}  零 unsafe 层 —— 0 处 ✓"),
            (None, _) => {
                println!("[unsafe] {name}  违规：{total} 处 unsafe 无容忍背书（{outside:?}）");
                violations.push(format!("crate {name} 存在未登记 unsafe（{total} 行）"));
            }
            (Some(a), 0) => {
                println!("[unsafe] {name}  允许面在案但当前零 unsafe（{}）", a.note);
            }
            (Some(a), _) => {
                let scope = match &a.path {
                    Some(p) => format!("白名单 {p}：{}", a.note),
                    None => format!("全 crate 允许层：{}", a.note),
                };
                let debt = match (&a.adr, &a.until) {
                    (Some(adr), Some(until)) => format!("（{adr}，至 {until}）"),
                    _ => String::new(),
                };
                if outside.is_empty() {
                    println!("[unsafe] {name}  {scope}{debt} —— {total} 处");
                } else {
                    println!("[unsafe] {name}  {scope}{debt} 之外另有违规：{:?}", outside);
                    violations.push(format!(
                        "crate {name} 在白名单文件之外存在 unsafe（{:?}）",
                        outside
                    ));
                }
            }
        }
    }

    // ---- 汇总 ----
    if violations.is_empty() {
        println!(
            "[S5c-lint] 零违规（政策面 {} 条 + 债务面在案）",
            allowlist.allowed_edges.len()
        );
    } else {
        for v in &violations {
            eprintln!("[S5c-lint] VIOLATION: {v}");
        }
    }
    Ok(violations.len())
}
