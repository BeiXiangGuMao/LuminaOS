//! xtask —— Lumina OS 构建编排与七阶段 CI。
//!
//! 依据《系统开发指南》第三章：CI 基础六阶段为 S1 格式检查、S2 clippy、
//! S3 构建、S4 单元测试、S5 文档、S6 报告归档。M2 起按 SPEC 表 19-1（P0）
//! 的自动化要求扩展为七阶段：S6 改为引导烟测（构建 bedrock-boot 引导镜像
//! 并在 QEMU 中验证串口 PASS 标记），报告归档顺延为 S7。每个阶段的输出
//! 追加写入日志目录（源码树外），失败即中断并返回非零码（fail-fast）。
//!
//! 用法：`cargo run -p xtask -- <ci|image|run|check|test|report>`；
//! 无参数默认 `ci`。

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

/// 源码树根（xtask crate 的上上级目录）。
const WORKSPACE_ROOT: &str = "/home/z/my-project/lumina-os";
/// 编译产物与日志根目录（源码树外，三分离约定）。
const BUILD_ROOT: &str = "/home/z/my-project/lumina-build";
/// 引导内核 crate 目录（相对源码树根）。
const BEDROCK_BOOT_DIR: &str = "crates/bedrock-boot";
/// 自定义 target JSON（相对 bedrock-boot crate 目录）。
const TARGET_JSON: &str = "../../targets/x86_64-lumina.json";
/// QEMU 串口烟测超时（秒；DEV-002 6.2 规定 120s 硬上限，烟测取短值快速失败）。
const SMOKE_TIMEOUT_SECS: u64 = 20;
/// 引导成功标记：内核经串口打印（DEV-002 6.2 TLV 协议）。
const BOOT_PASS_MARKER: &str = "[tlv] case=boot-p0-001 -> PASS";

/// 串口烟测日志路径。
fn serial_log() -> PathBuf {
    PathBuf::from(format!("{BUILD_ROOT}/logs/qemu-serial.log"))
}

/// QEMU 运行时根（无 root 安装：apt 闭包解包至 lumina-build/runtime/qemu-root）。
const QEMU_RUNTIME: &str = "/home/z/my-project/lumina-build/runtime/qemu-root";

/// QEMU 可执行文件定位：优先本项目运行时（无 root 解包安装），再退回 PATH。
fn find_qemu() -> Option<PathBuf> {
    let runtime = PathBuf::from(format!("{QEMU_RUNTIME}/usr/bin/qemu-system-x86_64"));
    if runtime.is_file() {
        return Some(runtime);
    }
    let conda = PathBuf::from(format!(
        "{BUILD_ROOT}/runtime/qemu-root/bin/qemu-system-x86_64"
    ));
    if conda.is_file() {
        return Some(conda);
    }
    // PATH 回退：逐项拼接检查，避免依赖 shell 语义。
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join("qemu-system-x86_64");
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

/// 引导镜像产物定位：lumina-build/target/x86_64-lumina/release/bootimage-*.bin。
fn find_bootimage() -> Option<PathBuf> {
    let dir = PathBuf::from(format!("{BUILD_ROOT}/target/x86_64-lumina/release"));
    std::fs::read_dir(&dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("bootimage-") && n.ends_with(".bin"))
                .unwrap_or(false)
        })
}

/// 一个 CI 阶段的执行结果。
struct StageResult {
    name: &'static str,
    passed: bool,
    elapsed_ms: u128,
}

fn log_file(name: &str) -> PathBuf {
    PathBuf::from(format!("{BUILD_ROOT}/logs/{name}.log"))
}

/// 运行一条命令：stdout/stderr 全量追加到阶段日志；返回退出码。
fn run_logged(stage: &str, program: &str, args: &[&str]) -> Option<i32> {
    run_logged_in(stage, program, args, WORKSPACE_ROOT, &[])
}

/// 同 [`run_logged`]，但指定工作目录与附加环境变量（bootimage 需强制 nightly）。
fn run_logged_in(
    stage: &str,
    program: &str,
    args: &[&str],
    cwd: &str,
    envs: &[(&str, &str)],
) -> Option<i32> {
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file(stage))
        .ok()?;
    let header = format!("\n$ cd {cwd} && {program} {}\n", args.join(" "));
    let _ = log.write_all(header.as_bytes());
    let mut cmd = Command::new(program);
    cmd.args(args).current_dir(cwd);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output();
    match out {
        Ok(o) => {
            let _ = log.write_all(&o.stdout);
            let _ = log.write_all(&o.stderr);
            o.status.code()
        }
        Err(e) => {
            let _ = writeln!(log, "spawn failed: {e}");
            None
        }
    }
}

/// 宿主侧编译检查五阶段定义：阶段名 → cargo 子命令与参数。
///
/// 均不带 --workspace：依赖 workspace 的 default-members（bedrock-boot 为裸机
/// bin，仅能以自定义 target 编译，已被排除在默认成员之外）。
const STAGES: &[(&str, &str, &[&str])] = &[
    ("S1-fmt", "cargo", &["fmt", "--all", "--", "--check"]),
    (
        "S2-clippy",
        "cargo",
        &["clippy", "--all-targets", "--", "-D", "warnings"],
    ),
    ("S3-build", "cargo", &["build"]),
    ("S4-test", "cargo", &["test"]),
    ("S5-doc", "cargo", &["doc", "--no-deps", "--quiet"]),
];

fn stage_log_header(stage: &str) {
    let _ = std::fs::create_dir_all(format!("{BUILD_ROOT}/logs"));
    let _ = std::fs::create_dir_all(format!("{BUILD_ROOT}/reports"));
    if let Ok(mut log) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file(stage))
    {
        let _ = writeln!(log, "========== {stage} @ {} ==========", timestamp());
    }
}

fn timestamp() -> String {
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    match since {
        Ok(d) => format!("epoch-{}", d.as_secs()),
        Err(_) => "epoch-unknown".into(),
    }
}

/// 执行 S1–S5；返回结果列表（S6-boot 与 S7 报告由调用方写）。
fn run_stages() -> Vec<StageResult> {
    let mut results = Vec::new();
    for (stage, program, args) in STAGES {
        stage_log_header(stage);
        let t0 = Instant::now();
        let code = run_logged(stage, program, args);
        results.push(StageResult {
            name: stage,
            passed: code == Some(0),
            elapsed_ms: t0.elapsed().as_millis(),
        });
        if code != Some(0) {
            eprintln!("[FAIL] {stage}：详见 {BUILD_ROOT}/logs/{stage}.log");
            break;
        }
        println!("[PASS] {stage} ({} ms)", t0.elapsed().as_millis());
    }
    results
}

/// 构建 bedrock-boot 引导镜像（bootloader + build-std，nightly 工具链）。
///
/// 返回镜像路径；失败返回 None（详情见 S6-boot 日志）。
fn build_boot_image(stage: &str) -> Option<PathBuf> {
    let cwd = format!("{WORKSPACE_ROOT}/{BEDROCK_BOOT_DIR}");
    // 强制 nightly：build-std 需要 nightly 工具链；RUSTUP_TOOLCHAIN 使进程树内
    // 全部 rustup shim 解析到 nightly，不依赖外部 PATH 状态（DEV-002 2.3）。
    let code = run_logged_in(
        stage,
        "cargo",
        &["bootimage", "--release", "--target", TARGET_JSON],
        &cwd,
        &[("RUSTUP_TOOLCHAIN", "nightly")],
    );
    if code != Some(0) {
        return None;
    }
    find_bootimage()
}

/// QEMU 串口烟测：运行镜像至超时，校验串口日志含 PASS 标记。
///
/// 内核进入 hlt 空闲循环不会自行退出，烟测按超时收割；串口日志落
/// lumina-build/logs/qemu-serial.log 供人工复查。
fn qemu_smoke(stage: &str, image: &Path) -> bool {
    let Some(qemu) = find_qemu() else {
        let _ = append_log(
            stage,
            "qemu-system-x86_64 未找到（预期于 lumina-build/runtime/qemu-root/bin）",
        );
        return false;
    };
    let log_path = serial_log();
    let _ = std::fs::remove_file(&log_path);
    let serial_arg = format!("file:{}", log_path.display());
    let drive_arg = format!("format=raw,file={}", image.display());

    let child = Command::new(&qemu)
        .args([
            "-L",
            &format!("{QEMU_RUNTIME}/usr/share/qemu"),
            "-L",
            &format!("{QEMU_RUNTIME}/usr/share/seabios"),
            "-display",
            "none",
            "-no-reboot",
            "-serial",
            &serial_arg,
            "-device",
            "isa-debug-exit,iobase=0xf4,iosize=0x04",
            "-drive",
            &drive_arg,
        ])
        .env(
            "LD_LIBRARY_PATH",
            format!("{QEMU_RUNTIME}/usr/lib/x86_64-linux-gnu:{QEMU_RUNTIME}/lib/x86_64-linux-gnu"),
        )
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            let _ = append_log(stage, &format!("QEMU 启动失败：{e}"));
            return false;
        }
    };

    let deadline = Instant::now() + Duration::from_secs(SMOKE_TIMEOUT_SECS);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let _ = append_log(stage, &format!("QEMU 提前退出：{status}"));
                break;
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(e) => {
                let _ = append_log(stage, &format!("QEMU wait 失败：{e}"));
                return false;
            }
        }
    }

    match std::fs::read_to_string(&log_path) {
        Ok(s) => {
            let _ = append_log(stage, "---- 串口日志 ----");
            let _ = append_log(stage, &s);
            s.contains(BOOT_PASS_MARKER)
        }
        Err(e) => {
            let _ = append_log(stage, &format!("串口日志读取失败：{e}"));
            false
        }
    }
}

/// 向阶段日志追加一行（无命令输出的自定义消息用）。
fn append_log(stage: &str, line: &str) -> std::io::Result<()> {
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file(stage))?;
    log.write_all(line.as_bytes())?;
    log.write_all(b"\n")?;
    Ok(())
}

/// S6-boot：构建引导镜像并烟测；返回结果。
fn run_boot_stage() -> StageResult {
    stage_log_header("S6-boot");
    let t0 = Instant::now();
    let mut cause = String::new();
    let passed = match build_boot_image("S6-boot") {
        Some(image) => {
            let _ = append_log("S6-boot", &format!("镜像：{}", image.display()));
            if qemu_smoke("S6-boot", &image) {
                true
            } else {
                cause = "串口未出现 PASS 标记".into();
                false
            }
        }
        None => {
            cause = "镜像构建失败".into();
            false
        }
    };
    if passed {
        println!("[PASS] S6-boot ({} ms)", t0.elapsed().as_millis());
    } else {
        eprintln!("[FAIL] S6-boot：{cause}，详见 {BUILD_ROOT}/logs/S6-boot.log");
    }
    StageResult {
        name: "S6-boot",
        passed,
        elapsed_ms: t0.elapsed().as_millis(),
    }
}

/// S7：汇总报告落盘。
fn write_report(results: &[StageResult]) -> std::io::Result<PathBuf> {
    let mut md = String::new();
    let _ = writeln!(md, "# Lumina OS CI 报告（{}）", timestamp());
    let _ = writeln!(md);
    let _ = writeln!(md, "| 阶段 | 结果 | 耗时 ms |");
    let _ = writeln!(md, "|---|---|---|");
    for r in results {
        let _ = writeln!(
            md,
            "| {} | {} | {} |",
            r.name,
            if r.passed { "PASS" } else { "FAIL" },
            r.elapsed_ms
        );
    }
    let passed = results.iter().filter(|r| r.passed).count();
    let _ = writeln!(md);
    let _ = writeln!(
        md,
        "**{passed}/{} 阶段通过**（fail-fast：首个失败即停）",
        results.len()
    );

    let path = PathBuf::from(format!(
        "{BUILD_ROOT}/reports/ci-summary-{}.md",
        timestamp()
    ));
    std::fs::write(&path, md)?;
    Ok(path)
}

fn main() -> ExitCode {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "ci".into());
    match cmd.as_str() {
        "ci" => {
            println!("Lumina OS xtask ci —— 七阶段门禁（DEV-002 第三章 + M2 扩展 S6-boot）");
            let mut results = run_stages();
            let host_passed = results.len() == STAGES.len() && results.iter().all(|r| r.passed);
            if host_passed {
                results.push(run_boot_stage());
            }
            let all_passed = results.len() == STAGES.len() + 1 && results.iter().all(|r| r.passed);
            match write_report(&results) {
                Ok(p) => println!("[S7-report] 报告已写入 {}", p.display()),
                Err(e) => eprintln!("[S7-report] 报告写入失败：{e}"),
            }
            if all_passed {
                println!("CI-OK：全部七阶段通过");
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        "image" => {
            println!("构建 bedrock-boot 引导镜像（nightly + build-std）…");
            match build_boot_image("S6-boot") {
                Some(p) => {
                    println!("镜像就绪：{}", p.display());
                    ExitCode::SUCCESS
                }
                None => {
                    eprintln!("镜像构建失败：详见 {BUILD_ROOT}/logs/S6-boot.log");
                    ExitCode::FAILURE
                }
            }
        }
        "run" => {
            println!("构建并烟测引导镜像（{}s 上限）…", SMOKE_TIMEOUT_SECS);
            match build_boot_image("S6-boot").filter(|p| qemu_smoke("S6-boot", p)) {
                Some(p) => {
                    println!("引导烟测通过：{}", p.display());
                    if let Ok(s) = std::fs::read_to_string(serial_log()) {
                        print!("{s}");
                    }
                    ExitCode::SUCCESS
                }
                None => {
                    eprintln!("烟测失败：详见 {BUILD_ROOT}/logs/S6-boot.log");
                    ExitCode::FAILURE
                }
            }
        }
        "check" => {
            let results = run_stages();
            if results.iter().all(|r| r.passed) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        "test" => {
            stage_log_header("S4-test");
            let t0 = Instant::now();
            let code = run_logged("S4-test", "cargo", &["test"]);
            println!(
                "[{}] cargo test ({} ms)",
                if code == Some(0) { "PASS" } else { "FAIL" },
                t0.elapsed().as_millis()
            );
            if code == Some(0) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        "report" => {
            println!("报告目录：{BUILD_ROOT}/reports");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("未知子命令：{other}；可用：ci | image | run | check | test | report");
            ExitCode::FAILURE
        }
    }
}
