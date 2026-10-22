//! xtask —— Lumina OS 构建编排与 CI 门禁。
//!
//! 依据《系统开发指南》第三章（经 CHANGELOG v0.2.0 扩展，M24 起再度扩容）：
//! 宿主面 S1 格式检查、S2 clippy、S3 构建、S4 单元测试、S5 文档 +
//! S5b IDL 生成物一致性闸（idl-check，M24-M2 起）；内核三阶段
//! S6 clippy（自定义目标）、S7 构建、S8 裸机冒烟（QEMU multiboot1 自检）；
//! 最后 S9 写入报告。每个阶段的输出追加写入日志目录（源码树外），
//! 失败即中断并返回非零码（fail-fast）。
//!
//! 用法：`cargo run -p xtask -- <ci|smoke|check|test|report|idl-gen|idl-check>`；
//! 无参数默认 `ci`。

mod idl;
mod toml_min;

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{Read, Write as _};
use std::path::PathBuf;
use std::process::Stdio;
use std::process::{Command, ExitCode};
use std::time::Instant;

/// 源码树根（xtask crate 的上上级目录）。
const WORKSPACE_ROOT: &str = "/home/z/my-project/lumina-os";
/// 编译产物与日志根目录（源码树外，三分离约定）。
const BUILD_ROOT: &str = "/home/z/my-project/lumina-build";

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
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file(stage))
        .ok()?;
    let header = format!("\n$ {program} {}\n", args.join(" "));
    let _ = log.write_all(header.as_bytes());
    let out = Command::new(program)
        .args(args)
        .current_dir(WORKSPACE_ROOT)
        .output();
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

/// 宿主五阶段（S1–S5）：阶段名 → cargo 子命令与参数。
const HOST_STAGES: &[(&str, &str, &[&str])] = &[
    ("S1-fmt", "cargo", &["fmt", "--all", "--", "--check"]),
    (
        "S2-clippy",
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    ),
    ("S3-build", "cargo", &["build", "--workspace"]),
    ("S4-test", "cargo", &["test", "--workspace"]),
    ("S5-doc", "cargo", &["doc", "--no-deps", "--quiet"]),
];

/// 内核两阶段（S6–S7）：自定义目标语义。
const KERNEL_STAGES: &[(&str, &str, &[&str])] = &[
    (
        "S6-kernel-lint",
        "cargo",
        &[
            "clippy",
            "-p",
            "lumina-kernel",
            "--features",
            "boot",
            "--target",
            "x86_64-unknown-none",
            "--",
            "-D",
            "warnings",
        ],
    ),
    (
        "S7-kernel-build",
        "cargo",
        &[
            "build",
            "-p",
            "lumina-kernel",
            "--features",
            "boot",
            "--release",
            "--target",
            "x86_64-unknown-none",
        ],
    ),
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

/// 执行指定阶段切片；返回结果列表（报告由调用方写）。
fn run_stages(
    stages: &[(&'static str, &'static str, &'static [&'static str])],
) -> Vec<StageResult> {
    let mut results = Vec::new();
    for (stage, program, args) in stages {
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

/// 运行内建函数阶段（不经 cargo 子进程；IDL 一致性闸等）。
fn run_fn_stage(name: &'static str, f: impl FnOnce() -> bool) -> StageResult {
    stage_log_header(name);
    let t0 = Instant::now();
    let passed = f();
    println!(
        "[{}] {name} ({} ms)",
        if passed { "PASS" } else { "FAIL" },
        t0.elapsed().as_millis()
    );
    StageResult {
        name,
        passed,
        elapsed_ms: t0.elapsed().as_millis(),
    }
}

/// S5b-idl 闸：契约 → 生成器重算 → 与落盘生成物字节级比对（M24-M2）。
fn idl_gate() -> bool {
    match idl::cmd_check(WORKSPACE_ROOT) {
        Ok(()) => {
            println!("[S5b-idl] 生成物与契约一致（字节级比对通过）");
            true
        }
        Err(e) => {
            eprintln!("[S5b-idl] {e}");
            if let Ok(mut f) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_file("S5b-idl"))
            {
                let _ = writeln!(f, "DRIFT: {e}");
            }
            false
        }
    }
}

/// QEMU 运行时（用户态解包，见 lumina-build/runtime/qemu-root/README）。
const QEMU_BIN: &str =
    "/home/z/my-project/lumina-build/runtime/qemu-root/extracted/usr/bin/qemu-system-x86_64";
const QEMU_LIB: &str =
    "/home/z/my-project/lumina-build/runtime/qemu-root/extracted/usr/lib/x86_64-linux-gnu";
const QEMU_BIOS_SEABIOS: &str =
    "/home/z/my-project/lumina-build/runtime/qemu-root/extracted/usr/share/seabios";
const QEMU_BIOS_DATA: &str =
    "/home/z/my-project/lumina-build/runtime/qemu-root/extracted/usr/share/qemu";

/// S8：裸机冒烟 —— objcopy 产出 32 位可装载映像，QEMU multiboot1 启动，
/// 驱动 TLV 宿主-客户机联测，断言退出码 33 与全套串口自检标记（M4：15 项）。
fn run_smoke() -> StageResult {
    stage_log_header("S8-smoke");
    let t0 = Instant::now();
    let passed = smoke_inner();
    println!(
        "[{}] S8-smoke ({} ms)",
        if passed { "PASS" } else { "FAIL" },
        t0.elapsed().as_millis()
    );
    StageResult {
        name: "S8-smoke",
        passed,
        elapsed_ms: t0.elapsed().as_millis(),
    }
}

/// 内核映像（ELF）与裸映像（bin）路径。
const KERNEL_ELF: &str =
    "/home/z/my-project/lumina-build/target/x86_64-unknown-none/release/lumina-kernel";
const KERNEL_BIN: &str =
    "/home/z/my-project/lumina-build/target/x86_64-unknown-none/release/lumina-kernel.bin";

/// 自检标记总数（与内核 SELFTEST_TOTAL 同步；M12 完成态 = 43，M13-② 起 46，M15 起 52，M16 起 55，M17 起 58，M18 起 62，M21-③ 起 63，M23 起 65，M23-B 起 67，M23-C1 起 68，M23-C2 起 69，M23-C3 起 71）。
const SELFTEST_EXPECTED: &str = "71/71";

/// TLV 请求帧：tag 0x0007，value = b"lumina-m5"。
const TLV_REQ: &[u8] = &[
    0x07, 0x00, // tag = 0x0007（LE）
    0x09, 0x00, // len = 9（LE）
    b'l', b'u', b'm', b'i', b'n', b'a', b'-', b'm', b'5',
];
/// 应答 value 长度（"lumina-m5-ACK" = 13）。
const TLV_RESP_VALUE_LEN: usize = 13;

/// swap scratch 盘（M7-B：1 MiB 全零，挂从通道主盘 index=2；
/// 位于 lumina-build 产物区，不入源码树）。
const SWAP_IMG: &str = "/home/z/my-project/lumina-build/runtime/swap.img";

/// LFS1 数据盘（M17-①：1 MiB 全零，挂主通道从盘 index=1；空白盘首次
/// 挂载即格式化，产物区纪律同 swap 盘）。全零重建 = 每轮冒烟从空白
/// 介质起步（格式化路径确定性覆盖；持久化断言在盘内跨卸载重挂）。
const DISK_IMG: &str = "/home/z/my-project/lumina-build/runtime/disk.img";

/// S8 实体；返回是否全部断言通过。
fn smoke_inner() -> bool {
    // 0) swap 盘就位（M7-B 自检 27 的 ATA PIO 探测/读写对象；每次重建）
    if let Some(dir) = std::path::Path::new(SWAP_IMG).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if std::fs::write(SWAP_IMG, vec![0u8; 1024 * 1024]).is_err() {
        eprintln!("[FAIL] S8-smoke：swap scratch 盘创建失败：{SWAP_IMG}");
        return false;
    }
    // 0b) LFS1 数据盘就位（M17-① 自检 56 的 ATA PIO 挂载对象；每次重建）
    if std::fs::write(DISK_IMG, vec![0u8; 1024 * 1024]).is_err() {
        eprintln!("[FAIL] S8-smoke：LFS1 数据盘创建失败：{DISK_IMG}");
        return false;
    }
    // 1) objcopy 产出裸映像（QEMU multiboot1 仅接受 32 位可装载映像）
    let code = run_logged(
        "S8-smoke",
        "objcopy",
        &["-O", "binary", KERNEL_ELF, KERNEL_BIN],
    );
    if code != Some(0) {
        eprintln!("[FAIL] S8-smoke：objcopy 产出映像失败，详见 S8-smoke.log");
        return false;
    }
    // 2) QEMU 无头启动：串口走 stdio（双向管道）+ isa-debug-exit 自动退出；
    //    超时由下方看门狗直接杀 QEMU 本体（timeout 包裹会漏杀孤儿进程）
    let swap_drive = format!("file={SWAP_IMG},format=raw,if=ide,index=2,media=disk");
    let disk_drive = format!("file={DISK_IMG},format=raw,if=ide,index=1,media=disk");
    let mut child = match Command::new(QEMU_BIN)
        .args([
            "-L",
            QEMU_BIOS_SEABIOS,
            "-L",
            QEMU_BIOS_DATA,
            "-kernel",
            KERNEL_BIN,
            "-drive",
            disk_drive.as_str(),
            "-drive",
            swap_drive.as_str(),
            "-m",
            "256M",
            "-smp",
            "2",
            "-display",
            "none",
            "-no-reboot",
            "-serial",
            "stdio",
            "-device",
            "isa-debug-exit,iobase=0xf4,iosize=0x04",
            // M24-⓪ 对账：网络面自检（t68-t71）需 virtio-net-pci 在场，
            // 参数与 demo_m23b_driver.py 批跑面对齐；缺设备时 net 三项恒
            // FAIL，ci 门禁面失真（本先例 71/71 全绿后才可提交）。
            "-device",
            "virtio-net-pci,netdev=n0,disable-legacy=on",
            "-netdev",
            "user,id=n0",
        ])
        .env("LD_LIBRARY_PATH", QEMU_LIB)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[FAIL] S8-smoke：QEMU 启动失败：{e}");
            return false;
        }
    };
    // 看门狗：150 s 后强杀（步进睡眠，进程先退出则提前收工）。
    // M10 扩容依据：新增三自检（t34 双核 ring3 抢占窗口 + t35 八次盘 I/O
    // 的阻塞化换入链 + t36 等待/收割），TCG 下全程实测 ~80 s（v0.9 =
    // ~50 s @55s 门），余量取整 150 s。
    let pid = child.id();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let wd = std::sync::Arc::clone(&done);
    let watchdog = std::thread::spawn(move || {
        for _ in 0..150 {
            if wd.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        let _ = Command::new("kill").args(["-9", &pid.to_string()]).output();
    });

    let Some(mut stdout) = child.stdout.take() else {
        eprintln!("[FAIL] S8-smoke：stdout 管道缺失");
        return false;
    };
    let Some(mut stdin) = child.stdin.take() else {
        eprintln!("[FAIL] S8-smoke：stdin 管道缺失");
        return false;
    };
    let Some(mut stderr) = child.stderr.take() else {
        eprintln!("[FAIL] S8-smoke：stderr 管道缺失");
        return false;
    };
    let mut all: Vec<u8> = Vec::new();
    let mut buf = [0u8; 512];
    let mut tlv_ok = false;

    // 阶段 1：等 READY → 发请求帧
    let mut sent = false;
    // 阶段 2：等 RESP 前缀 → 读 4+len 字节验证
    let mut resp_checked = false;

    loop {
        match stdout.read(&mut buf) {
            Ok(0) => break, // EOF（进程退出）
            Ok(n) => all.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
        if !sent && find(all.as_slice(), b"LUMINA-HOSTLINK-READY").is_some() {
            if stdin
                .write_all(TLV_REQ)
                .and_then(|_| stdin.flush())
                .is_err()
            {
                eprintln!("[FAIL] S8-smoke：TLV 请求写入失败");
            }
            sent = true;
        }
        if sent && !resp_checked {
            if let Some(pos) = find(all.as_slice(), b"LUMINA-TLV-RESP:") {
                let mut frame_start = pos + b"LUMINA-TLV-RESP:".len();
                // writeln! 的 CRLF 在原始帧之前
                if all.len() > frame_start + 2 && &all[frame_start..frame_start + 2] == b"\r\n" {
                    frame_start += 2;
                }
                let need = 4 + TLV_RESP_VALUE_LEN;
                if all.len() >= frame_start + need {
                    let f = &all[frame_start..frame_start + need];
                    let tag = u16::from_le_bytes([f[0], f[1]]);
                    let len = u16::from_le_bytes([f[2], f[3]]) as usize;
                    let value = &f[4..];
                    let expect = b"lumina-m5-ACK";
                    if tag == 0x8007 && len == TLV_RESP_VALUE_LEN && value == &expect[..] {
                        tlv_ok = true;
                    }
                    resp_checked = true;
                }
            }
        }
    }
    let _ = stdin;
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut err_buf = Vec::new();
    let _ = stderr.read_to_end(&mut err_buf);
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file("S8-smoke"))
    {
        let _ = writeln!(
            f,
            "stderr ({} bytes): {}",
            err_buf.len(),
            String::from_utf8_lossy(&err_buf)
        );
        let _ = writeln!(f, "stdout bytes: {}", all.len());
    }

    let out = child.wait();
    let _ = watchdog.join();
    let code = match &out {
        Ok(st) => st.code().unwrap_or(-1),
        Err(_) => -1,
    };
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file("S8-smoke"))
    {
        let _ = writeln!(f, "qemu exit code: {code}（33 = 自检成功退出）");
        let _ = writeln!(f, "tlv roundtrip ok: {tlv_ok}");
    }
    // 无论成败先落盘串口日志（失败诊断的关键证据）
    let log_text = String::from_utf8_lossy(&all).into_owned();
    let _ = std::fs::write(
        format!("{BUILD_ROOT}/logs/boot-smoke.log"),
        log_text.as_bytes(),
    );
    if code != 33 {
        eprintln!("[FAIL] S8-smoke：QEMU 退出码 {code} ≠ 33，内核未完成自检退出");
        return false;
    }
    // 3) 串口日志断言：启动标记 + 十五项自检 + 用户态标记 + TLV 双向
    let selftest_marker = format!("LUMINA-SELFTEST-PASS {SELFTEST_EXPECTED}");
    let required: [&[u8]; 5] = [
        b"LUMINA-BOOT-OK",
        selftest_marker.as_bytes(),
        b"LUMINA-TLV-OK",
        b"USER-OK",
        b"user done: exit=42",
    ];
    let mut ok = tlv_ok;
    for marker in required {
        if find(all.as_slice(), marker).is_none() {
            eprintln!(
                "[FAIL] S8-smoke：串口日志缺少标记 {}",
                String::from_utf8_lossy(marker)
            );
            ok = false;
        }
    }
    // TLV 应答帧若未验证成功也要显式失败
    if !resp_checked {
        eprintln!("[FAIL] S8-smoke：未收到 TLV 应答帧");
        ok = false;
    }
    ok
}

/// 子切片查找（memmem 的最小实现，std 无内置）。
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// 汇总报告落盘并追加 devlog（S9）。
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

/// 阶段结果汇总行。
fn summarize(results: &[StageResult]) -> String {
    let passed = results.iter().filter(|r| r.passed).count();
    format!(
        "{passed}/{} 阶段通过（fail-fast：首个失败即停）",
        results.len()
    )
}

fn main() -> ExitCode {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "ci".into());
    match cmd.as_str() {
        "ci" => {
            println!("Lumina OS xtask ci —— 十阶段门禁（宿主六阶段 + 内核三阶段 + 报告）");
            let mut results = run_stages(HOST_STAGES);
            if results.iter().all(|r| r.passed) {
                results.push(run_fn_stage("S5b-idl", idl_gate));
            }
            if results.iter().all(|r| r.passed) {
                results.extend(run_stages(KERNEL_STAGES));
            }
            if results.iter().all(|r| r.passed) {
                results.push(run_smoke());
            }
            let total = HOST_STAGES.len() + 1 + KERNEL_STAGES.len() + 1;
            let all_passed = results.len() == total && results.iter().all(|r| r.passed);
            println!("{}", summarize(&results));
            match write_report(&results) {
                Ok(p) => println!("[S9-report] 报告已写入 {}", p.display()),
                Err(e) => eprintln!("[S9-report] 报告写入失败：{e}"),
            }
            if all_passed {
                println!("CI-OK：全部九阶段通过");
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        "smoke" => {
            println!("Lumina OS xtask smoke —— 内核 lint/build + QEMU 裸机自检");
            let mut results = run_stages(KERNEL_STAGES);
            if results.iter().all(|r| r.passed) {
                results.push(run_smoke());
            }
            println!("{}", summarize(&results));
            let total = KERNEL_STAGES.len() + 1;
            if results.len() == total && results.iter().all(|r| r.passed) {
                println!("SMOKE-OK");
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        "check" => {
            let mut results = run_stages(HOST_STAGES);
            if results.iter().all(|r| r.passed) {
                results.push(run_fn_stage("S5b-idl", idl_gate));
            }
            if results.iter().all(|r| r.passed) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        "test" => {
            stage_log_header("S4-test");
            let t0 = Instant::now();
            let code = run_logged("S4-test", "cargo", &["test", "--workspace"]);
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
        "idl-gen" => match idl::cmd_gen(WORKSPACE_ROOT) {
            Ok(path) => {
                println!("IDL 生成物已落位：{path}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[idl-gen] {e}");
                ExitCode::FAILURE
            }
        },
        "idl-check" => match idl::cmd_check(WORKSPACE_ROOT) {
            Ok(()) => {
                println!("IDL 生成物与契约一致（字节级比对通过）");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("[idl-check] {e}");
                ExitCode::FAILURE
            }
        },
        other => {
            eprintln!(
                "未知子命令：{other}；可用：ci | smoke | check | test | report | idl-gen | idl-check"
            );
            ExitCode::FAILURE
        }
    }
}
