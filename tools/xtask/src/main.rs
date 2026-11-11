//! xtask —— Lumina OS 构建编排与 CI 门禁。
//!
//! 依据《系统开发指南》第三章（经 CHANGELOG v0.2.0 扩展，M24 起再度扩容）：
//! 宿主面 S1 格式检查、S2 clippy、S3 构建、S4 单元测试、S5 文档 +
//! S5b IDL 生成物一致性闸（idl-check，M24-M2 起）+ S5c lint-deps/unsafe
//! 台账机检（lint，M24-X1 起）；内核三阶段
//! S6 clippy（自定义目标）、S7 构建、S8 裸机冒烟（QEMU multiboot1 自检）；
//! 最后 S9 写入报告。另有 S10-longrun 长稳双面板可选阶段（M33-R1，
//! `longrun` 子命令——不在 ci 门禁内）。每个阶段的输出追加写入日志目录
//! （源码树外），失败即中断并返回非零码（fail-fast）。
//!
//! 用法：`cargo run -p xtask -- <ci|smoke|check|test|report|lint|idl-gen|idl-check|longrun>`；
//! 无参数默认 `ci`。

mod idl;
mod lint;
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

/// S5c-lint 闸：依赖矩阵对照 + unsafe 台账扫描（M24-X1；违规即拒）。
fn lint_gate() -> bool {
    let violations = lint::run(WORKSPACE_ROOT);
    if violations > 0 {
        if let Ok(mut f) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file("S5c-lint"))
        {
            let _ = writeln!(f, "VIOLATIONS: {violations}");
        }
    }
    violations == 0
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

/// 自检标记总数（与内核 SELFTEST_TOTAL 同步；M12 完成态 = 43，M13-② 起 46，M15 起 52，M16 起 55，M17 起 58，M18 起 62，M21-③ 起 63，M23 起 65，M23-B 起 67，M23-C1 起 68，M23-C2 起 69，M23-C3 起 71，M24-S1 起 72，M24-C1 起 73，M25-T1 起 75，M26-T1 起 76，M28-T1 起 77，M27-N2 起 78，M31-T1 起 80，M32-T1 起 81，M33-T1 起 82，M34-B2 起 83，M35-BBa 起 84，M35-BBb 起 85，M36-N1 起 86，M36-BB3b 起 87，M37-A1b 起 88，M37-N1 起 89，M38-SP1 起 90，M38-TCP1 起 91，M39-BBLS 起 92，M39-MU 起 93，M39-DPMS 起 94；M40-ASH2 t95 备置撤闸空缺跳号如实登记；M40-CRYSTAL t96 起 95；M40-CAT t97 起 96；M41-笔① t95 转正（栈 grow 缺陷族修复落域）起 97；M41-笔② t98（块层字节域取证矩阵）起 98；M41-笔③ t99（saved-set+补充组矩阵）起 99；M41-笔④ t100（ash 交互面）起 100；M42-FBDEV1 t101（用户态 fb 驱动进程移交链）起 101；M42-FBSVC2 t102（常驻 fbdev 服务活体）起 102；M42-UNIX3 t103（unix socket 域 + Wayland wire 语义面活体）起 103；M42-COMP4 t104（合成器进程面：常驻 waycomp 合流电气面 + 阻塞 accept/EOF 对端终结面 + cascade 仲裁策略承接）起 104；M42-ELF5 t105（用户态 ELF 播种 lane：ring3 编译进程承接）+ t106（桌面链 wl_shm/fd 传递活体）起 106）。
const SELFTEST_EXPECTED: &str = "109/109";

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

/// M33-F1：busybox 介质路径（multiboot module 通道 = QEMU `-initrd`）。
/// 缺位时 S8 fail-visible（制备证据链必修；一次性获取 =
/// scripts/busybox-fetch.sh）。
const BUSYBOX_MEDIA: &str = "/home/z/my-project/lumina-build/runtime/busybox/busybox";

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
    // 0c) M33-F1 busybox 介质就位检查（fail-visible：S8 起制备链必修）
    let busybox_ok = std::path::Path::new(BUSYBOX_MEDIA)
        .metadata()
        .map(|m| m.len() > 0)
        .unwrap_or(false);
    if !busybox_ok {
        eprintln!(
            "[FAIL] S8-smoke：busybox 介质缺位：{BUSYBOX_MEDIA}（一次性获取：sh scripts/busybox-fetch.sh）"
        );
        return false;
    }
    eprintln!("[S8-smoke] busybox 介质在位：{BUSYBOX_MEDIA}");
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
    // M30-X1 t73 取证升级（滤波升级）：LUMINA_S8_PCAP 环境门控 filter-dump
    // 全账捕获——"1" 用默认路径，其余值为显式路径；unset 时零行为变化
    // （默认参数面不变）。捕获层在 netdev 侧，客户机 RX 通路设备级死亡
    // （M27-R1 实证「used 回写 ≠ 交付 netdev」B 面）与 A 面回声窗都在账。
    let pcap_path = match std::env::var("LUMINA_S8_PCAP") {
        Ok(v) if v == "1" => Some("/home/z/my-project/lumina-build/logs/t73-hunt.pcap".to_string()),
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    };
    let mut qemu_args: Vec<String> = vec![
        "-L",
        QEMU_BIOS_SEABIOS,
        "-L",
        QEMU_BIOS_DATA,
        "-kernel",
        KERNEL_BIN,
        "-initrd",
        BUSYBOX_MEDIA,
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
    ]
    .into_iter()
    .map(String::from)
    .collect();
    // M33-T1 取证门控：LUMINA_QEMU_INT=1 → QEMU -d int 异常级 trace
    // （QEMU 视角的 #PF err/cr2/walk 落盘，页表层取证对账用；unset 零行为）
    if std::env::var("LUMINA_QEMU_INT").as_deref() == Ok("1") {
        qemu_args.push("-d".into());
        qemu_args.push("int".into());
        qemu_args.push("-D".into());
        qemu_args.push("/home/z/my-project/lumina-build/logs/qemu-int.log".into());
    }
    if let Some(path) = &pcap_path {
        qemu_args.push("-object".into());
        qemu_args.push(format!("filter-dump,id=pcapf0,netdev=n0,file={path}"));
        println!("[S8-smoke] pcap 滤波捕获在案：{path}");
    }
    let mut child = match Command::new(QEMU_BIN)
        .args(&qemu_args)
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
    //    （M31-W1 起：Weave 自举装载证据行在环——机器可验）
    let selftest_marker = format!("LUMINA-SELFTEST-PASS {SELFTEST_EXPECTED}");
    let required: [&[u8]; 61] = [
        b"LUMINA-BOOT-OK",
        selftest_marker.as_bytes(),
        b"LUMINA-TLV-OK",
        b"USER-OK",
        b"user done: exit=42",
        b"LUMINA-WEAVE-BOOT",
        // M33-T1：busybox echo applet 串口取证（ELF 装载 → Linux syscall
        // 面 → musl 初始化全链活体；介质缺位时 S8 前置检查已 fail-visible）
        b"LUMINA-T82-OK",
        // M34-B2：applet 扩容活体（true/false/printf/wc -l 四 applet 分发
        // 路径 + exit 码语义对账；t83 相位汇总标记）
        b"LUMINA-T83-OK",
        // M35-BBb：sh 流水线活体（`|` 解析 → fork+pipe2+dup2+execve 两段
        // 串联——yes|head 真流管道 + exit 码对账；t85 相位汇总标记）
        b"LUMINA-T85-OK",
        // M36-BB3b：阻塞管道活体（缺省阻塞语义四相位——写醒读字节级
        // 回显 LUMINA-T87-WAKE + t87 相位汇总标记）
        b"LUMINA-T87-OK",
        b"LUMINA-T87-WAKE",
        // M37-A1b：多 Surface alpha 合成活体（SurfaceTable→Stack blend
        // 电气化——over 手算锚 VRAM 读回 + t88 相位汇总标记）
        b"LUMINA-T88-BLEND",
        b"LUMINA-T88-OK",
        // M37-N1：TCP 重传面活体（TSC 纳秒 RTO 臂电重发 + 乱序重组拼接
        // + 外部 RX 对接收口——t89 重传电证据行 + 相位汇总标记）
        b"LUMINA-T89-RETX",
        b"LUMINA-T89-OK",
        // M38-SP1：阻塞臂握手旗活体（M22-③ 空槽切换竞态专项——四风暴
        // 跨核 block/wake 交叉域压力 + 四锚断言；t90 取证行 + 相位汇总标记）
        b"LUMINA-T90-HANDOFF",
        b"LUMINA-T90-OK",
        // M38-TCP1：TCP 服务化批次活体（五面连接表驱动——双连接并行交付
        // + Karn 窄化 + 拥塞折叠回升 + 零窗探测电击发 + 窗缩放有效窗；
        // t91 取证行 + 相位汇总标记）
        b"LUMINA-T91-TCP",
        b"LUMINA-T91-OK",
        // M39-BBLS：busybox ls 深链活体（乱序目录制备 → ls -1 派生消费
        // → 排序输出串口取证——AAA/ZZZ 位置序断言随面板尾 + readlink
        // 双相位；t92 取证行 + 相位汇总标记）
        b"LUMINA-T92-LS",
        b"LUMINA-T92-OK",
        b"LUMINA-T92-AAA",
        b"LUMINA-T92-ZZZ",
        // M39-MU：多用户纵深活体（凭据四元真面 + setuid 根域收口 + 权限
        // 门禁覆盖表——busybox id 领域换装消费 uid=1000 串口取证；t93
        // 相位汇总标记）
        b"LUMINA-T93-MU",
        b"LUMINA-T93-OK",
        b"uid=1000",
        // M39-DPMS：DPMS 电气面活体（SR01 消隐位 + Misc Output 同步极性
        // 域写/读回 + blank/unblank 登记面电气挂接；t94 相位汇总标记）
        b"LUMINA-T94-DPMS",
        b"LUMINA-T94-OK",
        // M41-笔①：ash 启动链活体转正（栈 grow 缺陷族 × syscall entry
        // 致命域修复——CPL0 用户栈 push #PF 漏救域收口；ash -c 'exit 7'
        // 全量启动链活体收割；t95 相位汇总标记）
        b"LUMINA-T95-ASH",
        b"LUMINA-T95-OK",
        // M41-笔②：块层字节域取证矩阵活体（M17-① 标本清账——值域矩阵
        // 八组 × 同/跨调用 × 双文件交替哨兵 × 持久化对账；t98 标记）
        b"LUMINA-T98-M17",
        b"LUMINA-T98-OK",
        // M41-笔③：多用户纵深二批活体（saved-set 三态交换链 +
        // setgroups/getgroups 双面 + 补充组盘上门禁矩阵；t99 标记）
        b"LUMINA-T99-MU2",
        b"LUMINA-T99-OK",
        // M41-笔④：ash 交互面活体（busybox sh 无 -c 交互模式 + kbd 字节
        // 直注入 + 阻塞式 tty read 端到端；t100 标记）
        b"LUMINA-T100-ASH",
        b"LUMINA-T100-OK",
        // M42-阶段一 笔①：用户态 fb 驱动进程移交链活体（LFB 映射移交 +
        // SYS_DEV_PIO 端口裁量 + svc Owner 用户态承接；t101 标记）
        b"LUMINA-T101-FBDEV",
        b"LUMINA-T101-OK",
        // M42-阶段一 笔②：常驻 fbdev 服务活体（服务环/IPC 通道铸造挂接
        // + Owner 移交链 + 常驻服务映像 PAINT_RECT/越域拒绝/QUIT + VRAM
        // 双漆读回；t102 标记）
        b"LUMINA-T102-FBSVC",
        b"LUMINA-T102-OK",
        // M42-阶段二 笔③：unix socket 域 + Wayland wire 语义面活体
        //（socketpair/连接面/阻塞唤醒链/流短写 + prism::wayland 编组
        // 解析回环 + close 对象存续纪律；t103 标记）
        b"LUMINA-T103-UNIX",
        b"LUMINA-T103-OK",
        // M42-阶段三 笔④：合成器进程面活体（常驻 waycomp 合流电气面
        //——unix socket 域 ⇄ wire 壳 ⇄ SYS_FB_SURFACE + 阻塞 accept/
        // EOF 对端终结面 + cascade 仲裁策略承接 + VRAM 模式读回/回退
        // 对账；t104 标记）
        b"LUMINA-T104-COMP",
        b"LUMINA-T104-OK",
        // M42-次笔 域①：用户态 ELF 播种 lane 活体（ring3 编译进程承接
        //——真 ELF64 静态映像原生 ABI 播种 + 结构闸负例 + exit=77
        // 收割；t105 标记）
        b"LUMINA-T105-ELF",
        b"LUMINA-T105-R3",
        b"LUMINA-T105-OK",
        // M42-次笔 域②：桌面链 wl_shm/fd 传递活体（SYS_SHM 池域 +
        // SCM_RIGHTS 语义面 + waycomp 池承接 + 客户端像素 VRAM 断言 +
        // teardown 复原；t106 标记）
        b"LUMINA-T106-CLIENT",
        b"LUMINA-T106-SHM",
        b"LUMINA-T106-OK",
        // M42-本笔 域①：重排改写面活体（UPDATE 几何演进——policy_rewrite
        // 策略驱动几何演进 + DropLog 摘除传播 + 形状锁退役；t107 标记）
        b"LUMINA-T107-GEOM",
        b"LUMINA-T107-OK",
        // M42-本笔 域②：fbdev 驱动进程 ELF 化迁移活体（spawn_elf_seed_
        // wired 接线域 + resident × ELF lane 交叉 + pio 授权生命周期闭环
        // + 服务环回环；t108 标记）
        b"LUMINA-T108-ELFSVC",
        b"LUMINA-T108-OK",
        // M42-INPUT7 笔⑦：waycomp 主体迁移前置活体（native 编译进程链
        // + wl_seat/wl_keyboard 输入链 + 指针键盘事件语义面；t109 标记）
        b"LUMINA-T109-INPUT",
        b"LUMINA-T109-OK",
        // M40-CRYSTAL：盘上属主域活体（InodeRec v2 属主三域 + chown/
        // chmod 车道 + stat 真面 + 门禁回源 + 持久化对账；t96 标记）
        b"LUMINA-T96-OWN",
        b"LUMINA-T96-OK",
        // M40-CAT：cat applet 实证（制备载荷 + cat 派生消费——内容级
        // 断言标记〔载荷即标记〕+ sendfile 车道 + 负例；t97 标记）
        b"LUMINA-T97-CAT",
        b"LUMINA-T97-OK",
        // M34-D1：驱动服务框架结构面 boot 注册证据（五驱动内核态占位）
        b"LUMINA-SVC-INIT",
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
    // t92 排序取证：ls 输出字典序断言（制备反相 ZZZ 首建 vs 输出 AAA
    // 首行——pos(AAA) < pos(ZZZ)；缺席由 required 面报，此处只判序）
    if let (Some(pa), Some(pz)) = (
        find(all.as_slice(), b"LUMINA-T92-AAA"),
        find(all.as_slice(), b"LUMINA-T92-ZZZ"),
    ) {
        if pa >= pz {
            eprintln!("[FAIL] S8-smoke：t92 排序取证失序（pos(AAA)={pa} >= pos(ZZZ)={pz}）");
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

// ================= M33-R1：S10-longrun 长稳双面板（可选阶段，不在 ci 门禁） =================
//
// Panel A：busybox boot-cycle 循环——每拍 = S8 同款全口径引导（自检
//   82/82 + TLV 往返 + t82 busybox echo 活体 + 退出码 33），时长/最小
//   拍数双闸，逐拍心跳落 S10-longrun-a.log。
// Panel B：1080p@60 显示 tick——kernel `longrun` 特性映像（自检通过后
//   非退出路径），就绪标记后预算窗心跳采集，到时强杀按判定面成像。
// 正式 24h/72h 门禁记录待真机窗口挂账（M33-R1 口径登记——风险登记册
// 既定裁决：TCG 回归基线制，环境 B 级实测标记「待真机窗口」）。

/// Panel A 默认时长（秒）：24h = 86 400。LUMINA_LONGRUN_A_SECS 可覆写。
const LONGRUN_A_SECS: u64 = 86_400;
/// Panel B 默认预算（秒）：72h = 259 200，自 LUMINA-LONGRUN-B-ON 就绪
/// 标记起算（引导期不占预算）。LUMINA_LONGRUN_B_SECS 可覆写。
const LONGRUN_B_SECS: u64 = 259_200;
/// Panel A 最小拍数（正式口径 1；短窗实证 2——确定性双拍分钟级采样）。
const LONGRUN_A_CYCLES_MIN: u64 = 1;
/// 短窗实证 Panel A 最小拍数。
const LONGRUN_SHORT_A_CYCLES_MIN: u64 = 2;
/// 短窗实证 Panel B 预算（秒）。
const LONGRUN_SHORT_B_SECS: u64 = 30;
/// 单拍/引导期看门狗（S8 同款 150 s）。
const LONGRUN_BOOT_WATCHDOG_SECS: u64 = 150;
/// 长稳特性内核裸映像（Panel B 专用 objcopy 产物——与 S8 KERNEL_BIN
/// 分离，门禁标准映像零触碰）。
const KERNEL_LONGRUN_BIN: &str =
    "/home/z/my-project/lumina-build/target/x86_64-unknown-none/release/lumina-kernel-longrun.bin";

/// 长稳环境整数读取（缺省/空 = 默认口径；非法值 fail-visible 文案回传）。
fn longrun_env_u64(name: &str, default: u64) -> Result<u64, String> {
    match std::env::var(name) {
        Err(_) => Ok(default),
        Ok(v) if v.is_empty() => Ok(default),
        Ok(v) => v
            .parse::<u64>()
            .map_err(|_| format!("{name}={v} 非法（须为非负整数）")),
    }
}

/// 长稳 QEMU 公共参数面（S8 同款：multiboot1 + 双盘 + 256M + 双核 +
/// virtio-net + isa-debug-exit；pcap/int 取证门控不进长稳面——长稳证据
/// 口径纯净，环境变量零依赖）。
fn longrun_qemu_args(kernel_bin: &str) -> Vec<String> {
    let swap_drive = format!("file={SWAP_IMG},format=raw,if=ide,index=2,media=disk");
    let disk_drive = format!("file={DISK_IMG},format=raw,if=ide,index=1,media=disk");
    vec![
        "-L",
        QEMU_BIOS_SEABIOS,
        "-L",
        QEMU_BIOS_DATA,
        "-kernel",
        kernel_bin,
        "-initrd",
        BUSYBOX_MEDIA,
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
        "-device",
        "virtio-net-pci,netdev=n0,disable-legacy=on",
        "-netdev",
        "user,id=n0",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// 长稳看门狗（S8 同款机制）：到时 kill -9（步进睡眠，done 置位提前
/// 收工）。
fn longrun_watchdog(
    pid: u32,
    secs: u64,
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        for _ in 0..secs {
            if done.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        let _ = Command::new("kill").args(["-9", &pid.to_string()]).output();
    })
}

/// TLV 应答帧校验（S8 同款协议：tag 0x8007 + len 13 + value
/// lumina-m5-ACK）。返回 (resp_checked, tlv_ok) 两态；应答帧未到全时
/// 调用方逐读迭代重查（帧完整即收口，语义与 S8 流式判定一致）。
fn longrun_tlv_check(all: &[u8]) -> (bool, bool) {
    let Some(pos) = find(all, b"LUMINA-TLV-RESP:") else {
        return (false, false);
    };
    let mut frame_start = pos + b"LUMINA-TLV-RESP:".len();
    if all.len() > frame_start + 2 && &all[frame_start..frame_start + 2] == b"\r\n" {
        frame_start += 2;
    }
    let need = 4 + TLV_RESP_VALUE_LEN;
    if all.len() < frame_start + need {
        return (false, false);
    }
    let f = &all[frame_start..frame_start + need];
    let tag = u16::from_le_bytes([f[0], f[1]]);
    let len = u16::from_le_bytes([f[2], f[3]]) as usize;
    let value = &f[4..];
    (
        true,
        tag == 0x8007 && len == TLV_RESP_VALUE_LEN && value == &b"lumina-m5-ACK"[..],
    )
}

/// 引导链标记面断言（S8 required 七标记 + TLV 往返——Panel A/B 共用；
/// 返回失败清单，空 = 全过）。
fn longrun_boot_fails(serial: &[u8], tlv_ok: bool, resp_checked: bool) -> Vec<String> {
    let mut fails = Vec::new();
    let selftest_marker = format!("LUMINA-SELFTEST-PASS {SELFTEST_EXPECTED}");
    let markers: [&[u8]; 61] = [
        b"LUMINA-BOOT-OK",
        selftest_marker.as_bytes(),
        b"LUMINA-TLV-OK",
        b"USER-OK",
        b"user done: exit=42",
        b"LUMINA-WEAVE-BOOT",
        b"LUMINA-T82-OK",
        b"LUMINA-T83-OK",
        b"LUMINA-T85-OK",
        b"LUMINA-T87-OK",
        b"LUMINA-T87-WAKE",
        b"LUMINA-T88-BLEND",
        b"LUMINA-T88-OK",
        b"LUMINA-T89-RETX",
        b"LUMINA-T89-OK",
        b"LUMINA-T90-HANDOFF",
        b"LUMINA-T90-OK",
        b"LUMINA-T91-TCP",
        b"LUMINA-T91-OK",
        b"LUMINA-T92-LS",
        b"LUMINA-T92-OK",
        b"LUMINA-T92-AAA",
        b"LUMINA-T92-ZZZ",
        b"LUMINA-T93-MU",
        b"LUMINA-T93-OK",
        b"uid=1000",
        b"LUMINA-T94-DPMS",
        b"LUMINA-T94-OK",
        b"LUMINA-T95-ASH",
        b"LUMINA-T95-OK",
        b"LUMINA-T96-OWN",
        b"LUMINA-T96-OK",
        b"LUMINA-T98-M17",
        b"LUMINA-T98-OK",
        b"LUMINA-T99-MU2",
        b"LUMINA-T99-OK",
        b"LUMINA-T100-ASH",
        b"LUMINA-T100-OK",
        // M42-阶段一 笔①：用户态 fb 驱动进程移交链活体（LFB 映射移交 +
        // SYS_DEV_PIO 端口裁量 + svc Owner 用户态承接；t101 标记）
        b"LUMINA-T101-FBDEV",
        b"LUMINA-T101-OK",
        // M42-阶段一 笔②：常驻 fbdev 服务活体（服务环/IPC 通道铸造挂接
        // + Owner 移交链 + 常驻服务映像 PAINT_RECT/越域拒绝/QUIT + VRAM
        // 双漆读回；t102 标记）
        b"LUMINA-T102-FBSVC",
        b"LUMINA-T102-OK",
        // M42-阶段二 笔③：unix socket 域 + Wayland wire 语义面活体
        //（socketpair/连接面/阻塞唤醒链/流短写 + prism::wayland 编组
        // 解析回环 + close 对象存续纪律；t103 标记）
        b"LUMINA-T103-UNIX",
        b"LUMINA-T103-OK",
        // M42-阶段三 笔④：合成器进程面活体（常驻 waycomp 合流电气面
        //——unix socket 域 ⇄ wire 壳 ⇄ SYS_FB_SURFACE + 阻塞 accept/
        // EOF 对端终结面 + cascade 仲裁策略承接 + VRAM 模式读回/回退
        // 对账；t104 标记）
        b"LUMINA-T104-COMP",
        b"LUMINA-T104-OK",
        // M42-次笔 域①②：ELF 播种 lane + 桌面链 wl_shm/fd 传递活体
        //（t105/t106 标记）
        b"LUMINA-T105-ELF",
        b"LUMINA-T105-R3",
        b"LUMINA-T105-OK",
        b"LUMINA-T106-CLIENT",
        b"LUMINA-T106-SHM",
        b"LUMINA-T106-OK",
        // M42-本笔：重排改写面 + fbdev ELF 化迁移活体（t107/t108 标记）
        b"LUMINA-T107-GEOM",
        b"LUMINA-T107-OK",
        b"LUMINA-T108-ELFSVC",
        b"LUMINA-T108-OK",
        // M42-INPUT7 笔⑦：waycomp 主体迁移前置活体（native 编译进程链
        // + wl_seat/wl_keyboard 输入链 + 指针键盘事件语义面；t109 标记）
        b"LUMINA-T109-INPUT",
        b"LUMINA-T109-OK",
        b"LUMINA-T97-CAT",
        b"LUMINA-T97-OK",
        b"LUMINA-SVC-INIT",
    ];
    for marker in markers {
        if find(serial, marker).is_none() {
            fails.push(format!("缺标记 {}", String::from_utf8_lossy(marker)));
        }
    }
    // t92 排序取证：ls 输出字典序断言（pos(AAA) < pos(ZZZ)；缺席由
    // required 面报，此处只判序）
    if let (Some(pa), Some(pz)) = (
        find(serial, b"LUMINA-T92-AAA"),
        find(serial, b"LUMINA-T92-ZZZ"),
    ) {
        if pa >= pz {
            fails.push(format!(
                "t92 排序取证失序（pos(AAA)={pa} >= pos(ZZZ)={pz}）"
            ));
        }
    }
    if !resp_checked {
        fails.push("未收到 TLV 应答帧".into());
    } else if !tlv_ok {
        fails.push("TLV 应答帧校验失配".into());
    }
    fails
}

/// Panel A 单拍证据（串口全文 + 退出码 + TLV 两态）。
struct CycleRun {
    serial: Vec<u8>,
    exit: i32,
    tlv_ok: bool,
    resp_checked: bool,
}

/// Panel A 单拍：全口径引导（S8 同款断言面）+ 退出码 33。看门狗 150 s；
/// 管道/等待失败 = Err（fail-visible）。
fn longrun_cycle_a(kernel_bin: &str) -> Result<CycleRun, String> {
    let mut child = Command::new(QEMU_BIN)
        .args(longrun_qemu_args(kernel_bin))
        .env("LD_LIBRARY_PATH", QEMU_LIB)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("QEMU 启动失败：{e}"))?;
    let pid = child.id();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let wd = longrun_watchdog(
        pid,
        LONGRUN_BOOT_WATCHDOG_SECS,
        std::sync::Arc::clone(&done),
    );
    let Some(mut stdout) = child.stdout.take() else {
        return Err("stdout 管道缺失".into());
    };
    let Some(mut stdin) = child.stdin.take() else {
        return Err("stdin 管道缺失".into());
    };
    let mut all: Vec<u8> = Vec::new();
    let mut buf = [0u8; 512];
    let mut sent = false;
    let mut resp_checked = false;
    let mut tlv_ok = false;
    loop {
        match stdout.read(&mut buf) {
            Ok(0) => break, // EOF（进程退出）
            Ok(n) => all.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
        if !sent && find(&all, b"LUMINA-HOSTLINK-READY").is_some() {
            if stdin
                .write_all(TLV_REQ)
                .and_then(|_| stdin.flush())
                .is_err()
            {
                return Err("TLV 请求写入失败".into());
            }
            sent = true;
        }
        if sent && !resp_checked {
            let (rc, tok) = longrun_tlv_check(&all);
            resp_checked = rc;
            tlv_ok = tok;
        }
    }
    drop(stdin);
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = wd.join();
    let out = child.wait().map_err(|e| format!("wait 失败：{e}"))?;
    Ok(CycleRun {
        serial: all,
        exit: out.code().unwrap_or(-1),
        tlv_ok,
        resp_checked,
    })
}

/// Panel A：busybox boot-cycle 循环（时长预算 + 最小拍数双闸——
/// `cycles >= cycles_min && elapsed >= a_secs` 收束）。心跳逐拍落
/// S10-longrun-a.log；失败拍串口全文落盘后 fail-fast。
fn longrun_panel_a(kernel_bin: &str, a_secs: u64, cycles_min: u64) -> Result<String, String> {
    let t0 = Instant::now();
    let mut cycles: u64 = 0;
    let mut total_ms: u128 = 0;
    loop {
        let c0 = Instant::now();
        let run = longrun_cycle_a(kernel_bin)?;
        cycles += 1;
        total_ms += c0.elapsed().as_millis();
        let mut fails = longrun_boot_fails(&run.serial, run.tlv_ok, run.resp_checked);
        if run.exit != 33 {
            fails.push(format!("退出码 {} ≠ 33（内核未完成自检退出）", run.exit));
        }
        if let Ok(mut f) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file("S10-longrun-a"))
        {
            let _ = writeln!(
                f,
                "cycle={cycles} exit={} ms={} tlv={} fails={}",
                run.exit,
                c0.elapsed().as_millis(),
                run.tlv_ok,
                fails.len()
            );
        }
        if !fails.is_empty() {
            let _ = std::fs::write(
                format!("{BUILD_ROOT}/logs/S10-longrun-a-fail-cycle-{cycles}.log"),
                &run.serial,
            );
            return Err(format!("Panel A 第 {cycles} 拍失败：{}", fails.join("；")));
        }
        if cycles >= cycles_min && t0.elapsed().as_secs() >= a_secs {
            break;
        }
    }
    let avg = total_ms / u128::from(cycles.max(1));
    Ok(format!(
        "LUMINA-LONGRUN-A PASS cycles={cycles} avg_ms={avg}"
    ))
}

/// 心跳行 tick 值提取（"tick=" 后首个十进制段；无数字/溢出 = None）。
fn longrun_tick_of(line: &[u8]) -> Option<u64> {
    let pos = find(line, b"tick=")?;
    let rest = &line[pos + b"tick=".len()..];
    let first = *rest.first()?;
    if !first.is_ascii_digit() {
        return None;
    }
    let mut v: u64 = 0;
    for &b in rest {
        if !b.is_ascii_digit() {
            break;
        }
        v = v.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    Some(v)
}

/// Panel B：1080p@60 显示 tick 长稳单发（kernel longrun 特性映像）。
/// 引导至 LUMINA-LONGRUN-B-ON（引导看门狗 150 s；TLV 喂入同 Panel A）→
/// 预算窗 b_secs 心跳采集 → kill -9 收束 → 判定面：引导链标记全量 /
/// 就绪标记在案 / 无 FAULT 行 / 心跳 ≥2 / tick 严格单调 / 被强杀收束
/// （exit=-1；内核侧提前自退即异常显形）。fps = 末拍 tick ÷ 预算窗秒
/// （信息面记录——60fps 闸归真机窗口，M33-R1 口径）。
fn longrun_panel_b(kernel_bin: &str, b_secs: u64) -> Result<String, String> {
    let mut child = Command::new(QEMU_BIN)
        .args(longrun_qemu_args(kernel_bin))
        .env("LD_LIBRARY_PATH", QEMU_LIB)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("QEMU 启动失败：{e}"))?;
    let pid = child.id();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let wd = longrun_watchdog(
        pid,
        LONGRUN_BOOT_WATCHDOG_SECS + b_secs + 15,
        std::sync::Arc::clone(&done),
    );
    let Some(mut stdout) = child.stdout.take() else {
        return Err("stdout 管道缺失".into());
    };
    let Some(mut stdin) = child.stdin.take() else {
        return Err("stdin 管道缺失".into());
    };
    let mut all: Vec<u8> = Vec::new();
    let mut buf = [0u8; 512];
    let mut sent = false;
    let mut resp_checked = false;
    let mut tlv_ok = false;
    let mut on_at: Option<Instant> = None;
    let mut killed = false;
    loop {
        match stdout.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => all.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
        if !sent && find(&all, b"LUMINA-HOSTLINK-READY").is_some() {
            if stdin
                .write_all(TLV_REQ)
                .and_then(|_| stdin.flush())
                .is_err()
            {
                return Err("TLV 请求写入失败".into());
            }
            sent = true;
        }
        if sent && !resp_checked {
            let (rc, tok) = longrun_tlv_check(&all);
            resp_checked = rc;
            tlv_ok = tok;
        }
        if on_at.is_none() && find(&all, b"LUMINA-LONGRUN-B-ON").is_some() {
            on_at = Some(Instant::now());
        }
        if let Some(t0) = on_at {
            if t0.elapsed().as_secs() >= b_secs {
                let _ = Command::new("kill").args(["-9", &pid.to_string()]).output();
                killed = true;
                break;
            }
        }
    }
    // 强杀后残量排空（末段心跳收账——管道 EOF 即止）
    let _ = stdout.read_to_end(&mut all);
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = wd.join();
    let out = child.wait().map_err(|e| format!("wait 失败：{e}"))?;
    let exit = out.code().unwrap_or(-1);

    let mut fails = longrun_boot_fails(&all, tlv_ok, resp_checked);
    if find(&all, b"LUMINA-LONGRUN-B-ON").is_none() {
        fails.push("长稳就绪标记缺失（未进入 Panel B tick 循环）".into());
    }
    if find(&all, b"LUMINA-LONGRUN-B-FAULT").is_some() {
        fails.push("LUMINA-LONGRUN-B-FAULT 在案（tick 交盒/同步失配显形）".into());
    }
    let mut ticks: Vec<u64> = Vec::new();
    for line in all.split(|&b| b == b'\n') {
        if find(line, b"LUMINA-LONGRUN-B tick=").is_some() {
            match longrun_tick_of(line) {
                Some(t) => ticks.push(t),
                None => fails.push("心跳行 tick 解析失败".into()),
            }
        }
    }
    if ticks.len() < 2 {
        fails.push(format!("心跳数 {} < 2", ticks.len()));
    }
    for w in ticks.windows(2) {
        if w[1] <= w[0] {
            fails.push(format!("tick 非单调：{} → {}", w[0], w[1]));
            break;
        }
    }
    if !killed {
        fails.push(format!(
            "未被强杀收束（exit={exit}——内核侧提前退出即异常显形）"
        ));
    }
    let last_tick = ticks.last().copied().unwrap_or(0);
    let fps = if b_secs > 0 {
        last_tick as f64 / b_secs as f64
    } else {
        0.0
    };
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file("S10-longrun-b"))
    {
        let _ = writeln!(
            f,
            "panel_b b_secs={b_secs} heartbeats={} first_tick={:?} last_tick={last_tick} exit={exit} killed={killed} tlv={tlv_ok} fails={}",
            ticks.len(),
            ticks.first(),
            fails.len()
        );
    }
    if !fails.is_empty() {
        let _ = std::fs::write(format!("{BUILD_ROOT}/logs/S10-longrun-b-fail.log"), &all);
        return Err(format!("Panel B 失败：{}", fails.join("；")));
    }
    Ok(format!(
        "LUMINA-LONGRUN-B PASS ticks={last_tick} fps={fps:.1} heartbeats={}",
        ticks.len()
    ))
}

/// S10-longrun 实体：双面板顺序执行；返回是否全绿。步序（fail-fast）：
/// 介质三件就位 → 长稳特性 clippy（cfg 面 S6 不可见——boot,longrun 双
/// 特性显式收口）→ 标准内核构建+objcopy → Panel A → 长稳内核构建+
/// objcopy → Panel B（顺序纪律：Panel A 消费标准映像在前，长稳 variant
/// 覆写同一 ELF 路径在后——产物面单一事实源）。
fn longrun_inner() -> bool {
    stage_log_header("S10-longrun");
    let short = std::env::var("LUMINA_LONGRUN_SHORT").is_ok_and(|v| v == "1");
    let (a_def, b_def, c_def) = if short {
        (0, LONGRUN_SHORT_B_SECS, LONGRUN_SHORT_A_CYCLES_MIN)
    } else {
        (LONGRUN_A_SECS, LONGRUN_B_SECS, LONGRUN_A_CYCLES_MIN)
    };
    let (a_secs, b_secs, cycles_min) = match (
        longrun_env_u64("LUMINA_LONGRUN_A_SECS", a_def),
        longrun_env_u64("LUMINA_LONGRUN_B_SECS", b_def),
        longrun_env_u64("LUMINA_LONGRUN_A_CYCLES_MIN", c_def),
    ) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
            eprintln!("[FAIL] S10-longrun：{e}");
            return false;
        }
    };
    println!(
        "[S10-longrun] 口径：Panel A busybox 循环 a_secs={a_secs} cycles_min={cycles_min} / Panel B 1080p tick b_secs={b_secs}{}",
        if short {
            "（短窗实证）"
        } else {
            "（正式口径——24h/72h 门禁记录待真机窗口挂账）"
        }
    );
    // 0) 介质三件就位（S8 同款：双盘重建 + busybox 在位检查，fail-visible）
    if let Some(dir) = std::path::Path::new(SWAP_IMG).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if std::fs::write(SWAP_IMG, vec![0u8; 1024 * 1024]).is_err() {
        eprintln!("[FAIL] S10-longrun：swap scratch 盘创建失败：{SWAP_IMG}");
        return false;
    }
    if std::fs::write(DISK_IMG, vec![0u8; 1024 * 1024]).is_err() {
        eprintln!("[FAIL] S10-longrun：LFS1 数据盘创建失败：{DISK_IMG}");
        return false;
    }
    let busybox_ok = std::path::Path::new(BUSYBOX_MEDIA)
        .metadata()
        .map(|m| m.len() > 0)
        .unwrap_or(false);
    if !busybox_ok {
        eprintln!("[FAIL] S10-longrun：busybox 介质缺位：{BUSYBOX_MEDIA}（一次性获取：sh scripts/busybox-fetch.sh）");
        return false;
    }
    // 1) 长稳特性面 clippy——cfg(feature="longrun") 代码 S6（boot 单特性）
    //    不可见，双特性显式收口（lint 纪律：特性面同在环）
    if run_logged(
        "S10-longrun",
        "cargo",
        &[
            "clippy",
            "-p",
            "lumina-kernel",
            "--features",
            "boot,longrun",
            "--target",
            "x86_64-unknown-none",
            "--",
            "-D",
            "warnings",
        ],
    ) != Some(0)
    {
        eprintln!("[FAIL] S10-longrun：kernel clippy(boot,longrun) 未过，详见 S10-longrun.log");
        return false;
    }
    // 2) 标准内核构建 + objcopy（Panel A 映像）
    if run_logged(
        "S10-longrun",
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
    ) != Some(0)
    {
        eprintln!("[FAIL] S10-longrun：标准内核构建失败，详见 S10-longrun.log");
        return false;
    }
    if run_logged(
        "S10-longrun",
        "objcopy",
        &["-O", "binary", KERNEL_ELF, KERNEL_BIN],
    ) != Some(0)
    {
        eprintln!("[FAIL] S10-longrun：objcopy 标准映像失败，详见 S10-longrun.log");
        return false;
    }
    // 3) Panel A：busybox boot-cycle 循环
    match longrun_panel_a(KERNEL_BIN, a_secs, cycles_min) {
        Ok(line) => println!("{line}"),
        Err(e) => {
            eprintln!("[FAIL] S10-longrun：{e}");
            return false;
        }
    }
    // 4) 长稳内核构建 + objcopy（Panel B 映像）——顺序纪律：Panel A 消费
    //    标准映像在前，长稳 variant 覆写同一 ELF 路径在后
    if run_logged(
        "S10-longrun",
        "cargo",
        &[
            "build",
            "-p",
            "lumina-kernel",
            "--features",
            "boot,longrun",
            "--release",
            "--target",
            "x86_64-unknown-none",
        ],
    ) != Some(0)
    {
        eprintln!("[FAIL] S10-longrun：长稳内核构建失败，详见 S10-longrun.log");
        return false;
    }
    if run_logged(
        "S10-longrun",
        "objcopy",
        &["-O", "binary", KERNEL_ELF, KERNEL_LONGRUN_BIN],
    ) != Some(0)
    {
        eprintln!("[FAIL] S10-longrun：objcopy 长稳映像失败，详见 S10-longrun.log");
        return false;
    }
    // 5) Panel B：1080p@60 显示 tick 预算窗
    match longrun_panel_b(KERNEL_LONGRUN_BIN, b_secs) {
        Ok(line) => println!("{line}"),
        Err(e) => {
            eprintln!("[FAIL] S10-longrun：{e}");
            return false;
        }
    }
    println!("S10-LONGRUN-OK");
    true
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
            println!("Lumina OS xtask ci —— 十一阶段门禁（宿主七阶段 + 内核三阶段 + 报告）");
            let mut results = run_stages(HOST_STAGES);
            if results.iter().all(|r| r.passed) {
                results.push(run_fn_stage("S5b-idl", idl_gate));
            }
            if results.iter().all(|r| r.passed) {
                results.push(run_fn_stage("S5c-lint", lint_gate));
            }
            if results.iter().all(|r| r.passed) {
                results.extend(run_stages(KERNEL_STAGES));
            }
            if results.iter().all(|r| r.passed) {
                results.push(run_smoke());
            }
            let total = HOST_STAGES.len() + 2 + KERNEL_STAGES.len() + 1;
            let all_passed = results.len() == total && results.iter().all(|r| r.passed);
            println!("{}", summarize(&results));
            match write_report(&results) {
                Ok(p) => println!("[S9-report] 报告已写入 {}", p.display()),
                Err(e) => eprintln!("[S9-report] 报告写入失败：{e}"),
            }
            if all_passed {
                println!("CI-OK：全部 {} 阶段通过（含 S9 报告）", total + 1);
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
                results.push(run_fn_stage("S5c-lint", lint_gate));
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
            // M41-S4F：harbor 测试面串行（--test-threads=1）——errno 面 =
            // 进程级全局 AtomicI32（errno.rs 文档口径），并行测试线程的
            // errno 写入互踩构成固有竞态（本机实录 strtol_overflow_erange
            // 二值翻车：期望 ERANGE(34) 读得 0——他线程 set_errno(0) 落窗）。
            // POSIX errno 语义 = 线程局部，harbor v0 = 进程全局——测试面
            // 与库模型对齐取串行，生产面零改动；workspace 其余套件并行不变。
            let code_harbor = run_logged(
                "S4-test",
                "cargo",
                &["test", "-p", "harbor", "--", "--test-threads=1"],
            );
            let code_rest = run_logged(
                "S4-test",
                "cargo",
                &["test", "--workspace", "--exclude", "harbor"],
            );
            let code = match (code_harbor, code_rest) {
                (Some(0), Some(0)) => Some(0),
                _ => Some(1),
            };
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
        "lint" => {
            let violations = lint::run(WORKSPACE_ROOT);
            if violations == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
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
        "longrun" => {
            println!(
                "Lumina OS xtask longrun —— S10 长稳双面板（可选阶段，M33-R1：Panel A busybox 循环 / Panel B 1080p@60 显示 tick）"
            );
            let t0 = Instant::now();
            let passed = longrun_inner();
            println!(
                "[{}] S10-longrun ({} ms)",
                if passed { "PASS" } else { "FAIL" },
                t0.elapsed().as_millis()
            );
            if passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        other => {
            eprintln!(
                "未知子命令：{other}；可用：ci | smoke | check | test | report | lint | idl-gen | idl-check | longrun"
            );
            ExitCode::FAILURE
        }
    }
}
