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

/// 自检标记总数（与内核 SELFTEST_TOTAL 同步；M12 完成态 = 43，M13-② 起 46，M15 起 52，M16 起 55，M17 起 58，M18 起 62，M21-③ 起 63，M23 起 65，M23-B 起 67，M23-C1 起 68，M23-C2 起 69，M23-C3 起 71，M24-S1 起 72，M24-C1 起 73，M25-T1 起 75，M26-T1 起 76，M28-T1 起 77，M27-N2 起 78，M31-T1 起 80，M32-T1 起 81，M33-T1 起 82，M34-B2 起 83，M35-BBa 起 84，M35-BBb 起 85，M36-N1 起 86，M36-BB3b 起 87，M37-A1b 起 88，M37-N1 起 89，M38-SP1 起 90，M38-TCP1 起 91，M39-BBLS 起 92，M39-MU 起 93，M39-DPMS 起 94；M40-ASH2 t95 备置撤闸空缺跳号如实登记；M40-CRYSTAL t96 起 95；M40-CAT t97 起 96；M41-笔① t95 转正（栈 grow 缺陷族修复落域）起 97；M41-笔② t98（块层字节域取证矩阵）起 98；M41-笔③ t99（saved-set+补充组矩阵）起 99；M41-笔④ t100（ash 交互面）起 100；M42-FBDEV1 t101（用户态 fb 驱动进程移交链）起 101；M42-FBSVC2 t102（常驻 fbdev 服务活体）起 102；M42-UNIX3 t103（unix socket 域 + Wayland wire 语义面活体）起 103；M42-COMP4 t104（合成器进程面：常驻 waycomp 合流电气面 + 阻塞 accept/EOF 对端终结面 + cascade 仲裁策略承接）起 104；M42-ELF5 t105（用户态 ELF 播种 lane：ring3 编译进程承接）+ t106（桌面链 wl_shm/fd 传递活体）起 106；M42-GEOM6 t107（重排改写面）+ t108（fbdev 驱动进程 ELF 化迁移活体）起 108；M42-INPUT7 t109（waycomp 主体迁移前置：输入链活体）起 109；M42-WAYCOMP8 t110（waycomp 主体 ELF 化迁移活体）起 110；M42-WAYCOMP9 笔⑨ t110 环内升级（客户端全谱 walk + 畸形拒收探针——WIRE 标记 +1，t 号/总数不变，双面板 65）；M42-WAYCOMP10 t111（内核 ISR/抢占路径寄存器契约面标本活体）起 111；M42-WAYCOMP11 笔⑪ t112（卫生批次活体：argv 真消费 + shm 池回收 + 服务重启面）起 112；M42-WAYCOMP12 笔⑫ t113（输入守护 + 阻塞等待双域活体）起 113；M42-WAYCOMP13 笔⑬ t114（evdev 键码映射 + keymap 内容面活体）起 114；M42-WAYCOMP14 笔⑭ t115（wl_pointer axis 族/frame 活体）起 115；M42-WAYCOMP15 笔⑮ t116（wl_keyboard modifiers 语义活体）起 116；M42-WAYCOMP16 笔⑯ t117（输入队列多产者域活体）起 117；M42-WAYCOMP17 笔⑰ t118（kbd→waycomp ISR 转接臂活体）起 118；M42-WAYCOMP18 笔⑱ t119（display.sync/wl_callback 多注册表面活体）起 119；M42-WAYCOMP19 笔⑲ t120（毫秒时间源活体）起 120；M42-DMG20 笔⑳ t121（damage 联合域 SYNC 矩形活体）起 121；M42-DMGC21 笔㉑ t122（commit 发布域批量化活体）起 122；M42-DMGC22 笔㉒ t123（frame callback delete_id 复用面活体）起 123；M42-DMGI24 笔㉔ t124（kbd→waycomp ISR 臂指针/轴域扩展活体）起 124；M42-AUX25 笔㉕ t125（PS/2 aux IRQ12 电气源接线活体）起 125；M42-RDTSC26 笔㉖ t126（rdtsc lfence 序列化读活体）起 126；M42-DMG27 笔㉗ t127（联合域上限细化活体）起 127；M42-DMG28 笔㉘ t128（指针 16px 粗粒度域联动活体）起 128；M42-SPRITE29 笔㉙ t129（光标 sprite 渲染面活体）起 129；M42-AUXR3 笔㉚ t130（ring3 aux 驱动进程活体）起 130；M42-PTRLINK 笔㉛ t131（Enter/Leave 域联动活体）起 131；M42-WHEEL32 笔㉜ t132（IntelliMouse 轮询命令链 + wl_pointer axis 电气源活体：标记五件——T132-ANCHOR/KNOCK/AXIS/SIGN/OK，双面板 130→135）起 132；M42-CLICKF33 笔㉝ t133（click-to-focus 焦点迁移联动面活体：标记五件——T133-BASE/CLICK/MIGRATE/IDEMP/OK，双面板 135→140）起 133；M42-KBREP34 笔㉞ t134（wl_keyboard.repeat_info 键重复公告面活体：标记四件——T134-ANCHOR/REPEAT/NEG/OK，双面板 140→144）起 134；M43-AV12036 笔㊱ t135（wl_pointer.axis_value120 离散步进语义活体：标记四件——T135-ANCHOR/V120/SIGN/OK，双面板 144→148）起 135；M43-KBREP37 笔㊷ t136（键重复生产域 + set_cursor 请求域活体：标记四件——T136-REPEATINFO/REPS/SETCUR/OK，双面板 148→152）起 136；M43-PRIO38 笔电解 t137（产者优先级域活体：标记四件——T137-ANCHOR/BOOT/SEMANTIC/OK，双面板 152→156）起 137；M43-TSC39 笔㊹ t138（TSC deadline one-shot 定时器活体：标记四件——T138-FEATURE/ENABLE/ONESHOT/OK，双面板 156→160）起 138；M43-HWDW40 笔㊺ t139（Explorer 型别链 + IMEX 族谱解码活体：标记五件——T139-ANCHOR/EXPLORER/HWDW/SIGN/OK，双面板 160→165）起 139；M43-CURSOR41 笔㊻ t140（光标直迁域活体：标记四件——T140-BASE/RELINK/IDEMP/OK，双面板 165→169）起 140；M44-MAP42 笔㊼ t141（创建期/map 域直迁活体：标记五件——T141-OPEN/IDEMP/CROSS/BACK/OK，双面板 169→174）起 141；M44-AUXW43 笔㊽ t142（boot wheel/explorer 接线切换活体：标记四件——T142-BOOT/FAMILY/V0/OK + boot 取证行 LUMINA-AUX-BOOT-EXPLORER 双面入列，双面板 174→179）起 142；M44-TSCRG44 笔㊾ t143（真机窗口 TSC deadline 全谱对账活体：标记四件——T143-FEATURE/ONESHOT/REARM/OK，双面板 179→183）起 143；M45-BIT245 笔㊿ t144（真机窗口 bit24=1 CPUID 逐位对账活体：标记四件——T144-AUTH/BITS/JUDGE/OK，双面板 183→187）起 144；M45-MPMC46 笔51 t145（MPMC 环替换 SpinLock 串行化活体：标记四件——T145-STRUCT/MPMC/ISR/OK，双面板 187→191）起 145；M45-RECON47 笔52 t146（真机窗口 bit24=1 实测对账活体：标记四件——T146-WINDOW/PLAN/ROUTE/OK，双面板 191→195）起 146；M46-LDEXEC49 笔55 t147（harbor 机械执行面 ld-lumina.so 交付批活体：ET_DYN 结构判读 + 装载映射/分级缓冲 + GNU 哈希决议链 + 重定位四类写面 + TLS Variant II 布点 + init/fini 互逆序 + dlopen 族 + H-P03 四段打点——标记六件——T147-MAP/RELOC/TLS/INIT/BUDGET/OK，双面板 195→201）起 147；M47-LDCONS53 笔60 t148（装载计划消费面 + ld-lumina.so 本体交付批活体：本体真件机械链 + exec_plan 消费动作序列 + ring3 消费活体〔SYS_MMAP(46)/SYS_MPROTECT(47) 双车道 + 映射页代码 call + 负例三目〕+ 登记面——标记六件——T148-SO/LIVE/REG/OK + 探针面 PROBE/ELEC，双面板 201→207）起 148；M47-DLOPEN54 笔61 t149（dlopen 真消费面活体：DT_NEEDED 装载序真消费链 + ring3 自装载链〔SYS_MMAP(46) 四窗 + rep movsb 拷贝 + ring3 重定位写面 + RX 终旗×2 + call ldlumina_boot + GOT[2] 间呼 core_fn + COPY 读回 + BSS 尾零 + 负例二目 → EXIT(89)〕+ 登记面四行——标记四件 T149-CHAIN/LIVE/REG/OK + 探针面 PROBE/ELEC，双面板 207→213）起 149）；M48-PLTGOT55 笔63 t150（PLT/GOT 惰性绑定电气执行活体——标记四件 T150-PLT/LIVE/REG/OK + 探针面 PROBE/ELEC，双面板 213→219）起 150）；M48-DLSYM56 笔64 t151（dlsym 跨模块查找电气面活体——标记四件 T151-SYM/LIVE/REG/OK + 探针面 PROBE/ELEC，双面板 219→225）起 151）；M48-INIT57 笔65 t152（init_array 执行域活体——标记四件 T152-SO/INIT/LEDGER/OK，双面板 225→229）起 152）；M49-DLCLOSE58 笔67 t153（dlclose 真消费链执行域活体——链卸载序真消费〔依赖先卸 + Kept 幂等 + 末次出册〕+ 单件链 fini 执行台账金值〔读回原值域 + 直取域 + 互逆〕+ 三负例——标记四件 T153-CLOSE/FINI/NEG/OK，双面板 229→233）起 153）；M49-FINI59 笔68 t154（.fini_array 终局执行域活体——终局 fini 台账 + 终局清算 + 两负例——标记四件 T154-EXIT/CLEAR/NEG/OK，双面板 233→237）起 154）；M49-TLS60 笔69 t155（TLS 执行域活体——四模型写面 + DTV 扩展真做 + 三负例——标记四件 T155-WRITE/DTV/NEG/OK，双面板 237→241）起 155）；M49-PGRP62 笔71 t156（进程组/会话域活体——语义核矩阵 + 真车道 + 新码首用——标记四件 T156-MATRIX/LIVE/NEG/OK，双面板 241→245）起 156）；M50-EEXEC65 笔75 t157（EACCES exec 记账域活体——语义核 EACCES 维度 e1..e4 + 真车道 ERR_ACCES(16) 新码首用 + 清位对照放行 + err_to_errno 映射核验——标记四件 T157-MATRIX/LIVE/NEG/OK，双面板 245→249）起 157）；M50-TEXT69 笔79 t158（文本渲染消费面活体——FONT8X16 两域 1520 B 直对账 + title_bar_px 全谱 + render_text 画布对账——标记三件 T158-ANCHOR/RENDER/OK，双面板 249→252）起 158）；M50-XDGSHELL67 笔77 t159（xdg_shell 电气闭环活体——真车道全生命周期 + 标题带动态域 + 会话面负例五目——标记四件 T159-LOOP/TITLE/NEG/OK，双面板 252→256）起 159）；M50-IOPB71 笔81 t160（IOPB 挂 TSS 硬件面活体——挂载取证三元组 + 位域全谱 + ring3 端口电气探针直呼 in/out GP 零显形收割 + 重建面负例——标记四件 T160-IOPB/LIVE/NEG/OK，双面板 256→260）起 160）；M50-MUSLRUN72 笔82 t161（musl 动态全链真件 ring3 真执行活体——双真件页域装载 + 解释器真车道 + 静态/损件双 NEG fail-visible——标记五件 T161-DYN/DYN-OK〔内容面〕/LIVE/NEG/OK，双面板 260→265）起 161）；M51-EXECDYN73 笔84 t162（ring3 SYS_EXEC 动态分流活体——动态分流臂 + 同任务 CR3 替换 musl 真执行 + NEG 三目——标记四件 T162-EXEC/LIVE/NEG/OK，双面板 265→269）起 162）；M51-VECFONT74 笔85 t163（矢量字体栅格化活体——真件语义锚 + python 同源金值对账 + NEG 三目——标记四件 T163-ANCHOR/RENDER/NEG/OK，双面板 269→273）起 163）；M51-XDGPOP75 笔86 t164（xdg_popup 尺寸交互族活体——真车道 popup/size 双车道〔size-configure(1904,944) 单窗盒金值 + placement(14,28) 官方定位公式金值 + min/max 双向钳 (1000,900) + 父窗收场 popup_done 派生域〕+ clamp_minmax 语义核全谱 + 会话面 NEG 七目——标记五件 T164-LOOP/POPUP/SIZE/NEG/OK，双面板 273→278）起 164）；M51-NIC76 笔87 t165（真实 NIC 驱动 Intel 82540EM 活体——PCI 8086:100E 探针 + BAR0 MMIO + CTRL.SLU/STATUS.LU 链路面 + MAC 双车道〔EERD 寄存器车道先行 + RAL/RAH 自动车道回退——车道戳实录〕+ TX/RX 描述符环装配 + ARP 电气回环〔slirp n1 独立网段 who-has 10.0.2.2 应答 spa 断言〕+ NEG 三目〔NotUp/BadLen/idle〕——标记四件 T165-BRINGUP/LIVE/NEG/OK，双面板 278→282）起 165）；M52-E1KIRQ77 笔89 t166（e1000 中断面活体——IOAPIC 路由基础设施〔0xFEC00000 恒等映射 + VERSION/entries 读出 + 全表 mask 收敛〕+ PCI int pin/line 读出 + route〔ISA line → 0x44，BSP LAPIC，level+low〕+ 写后读回五位域对账 + IMS 武装（TXDW|RXT0）+ ARP 二轮通知域计数推进 + NEG 三目〔屏蔽零送达/再武装推进/ICR 净域〕——标记四件 T166-IRQ/LIVE/NEG/OK，双面板 282→286）起 166；M52-POPCON78 笔90 t167（popup 约束域收口活体——place_in_bounds 官方施策序〔flip→slide→resize 逐轴 + 屏域裁剪〕+ v3 reposition 面〔repositioned→configure 官方序双事件〕+ 嵌套父域 + popup_done 传递闭包 + NEG 六目——标记五件 T167-LOOP/REPOS/NEST/NEG/OK，双面板 286→291）起 167）；M52-VULK79 笔91 t168（GPU 加速车道活体——prism::gfx 命令缓冲/队列语义面消费〔Vulkan vkCmd* 同构三域——Fill 行块加速 + Blit 行块/forward-copy + Blend Q8 定点混合〕+ 屏域裁剪 + fence 账户面 + 确定性感锚逐位一致——标记四件 T168-CMD/LIVE/NEG/OK，双面板 291→295）起 168）；M52-HWVULK80 笔92 t169（硬件 Vulkan 队列活体——标记四件 T169-QFAM/ICD/HW/OK）起 169；M52-PCIQLR81 笔93 t170（真机 PCI level+low 口径复评面活体——标记四件 T170-PROF/READBACK/NEG/OK，双面板 295→303〔T169/T170 八件入 required/longrun 双面〕）起 170）；M53-E1KNET82 笔95 t171（e1000↔pulse 接线活体——TX 组帧车道〔pulse::udp/pulse::tcp 官方编码核 + 伪头校验和〕+ RX 分派闸〔ARP 族 + ICMP 三目 + UDP/TCP 解析核 + 校验和 fail-visible〕+ CORE 合成帧语义核七目 + 三相电气回环〔ICMP echo 反射 + DHCP offer 真消费 + TCP SYN→RST——slirp n1 零宿主监听依赖〕——标记五件 T171-CORE/ICMP/UDP/TCP/OK，双面板 303→308）起 171；M53-XDGSTAT83 笔96 t172（xdg_toplevel 状态族消费面活体——标记四件 T172-CORE/WIRE/SESS/OK，双面板 308→312）起 172）。
const SELFTEST_EXPECTED: &str = "172/172";

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

/// M50-MUSLRUN72 笔82：动态链真件介质路径（multiboot module 1/2 通道 =
/// `-initrd` 逗号多模块；在库真件 artifacts/musl——Alpine v3.19 musl
/// 1.2.4 ld-musl-x86_64.so.1 + busybox 1.36.1 动态 PIE，笔80 MUSL70
/// 入库）。缺位时 S8 fail-visible。
const MUSL_DYN_MEDIA: &str = "/home/z/my-project/lumina-os/artifacts/musl/busybox-dynamic";
const MUSL_INTERP_MEDIA: &str = "/home/z/my-project/lumina-os/artifacts/musl/ld-musl-x86_64.so.1";

/// M51-VECFONT74 笔85：矢量字体真件介质路径（multiboot module 3 通道；
/// 在库真件 artifacts/fonts——DejaVu Sans Mono 1.16，笔85 入库）。
/// 缺位时 S8 fail-visible。
const VECFONT_MEDIA: &str = "/home/z/my-project/lumina-os/artifacts/fonts/DejaVuSansMono.ttf";

/// 四模块 initrd 参数（busybox 静态 + busybox-dynamic + ld-musl +
/// DejaVuSansMono.ttf——逗号多模块 = multiboot module 0/1/2/3 顺序
/// 注入，boot staging 四件媒体通道同步）。
fn initrd_media() -> String {
    format!("{BUSYBOX_MEDIA},{MUSL_DYN_MEDIA},{MUSL_INTERP_MEDIA},{VECFONT_MEDIA}")
}

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
    // 0c-2) M50-MUSLRUN72 笔82 动态链真件介质就位检查（fail-visible）
    // + M51-VECFONT74 笔85 矢量字体真件随行（module 3 通道）
    for (name, path) in [
        ("busybox-dynamic", MUSL_DYN_MEDIA),
        ("ld-musl-x86_64.so.1", MUSL_INTERP_MEDIA),
        ("DejaVuSansMono.ttf", VECFONT_MEDIA),
    ] {
        let ok = std::path::Path::new(path)
            .metadata()
            .map(|m| m.len() > 0)
            .unwrap_or(false);
        if !ok {
            eprintln!("[FAIL] S8-smoke：真件介质缺位：{name}：{path}（在库 artifacts）");
            return false;
        }
        eprintln!("[S8-smoke] 真件介质在位：{name}：{path}");
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
    let initrd = initrd_media();
    // M30-X1 t73 取证升级（滤波升级）：LUMINA_S8_PCAP 环境门控 filter-dump
    // 全账捕获——"1" 用默认路径，其余值为显式路径；unset 时零行为变化
    // （默认参数面不变）。捕获层在 netdev 侧，客户机 RX 通路设备级死亡
    // （M27-R1 实证「used 回写 ≠ 交付 netdev」B 面）与 A 面回声窗都在账。
    let pcap_path = match std::env::var("LUMINA_S8_PCAP") {
        Ok(v) if v == "1" => Some("/home/z/my-project/lumina-build/logs/t73-hunt.pcap".to_string()),
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    };
    // M53-E1KNET82 诊断门控：LUMINA_S8_PCAP1 置位 → n1 线包捕获（临时
    // 取证域——车道实录零虚构；定版前回撤或保留随裁决）。
    let pcap1_path = match std::env::var("LUMINA_S8_PCAP1") {
        Ok(v) if v == "1" => Some("/home/z/my-project/lumina-build/logs/t171-e1k.pcap".to_string()),
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
        initrd.as_str(),
        "-drive",
        disk_drive.as_str(),
        "-drive",
        swap_drive.as_str(),
        "-m",
        "256M",
        "-cpu",
        "qemu64,+tsc-deadline", // M43-TSC39 笔㊹：TSC-Deadline 特性位（CPUID.01H:ECX bit24）
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
        // M51-NIC76 笔87：真实 NIC 驱动面自检（t165）需 e1000 在场——
        // Intel 82540EM 真硬件件（第二 netdev 独立 slirp 网段），
        // mac=52:54:00:ab:cd:e1 定值金值锚（E1K_MAC_GOLD 同源）。
        "-device",
        "e1000,netdev=n1,mac=52:54:00:ab:cd:e1",
        "-netdev",
        "user,id=n1",
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
    if let Some(path) = &pcap1_path {
        qemu_args.push("-object".into());
        qemu_args.push(format!("filter-dump,id=pcapf1,netdev=n1,file={path}"));
        println!("[S8-smoke] n1 pcap 滤波捕获在案：{path}");
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
    // 看门狗：300 s 后强杀（步进睡眠，进程先退出则提前收工）。
    // M10 扩容依据：新增三自检（t34 双核 ring3 抢占窗口 + t35 八次盘 I/O
    // 的阻塞化换入链 + t36 等待/收割），TCG 下全程实测 ~80 s（v0.9 =
    // ~50 s @55s 门），余量取整 150 s；M42-DMGL22/23 随行扩容（t122/t123
    // 活体 + t110 round3 多 registry 批会话轮——每轮含 REGISTER paint +
    // teardown 全 pane compose 全屏域，S8 全程实测 ~56-91 s @ 宿主负载
    // 漂移 2-3× 窗——300 s 门给全谱余量）。
    let pid = child.id();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let wd = std::sync::Arc::clone(&done);
    let watchdog = std::thread::spawn(move || {
        for _ in 0..300 {
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
    let required: [&[u8]; 265] = [
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
        // M42-WAYCOMP8 笔⑧：waycomp 主体 ELF 化迁移活体（常驻服务会话
        // 环/合流电气面 ring3 化——真常驻回环；t110 标记 + ELF boot 取证）
        b"LUMINA-WAYCOMPELF-BOOT",
        b"LUMINA-T110-WAYCOMPELF",
        // M42-WAYCOMP9 笔⑨：会话环全谱 wire 解析活体（客户端全谱
        // walk 裁决 + 畸形拒收探针——t110 域⑥ 标记）
        b"LUMINA-T110-WIRE",
        b"LUMINA-T110-OK",
        // M42-WAYCOMP10 笔⑩：boot 面切换换防证据行（WAYCOMP_SVC_ELF
        // boot 常驻——kmain spawn 换防落账，内核 waycomp 双轨锚保持）
        b"LUMINA-WAYCOMP-BOOT-ELF",
        // M42-WAYCOMP10 笔⑩：内核 ISR/抢占路径寄存器契约面标本活体
        //（callee-saved 六寄存器 canary 三相位侵蚀窗实测——揭雷①根因
        // 裁决面；t111 标记）
        b"LUMINA-T111-ISR",
        b"LUMINA-T111-OK",
        // M42-WAYCOMP11 笔⑪：卫生批次活体（argv 真消费 + shm 池回收
        // + 服务重启面——t112 标记）
        b"LUMINA-T112-ARGV",
        b"LUMINA-T112-SHM",
        b"LUMINA-T112-RESTART",
        b"LUMINA-T112-OK",
        // M42-WAYCOMP12 笔⑫：输入守护 + 阻塞等待双域活体（ring3 输入
        // 守护面〔v0 内核态注入域〕+ 阻塞输入等待面〔WaitWhat::CompIn
        // 扩域〕——t113 标记）
        b"LUMINA-T113-GUARD",
        b"LUMINA-T113-WAIT",
        b"LUMINA-T113-OK",
        // M42-WAYCOMP13 笔⑬：evdev 键码映射 + keymap 内容面活体（scancode
        // → evdev → wl +8 两级换算出域 + XKB keymap 内容池 fd 交付——
        // t114 标记）
        b"LUMINA-T114-EVDEV",
        b"LUMINA-T114-KEYMAP",
        b"LUMINA-T114-OK",
        // M42-WAYCOMP14 笔⑭：wl_pointer axis 族/frame 活体（axis_source
        // 前置 + axis 批 + axis_stop + 扫掠终结 frame——t115 标记）
        b"LUMINA-T115-AXIS",
        b"LUMINA-T115-FRAME",
        b"LUMINA-T115-OK",
        // M42-WAYCOMP15 笔⑮：wl_keyboard modifiers 语义活体（XKB 掩码
        // 语义核 + enter 快照随行 + 端到端出域——t116 标记）
        b"LUMINA-T116-SEM",
        b"LUMINA-T116-MODS",
        b"LUMINA-T116-OK",
        // M42-WAYCOMP16 笔⑯：输入队列多产者域活体（IN_MU 串行化窗 +
        // 三源并发 20 键零丢失——t117 标记）
        b"LUMINA-T117-MP",
        b"LUMINA-T117-MPS",
        b"LUMINA-T117-OK",
        // M42-WAYCOMP17 笔⑰：kbd→waycomp ISR 转接臂活体（内核语境旗
        // + try_lock 有界退避随批 + 双车道分域——t118 标记）
        b"LUMINA-T118-ISR",
        b"LUMINA-T118-BACKOFF",
        b"LUMINA-T118-OK",
        // M42-WAYCOMP18 笔⑱：display.sync/wl_callback 多注册表面活体
        //（done+delete_id 对 + 同 id 复用 + 多 registry 多公告——t119 标记）
        b"LUMINA-T119-SYNC",
        b"LUMINA-T119-REG",
        b"LUMINA-T119-OK",
        // M42-WAYCOMP19 笔⑲：毫秒时间源活体（now_ms 单调 + TSC 校准
        // 对账 + wire time 域毫秒对读——t120 标记）
        b"LUMINA-T120-MS",
        b"LUMINA-T120-WIRE",
        b"LUMINA-T120-OK",
        // M42-DMG20 笔⑳：damage 联合域 SYNC 矩形活体（改写域联合合成
        // + fb 联合域直驱——t121 标记）
        b"LUMINA-T121-UNION",
        b"LUMINA-T121-BATCH",
        b"LUMINA-T121-OK",
        // M42-DMGC21 笔㉑：commit 发布域批量化活体（同窗双 commit +
        // 三窗单批批尾单合成 + COMPOSES 随批——t122 标记）
        b"LUMINA-T122-BATCH",
        b"LUMINA-T122-MULTI",
        b"LUMINA-T122-OK",
        // M42-DMGC22 笔㉒：frame callback delete_id 复用面活体（done+delete_id
        // 对 + 同 id 重装复用——t123 标记）
        b"LUMINA-T123-FRAME",
        b"LUMINA-T123-REUSE",
        b"LUMINA-T123-OK",
        // M42-DMGI24 笔㉔：kbd→waycomp ISR 臂指针/轴域扩展活体（五臂
        // 七条投递 + 争用退避 + 域闸负例——t124 标记）
        b"LUMINA-T124-PTRISR",
        b"LUMINA-T124-BACKOFF",
        b"LUMINA-T124-OK",
        // M42-AUX25 笔㉕：PS/2 aux IRQ12 电气源接线活体（IMR 级联双位
        // + 包解码光标增量 + 边界钳制 + 溢出/杂码负例——t125 标记）
        b"LUMINA-T125-AUX",
        b"LUMINA-T125-NEG",
        b"LUMINA-T125-OK",
        // M42-RDTSC26 笔㉖：rdtsc lfence 序列化读活体（紧邻采样单调 +
        // 校准一致性 + 增量窗——t126 标记）
        b"LUMINA-T126-TSC",
        b"LUMINA-T126-OK",
        // M42-DMG27 笔㉗：联合域上限细化活体（近邻吸附降阶 + 预算外
        // 翻转继承——t127 标记）
        b"LUMINA-T127-NEAR",
        b"LUMINA-T127-FAR",
        b"LUMINA-T127-OK",
        // M42-DMG28 笔㉘：指针 16px 粗粒度域联动活体（跨格双标 + 同格
        // 零扰 + ISR 臂联动——t128 标记）
        b"LUMINA-T128-CELL",
        b"LUMINA-T128-ISR",
        b"LUMINA-T128-OK",
        // M42-SPRITE29 笔㉙：光标 sprite 渲染面活体（结构锚 + 热点对位
        // 联动 + 边缘钳制 + 三探针——t129 标记四件）
        b"LUMINA-T129-SPRITE",
        b"LUMINA-T129-MOVE",
        b"LUMINA-T129-BLEND",
        b"LUMINA-T129-OK",
        // M42-AUXR3 笔㉚：ring3 aux 驱动进程活体（boot face + 接管态
        // 仲裁 + 驱动光标对账——t130 标记四件）
        b"LUMINA-T130-AUXBOOT",
        b"LUMINA-T130-AUX",
        b"LUMINA-T130-ELF",
        b"LUMINA-T130-OK",
        // M42-PTRLINK 笔㉛：Enter/Leave 域联动活体（焦点切换取证计数
        // + 联动直标 marks 确定性——t131 标记三件）
        b"LUMINA-T131-ENTER",
        b"LUMINA-T131-LINK",
        b"LUMINA-T131-OK",
        // M42-WHEEL32 笔㉜：IntelliMouse 轮询命令链 + axis 电气源活
        // 体（击键链真端口 + ACK 预算窗 + dz 域——t132 标记五件）
        b"LUMINA-T132-ANCHOR",
        b"LUMINA-T132-KNOCK",
        b"LUMINA-T132-AXIS",
        b"LUMINA-T132-SIGN",
        b"LUMINA-T132-OK",
        // M42-CLICKF33 笔㉝：click-to-focus 焦点迁移联动面活体（纯针
        // 直迁 + 键盘迁移取证戳 + 幂等/release 闸——t133 标记五件）
        b"LUMINA-T133-BASE",
        b"LUMINA-T133-CLICK",
        b"LUMINA-T133-MIGRATE",
        b"LUMINA-T133-IDEMP",
        b"LUMINA-T133-OK",
        // M42-KBREP34 笔㉞：wl_keyboard.repeat_info 键重复公告面活体
        // （键盘派生域 keymap 后随行 + v0 关闭声明 + 域闸负例——t134
        // 标记四件）
        b"LUMINA-T134-ANCHOR",
        b"LUMINA-T134-REPEAT",
        b"LUMINA-T134-NEG",
        b"LUMINA-T134-OK",
        // M43-AV12036 笔㊱：wl_pointer.axis_value120 离散步进语义活体
        // （wheel 源 frame 域随行 + 流内序锚 + 零步进不随行域闸——t135
        // 标记四件）
        b"LUMINA-T135-ANCHOR",
        b"LUMINA-T135-V120",
        b"LUMINA-T135-SIGN",
        b"LUMINA-T135-OK",
        // M43-KBREP37 笔㊷：键重复生产域 + set_cursor 请求域活体
        // （repeat_info 真值公告 + 重复窗 + 双臂请求域——t136 标记四件）
        b"LUMINA-T136-REPEATINFO",
        b"LUMINA-T136-REPS",
        b"LUMINA-T136-SETCUR",
        b"LUMINA-T136-OK",
        // M43-PRIO38 笔电解：产者优先级域活体（boot 代执面 + 级序
        // 对账 + 越界 clamp 语义核——t137 标记四件）
        b"LUMINA-T137-ANCHOR",
        b"LUMINA-T137-BOOT",
        b"LUMINA-T137-SEMANTIC",
        b"LUMINA-T137-OK",
        // M43-TSC39 笔㊹：TSC deadline one-shot 定时器活体（特性锚 +
        // LVT 使能 + one-shot 交付——t138 标记四件）
        b"LUMINA-T138-FEATURE",
        b"LUMINA-T138-ENABLE",
        b"LUMINA-T138-ONESHOT",
        b"LUMINA-T138-OK",
        // M43-HWDW40 笔㊺：Explorer 型别链 + IMEX 族谱解码活体（ID
        // 0x04 双旗武装 + dw 横轮域 + dz nibble 域 + 按钮 4/5 沿——
        // t139 标记五件）
        b"LUMINA-T139-ANCHOR",
        b"LUMINA-T139-EXPLORER",
        b"LUMINA-T139-HWDW",
        b"LUMINA-T139-SIGN",
        b"LUMINA-T139-OK",
        // M43-CURSOR41 笔㊻：光标直迁域活体（窗亡重排域 stationary
        // 光标位 hit-test 直迁 + 创建期 v0 口径 + 幂等零扰——t140
        // 标记四件）
        b"LUMINA-T140-BASE",
        b"LUMINA-T140-RELINK",
        b"LUMINA-T140-IDEMP",
        b"LUMINA-T140-OK",
        // M44-MAP42 笔㊼：创建期/map 域直迁活体（首映射批 stationary
        // 光标位 hit-test 直迁零 motion 前提 + wire enter 出域取证 +
        // map 域幂等零扰 + 跨窗直迁/窗亡回迁分戳分域——t141 标记五件）
        b"LUMINA-T141-OPEN",
        b"LUMINA-T141-IDEMP",
        b"LUMINA-T141-CROSS",
        b"LUMINA-T141-BACK",
        b"LUMINA-T141-OK",
        // M44-AUXW43 笔㊽：boot wheel/explorer 接线切换（boot 取证行
        // fail-visible 双面入列 + t142 活体标记四件——boot 态族谱解码
        // 全谱 + v0 误读域退役对账）
        b"LUMINA-AUX-BOOT-EXPLORER armed=true id=0x04",
        b"LUMINA-T142-BOOT",
        b"LUMINA-T142-FAMILY",
        b"LUMINA-T142-V0",
        b"LUMINA-T142-OK",
        // M44-TSCRG44 笔㊾：真机窗口 TSC deadline 全谱对账（交付后解
        // 除武装 + one-shot 零增判据 + 再武装语义 + 解除武装域——
        // t143 标记四件）
        b"LUMINA-T143-FEATURE",
        b"LUMINA-T143-ONESHOT",
        b"LUMINA-T143-REARM",
        b"LUMINA-T143-OK",
        // M45-BIT245 笔㊿：真机窗口 bit24=1 CPUID 逐位对账（SDM 权威
        // 位义表 32 目 + 逐位判读语义核 + 探测面同源一致——t144 标记
        // 四件）
        b"LUMINA-T144-AUTH",
        b"LUMINA-T144-BITS",
        b"LUMINA-T144-JUDGE",
        b"LUMINA-T144-OK",
        // M45-MPMC46 笔51：MPMC 环替换 SpinLock 串行化（ostd MpmcRing
        // 无锁环 + waycomp 输入域零锁直推 + ISR 臂退避域退役——t145
        // 标记四件）
        b"LUMINA-T145-STRUCT",
        b"LUMINA-T145-MPMC",
        b"LUMINA-T145-ISR",
        b"LUMINA-T145-OK",
        // M45-RECON47 笔52：真机窗口 bit24=1 实测对账（ReconWindow 二态
        // 判定核三源一致 + RECON_SEGMENTS 四段全谱装载计划面 + 0x6E0
        // 路由复证——t146 标记四件）
        b"LUMINA-T146-WINDOW",
        b"LUMINA-T146-PLAN",
        b"LUMINA-T146-ROUTE",
        b"LUMINA-T146-OK",
        // M46-LDEXEC49 笔55：harbor 机械执行面 ld-lumina.so 交付批
        //（ET_DYN 结构判读 + 装载映射/分级缓冲 + GNU 哈希决议链 +
        // 重定位四类写面 + TLS Variant II 布点 + init/fini 互逆序 +
        // dlopen 族 + H-P03 四段打点——t147 标记六件）
        b"LUMINA-T147-MAP",
        b"LUMINA-T147-RELOC",
        b"LUMINA-T147-TLS",
        b"LUMINA-T147-INIT",
        b"LUMINA-T147-BUDGET",
        b"LUMINA-T147-OK",
        // M47-LDCONS53 笔60：装载计划消费面 + ld-lumina.so 本体交付批
        //（本体真件机械链 + exec_plan 消费动作序列 + ring3 消费活体
        // mmap/mprotect/call + 登记面——t148 标记四件 + 探针面二件）
        b"LUMINA-T148-SO",
        b"LUMINA-T148-LIVE",
        b"LUMINA-T148-REG",
        b"LUMINA-T148-OK",
        b"LUMINA-T148-PROBE",
        b"LUMINA-T148-ELEC",
        // M47-DLOPEN54 笔61：dlopen 真消费面（DT_NEEDED 装载序真消费链
        // + ring3 自装载链 mmap×4/mprotect×2/boot call/GOT 间呼/COPY
        // 读回 + 登记面四行——t149 标记四件 + 探针面二件）
        b"LUMINA-T149-CHAIN",
        b"LUMINA-T149-LIVE",
        b"LUMINA-T149-REG",
        b"LUMINA-T149-OK",
        b"LUMINA-T149-PROBE",
        b"LUMINA-T149-ELEC",
        // M40-CRYSTAL：盘上属主域活体（InodeRec v2 属主三域 + chown/
        // chmod 车道 + stat 真面 + 门禁回源 + 持久化对账；t96 标记）
        b"LUMINA-T96-OWN",
        b"LUMINA-T96-OK",
        // M40-CAT：cat applet 实证（制备载荷 + cat 派生消费——内容级
        // 断言标记〔载荷即标记〕+ sendfile 车道 + 负例；t97 标记）
        b"LUMINA-T97-CAT",
        b"LUMINA-T97-OK",
        // M50-MUSLRUN72 笔82：musl 动态全链真件 ring3 真执行（t161 五件）
        b"LUMINA-T161-DYN",
        b"LUMINA-T161-DYN-OK",
        b"LUMINA-T161-LIVE",
        b"LUMINA-T161-NEG",
        b"LUMINA-T161-OK",
        b"LUMINA-T162-EXEC",
        b"LUMINA-T162-LIVE",
        b"LUMINA-T162-NEG",
        b"LUMINA-T162-OK",
        b"LUMINA-T163-ANCHOR",
        b"LUMINA-T163-RENDER",
        b"LUMINA-T163-NEG",
        b"LUMINA-T163-OK",
        // M51-XDGPOP75 笔86：xdg_popup 尺寸交互族（t164 五件）
        b"LUMINA-T164-LOOP",
        b"LUMINA-T164-POPUP",
        b"LUMINA-T164-SIZE",
        b"LUMINA-T164-NEG",
        b"LUMINA-T164-OK",
        // M51-NIC76 笔87：真实 NIC 驱动 e1000（t165 四件）
        b"LUMINA-T165-BRINGUP",
        b"LUMINA-T165-LIVE",
        b"LUMINA-T165-NEG",
        b"LUMINA-T165-OK",
        // M52-E1KIRQ77 笔89：e1000 中断面（t166 四件）
        b"LUMINA-T166-IRQ",
        b"LUMINA-T166-LIVE",
        b"LUMINA-T166-NEG",
        b"LUMINA-T166-OK",
        // M52-POPCON78 笔90：popup 约束域收口（t167 五件）
        b"LUMINA-T167-LOOP",
        b"LUMINA-T167-REPOS",
        b"LUMINA-T167-NEST",
        b"LUMINA-T167-NEG",
        b"LUMINA-T167-OK",
        // M52-VULK79 笔91：GPU 加速车道（t168 四件）
        b"LUMINA-T168-CMD",
        b"LUMINA-T168-LIVE",
        b"LUMINA-T168-NEG",
        b"LUMINA-T168-OK",
        // M52-HWVULK80 笔92：硬件 Vulkan 队列（t169 四件）
        b"LUMINA-T169-QFAM",
        b"LUMINA-T169-ICD",
        b"LUMINA-T169-HW",
        b"LUMINA-T169-OK",
        // M52-PCIQLR81 笔93：真机 PCI level+low 口径复评面（t170 四件）
        b"LUMINA-T170-PROF",
        b"LUMINA-T170-READBACK",
        b"LUMINA-T170-NEG",
        b"LUMINA-T170-OK",
        // M53-E1KNET82 笔95：e1000↔pulse 接线（t171 五件）
        b"LUMINA-T171-CORE",
        b"LUMINA-T171-ICMP",
        b"LUMINA-T171-UDP",
        b"LUMINA-T171-TCP",
        b"LUMINA-T171-OK",
        // M53-XDGSTAT83 笔96：xdg_toplevel 状态族消费面（t172 四件）
        b"LUMINA-T172-CORE",
        b"LUMINA-T172-WIRE",
        b"LUMINA-T172-SESS",
        b"LUMINA-T172-OK",
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
    let initrd = initrd_media();
    vec![
        "-L",
        QEMU_BIOS_SEABIOS,
        "-L",
        QEMU_BIOS_DATA,
        "-kernel",
        kernel_bin,
        "-initrd",
        initrd.as_str(),
        "-drive",
        disk_drive.as_str(),
        "-drive",
        swap_drive.as_str(),
        "-m",
        "256M",
        "-cpu",
        "qemu64,+tsc-deadline", // M43-TSC39 笔㊹：TSC-Deadline 特性位（CPUID.01H:ECX bit24）
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
        // M51-NIC76 笔87：e1000 真硬件件随行（t165 同参面——S8 同谱）
        "-device",
        "e1000,netdev=n1,mac=52:54:00:ab:cd:e1",
        "-netdev",
        "user,id=n1",
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
    let markers: [&[u8]; 273] = [
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
        // M42-WAYCOMP8 笔⑧：waycomp 主体 ELF 化迁移活体（常驻服务会话
        // 环/合流电气面 ring3 化——真常驻回环；t110 标记 + ELF boot 取证）
        b"LUMINA-WAYCOMPELF-BOOT",
        b"LUMINA-T110-WAYCOMPELF",
        // M42-WAYCOMP9 笔⑨：会话环全谱 wire 解析活体（客户端全谱
        // walk 裁决 + 畸形拒收探针——t110 域⑥ 标记）
        b"LUMINA-T110-WIRE",
        b"LUMINA-T110-OK",
        // M42-WAYCOMP10 笔⑩：boot 换防证据行 + 契约面标本活体（t111）
        b"LUMINA-WAYCOMP-BOOT-ELF",
        b"LUMINA-T111-ISR",
        b"LUMINA-T111-OK",
        // M42-WAYCOMP11 笔⑪：卫生批次活体（t112）
        b"LUMINA-T112-ARGV",
        b"LUMINA-T112-SHM",
        b"LUMINA-T112-RESTART",
        b"LUMINA-T112-OK",
        // M42-WAYCOMP12 笔⑫：输入守护 + 阻塞等待双域活体（t113）
        b"LUMINA-T113-GUARD",
        b"LUMINA-T113-WAIT",
        b"LUMINA-T113-OK",
        // M42-WAYCOMP13 笔⑬：evdev 键码映射 + keymap 内容面活体（t114）
        b"LUMINA-T114-EVDEV",
        b"LUMINA-T114-KEYMAP",
        b"LUMINA-T114-OK",
        // M42-WAYCOMP14 笔⑭：wl_pointer axis 族/frame 活体（t115）
        b"LUMINA-T115-AXIS",
        b"LUMINA-T115-FRAME",
        b"LUMINA-T115-OK",
        // M42-WAYCOMP15 笔⑮：wl_keyboard modifiers 语义活体（t116）
        b"LUMINA-T116-SEM",
        b"LUMINA-T116-MODS",
        b"LUMINA-T116-OK",
        // M42-WAYCOMP16 笔⑯：输入队列多产者域活体（t117）
        b"LUMINA-T117-MP",
        b"LUMINA-T117-MPS",
        b"LUMINA-T117-OK",
        // M42-WAYCOMP17 笔⑰：kbd→waycomp ISR 转接臂活体（内核语境旗
        // + try_lock 有界退避随批——t118）
        b"LUMINA-T118-ISR",
        b"LUMINA-T118-BACKOFF",
        b"LUMINA-T118-OK",
        // M42-WAYCOMP18 笔⑱：display.sync/wl_callback 多注册表面活体
        //（done+delete_id 对 + 同 id 复用 + 多 registry 多公告——t119）
        b"LUMINA-T119-SYNC",
        b"LUMINA-T119-REG",
        b"LUMINA-T119-OK",
        // M42-WAYCOMP19 笔⑲：毫秒时间源活体（now_ms 单调 + wire time
        // 域毫秒对读——t120）
        b"LUMINA-T120-MS",
        b"LUMINA-T120-WIRE",
        b"LUMINA-T120-OK",
        // M42-DMG20 笔⑳：damage 联合域 SYNC 矩形活体（改写域联合合成
        // + fb 联合域直驱——t121）
        b"LUMINA-T121-UNION",
        b"LUMINA-T121-BATCH",
        b"LUMINA-T121-OK",
        // M42-DMGC21 笔㉑：commit 发布域批量化活体（同窗双 commit +
        // 三窗单批批尾单合成 + COMPOSES 随批——t122 标记）
        b"LUMINA-T122-BATCH",
        b"LUMINA-T122-MULTI",
        b"LUMINA-T122-OK",
        // M42-DMGC22 笔㉒：frame callback delete_id 复用面活体（done+delete_id
        // 对 + 同 id 重装复用——t123 标记）
        b"LUMINA-T123-FRAME",
        b"LUMINA-T123-REUSE",
        b"LUMINA-T123-OK",
        // M42-DMGI24 笔㉔：kbd→waycomp ISR 臂指针/轴域扩展活体（五臂
        // 七条投递 + 争用退避 + 域闸负例——t124 标记）
        b"LUMINA-T124-PTRISR",
        b"LUMINA-T124-BACKOFF",
        b"LUMINA-T124-OK",
        // M42-AUX25 笔㉕：PS/2 aux IRQ12 电气源接线活体（双面同步——
        // t125 标记三件）
        b"LUMINA-T125-AUX",
        b"LUMINA-T125-NEG",
        b"LUMINA-T125-OK",
        // M42-RDTSC26 笔㉖：rdtsc lfence 序列化读活体（双面同步——t126
        // 标记两件）
        b"LUMINA-T126-TSC",
        b"LUMINA-T126-OK",
        // M42-DMG27 笔㉗：联合域上限细化活体（双面同步——t127 标记
        // 三件）
        b"LUMINA-T127-NEAR",
        b"LUMINA-T127-FAR",
        b"LUMINA-T127-OK",
        // M42-DMG28 笔㉘：指针 16px 粗粒度域联动活体（双面同步——t128
        // 标记三件）
        b"LUMINA-T128-CELL",
        b"LUMINA-T128-ISR",
        b"LUMINA-T128-OK",
        // M42-SPRITE29 笔㉙：光标 sprite 渲染面活体（结构锚 + 热点对位
        // 联动 + 边缘钳制 + 三探针——t129 标记四件）
        b"LUMINA-T129-SPRITE",
        b"LUMINA-T129-MOVE",
        b"LUMINA-T129-BLEND",
        b"LUMINA-T129-OK",
        // M42-AUXR3 笔㉚：ring3 aux 驱动进程活体（boot face + 接管态
        // 仲裁 + 驱动光标对账——t130 标记四件）
        b"LUMINA-T130-AUXBOOT",
        b"LUMINA-T130-AUX",
        b"LUMINA-T130-ELF",
        b"LUMINA-T130-OK",
        // M42-PTRLINK 笔㉛：Enter/Leave 域联动活体（焦点切换取证计数
        // + 联动直标 marks 确定性——t131 标记三件）
        b"LUMINA-T131-ENTER",
        b"LUMINA-T131-LINK",
        b"LUMINA-T131-OK",
        // M42-WHEEL32 笔㉜：IntelliMouse 轮询命令链 + axis 电气源活体
        // （击键链真端口 + ACK 预算窗 + dz 域——t132 标记五件）
        b"LUMINA-T132-ANCHOR",
        b"LUMINA-T132-KNOCK",
        b"LUMINA-T132-AXIS",
        b"LUMINA-T132-SIGN",
        b"LUMINA-T132-OK",
        // M42-CLICKF33 笔㉝：click-to-focus 焦点迁移联动面活体（t133
        // 标记五件）
        b"LUMINA-T133-BASE",
        b"LUMINA-T133-CLICK",
        b"LUMINA-T133-MIGRATE",
        b"LUMINA-T133-IDEMP",
        b"LUMINA-T133-OK",
        // M42-KBREP34 笔㉞：wl_keyboard.repeat_info 键重复公告面活体
        // （t134 标记四件）
        b"LUMINA-T134-ANCHOR",
        b"LUMINA-T134-REPEAT",
        b"LUMINA-T134-NEG",
        b"LUMINA-T134-OK",
        // M43-AV12036 笔㊱：wl_pointer.axis_value120 离散步进语义活体
        // （t135 标记四件）
        b"LUMINA-T135-ANCHOR",
        b"LUMINA-T135-V120",
        b"LUMINA-T135-SIGN",
        b"LUMINA-T135-OK",
        // M43-KBREP37 笔㊷：键重复生产域 + set_cursor 请求域活体
        // （repeat_info 真值公告 + 重复窗 + 双臂请求域——t136 标记四件）
        b"LUMINA-T136-REPEATINFO",
        b"LUMINA-T136-REPS",
        b"LUMINA-T136-SETCUR",
        b"LUMINA-T136-OK",
        // M43-PRIO38 笔电解：产者优先级域活体（boot 代执面 + 级序
        // 对账 + 越界 clamp 语义核——t137 标记四件）
        b"LUMINA-T137-ANCHOR",
        b"LUMINA-T137-BOOT",
        b"LUMINA-T137-SEMANTIC",
        b"LUMINA-T137-OK",
        // M43-TSC39 笔㊹：TSC deadline one-shot 定时器活体（特性锚 +
        // LVT 使能 + one-shot 交付——t138 标记四件）
        b"LUMINA-T138-FEATURE",
        b"LUMINA-T138-ENABLE",
        b"LUMINA-T138-ONESHOT",
        b"LUMINA-T138-OK",
        // M43-HWDW40 笔㊺：Explorer 型别链 + IMEX 族谱解码活体（t139
        // 标记五件）
        b"LUMINA-T139-ANCHOR",
        b"LUMINA-T139-EXPLORER",
        b"LUMINA-T139-HWDW",
        b"LUMINA-T139-SIGN",
        b"LUMINA-T139-OK",
        // M43-CURSOR41 笔㊻：光标直迁域活体（t140 标记四件）
        b"LUMINA-T140-BASE",
        b"LUMINA-T140-RELINK",
        b"LUMINA-T140-IDEMP",
        b"LUMINA-T140-OK",
        // M44-MAP42 笔㊼：创建期/map 域直迁活体（t141 标记五件）
        b"LUMINA-T141-OPEN",
        b"LUMINA-T141-IDEMP",
        b"LUMINA-T141-CROSS",
        b"LUMINA-T141-BACK",
        b"LUMINA-T141-OK",
        // M44-AUXW43 笔㊽：boot wheel/explorer 接线切换（t142 标记四件
        // + boot 取证行双面入列）
        b"LUMINA-AUX-BOOT-EXPLORER armed=true id=0x04",
        b"LUMINA-T142-BOOT",
        b"LUMINA-T142-FAMILY",
        b"LUMINA-T142-V0",
        b"LUMINA-T142-OK",
        // M44-TSCRG44 笔㊾：真机窗口 TSC deadline 全谱对账（t143 标记四件）
        b"LUMINA-T143-FEATURE",
        b"LUMINA-T143-ONESHOT",
        b"LUMINA-T143-REARM",
        b"LUMINA-T143-OK",
        // M45-BIT245 笔㊿：真机窗口 bit24=1 CPUID 逐位对账（t144 标记四件）
        b"LUMINA-T144-AUTH",
        b"LUMINA-T144-BITS",
        b"LUMINA-T144-JUDGE",
        b"LUMINA-T144-OK",
        // M45-MPMC46 笔51：MPMC 环替换 SpinLock 串行化（t145 标记四件）
        b"LUMINA-T145-STRUCT",
        b"LUMINA-T145-MPMC",
        b"LUMINA-T145-ISR",
        b"LUMINA-T145-OK",
        // M45-RECON47 笔52：t146 标记四件（真机窗口 bit24=1 实测对账）
        b"LUMINA-T146-WINDOW",
        b"LUMINA-T146-PLAN",
        b"LUMINA-T146-ROUTE",
        b"LUMINA-T146-OK",
        // M46-LDEXEC49 笔55：harbor 机械执行面 ld-lumina.so 交付批
        //（t147 标记六件——required 面同谱双面入列）
        b"LUMINA-T147-MAP",
        b"LUMINA-T147-RELOC",
        b"LUMINA-T147-TLS",
        b"LUMINA-T147-INIT",
        b"LUMINA-T147-BUDGET",
        b"LUMINA-T147-OK",
        // M47-LDCONS53 笔60：装载计划消费面 + ld-lumina.so 本体交付批
        //（t148 标记四件 + 探针面二件——required 面同谱双面入列）
        b"LUMINA-T148-SO",
        b"LUMINA-T148-LIVE",
        b"LUMINA-T148-REG",
        b"LUMINA-T148-OK",
        b"LUMINA-T148-PROBE",
        b"LUMINA-T148-ELEC",
        // M47-DLOPEN54 笔61：dlopen 真消费面（t149 标记四件 + 探针面
        // 二件——required 面同谱双面入列）
        b"LUMINA-T149-CHAIN",
        b"LUMINA-T149-LIVE",
        b"LUMINA-T149-REG",
        b"LUMINA-T149-OK",
        b"LUMINA-T149-PROBE",
        b"LUMINA-T149-ELEC",
        b"LUMINA-T159-LOOP",
        b"LUMINA-T159-TITLE",
        b"LUMINA-T159-NEG",
        b"LUMINA-T159-OK",
        b"LUMINA-T160-IOPB",
        b"LUMINA-T160-LIVE",
        b"LUMINA-T160-NEG",
        b"LUMINA-T160-OK",
        // M50-MUSLRUN72 笔82：musl 动态全链真件 ring3 真执行（t161 五件）
        b"LUMINA-T161-DYN",
        b"LUMINA-T161-DYN-OK",
        b"LUMINA-T161-LIVE",
        b"LUMINA-T161-NEG",
        b"LUMINA-T161-OK",
        b"LUMINA-T162-EXEC",
        b"LUMINA-T162-LIVE",
        b"LUMINA-T162-NEG",
        b"LUMINA-T162-OK",
        b"LUMINA-T163-ANCHOR",
        b"LUMINA-T163-RENDER",
        b"LUMINA-T163-NEG",
        b"LUMINA-T163-OK",
        // M51-XDGPOP75 笔86：xdg_popup 尺寸交互族（t164 五件）
        b"LUMINA-T164-LOOP",
        b"LUMINA-T164-POPUP",
        b"LUMINA-T164-SIZE",
        b"LUMINA-T164-NEG",
        b"LUMINA-T164-OK",
        // M51-NIC76 笔87：真实 NIC 驱动 e1000（t165 四件）
        b"LUMINA-T165-BRINGUP",
        b"LUMINA-T165-LIVE",
        b"LUMINA-T165-NEG",
        b"LUMINA-T165-OK",
        // M52-E1KIRQ77 笔89：e1000 中断面（t166 四件）
        b"LUMINA-T166-IRQ",
        b"LUMINA-T166-LIVE",
        b"LUMINA-T166-NEG",
        b"LUMINA-T166-OK",
        // M52-POPCON78 笔90：popup 约束域收口（t167 五件）
        b"LUMINA-T167-LOOP",
        b"LUMINA-T167-REPOS",
        b"LUMINA-T167-NEST",
        b"LUMINA-T167-NEG",
        b"LUMINA-T167-OK",
        // M52-VULK79 笔91：GPU 加速车道（t168 四件）
        b"LUMINA-T168-CMD",
        b"LUMINA-T168-LIVE",
        b"LUMINA-T168-NEG",
        b"LUMINA-T168-OK",
        // M52-HWVULK80 笔92：硬件 Vulkan 队列（t169 四件）
        b"LUMINA-T169-QFAM",
        b"LUMINA-T169-ICD",
        b"LUMINA-T169-HW",
        b"LUMINA-T169-OK",
        // M52-PCIQLR81 笔93：真机 PCI level+low 口径复评面（t170 四件）
        b"LUMINA-T170-PROF",
        b"LUMINA-T170-READBACK",
        b"LUMINA-T170-NEG",
        b"LUMINA-T170-OK",
        // M53-E1KNET82 笔95：e1000↔pulse 接线（t171 五件）
        b"LUMINA-T171-CORE",
        b"LUMINA-T171-ICMP",
        b"LUMINA-T171-UDP",
        b"LUMINA-T171-TCP",
        b"LUMINA-T171-OK",
        // M53-XDGSTAT83 笔96：xdg_toplevel 状态族消费面（t172 四件）
        b"LUMINA-T172-CORE",
        b"LUMINA-T172-WIRE",
        b"LUMINA-T172-SESS",
        b"LUMINA-T172-OK",
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
