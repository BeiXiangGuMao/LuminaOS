//! 系统调用 ABI（v0）：编号与寄存器布局。
//!
//! 冻结规则（SPEC 2 章）：v0 编号一经发布不得复用或改序，只允许追加。
//! 布局为 `rax=编号，rdi…r8=五个 u64 参数` 的经典六寄存器形式，
//! 与《语言移植与支持指南》第 2 章的原生 ABI 基座一致。
//!
//! 寄存器保全契约（v0.8 追加注记）：内核保证 rdi/rsi/rdx/r10/r8（参数）
//! 与 rbx/r12–r15 跨 syscall 全量往返；rcx/r11 为 SYSCALL 指令硬件消费
//! （返回 RIP/RFLAGS，经 sysret 原样恢复）；rax 为返回值；**rbp 为内核
//! 入口舞步寄存器，不跨 syscall 保留**（用户帧指针自管，语言运行时
//! 接入见 PORT-004 第 3 章注记）。

/// 打印内核诊断行（早期控制台）。
pub const SYS_LOG: u64 = 0;
/// 终止调用进程。
pub const SYS_EXIT: u64 = 1;
/// 让出 CPU 时间片。
pub const SYS_YIELD: u64 = 2;
/// 向 IPC 端点发送一段载荷。
pub const SYS_IPC_SEND: u64 = 3;
/// 从 IPC 端点接收一段载荷（阻塞）。
pub const SYS_IPC_RECV: u64 = 4;
/// 从父能力派生子能力。
pub const SYS_CAP_DERIVE: u64 = 5;
/// 映射物理页到本地址空间。
pub const SYS_MEM_MAP: u64 = 6;
/// 设置调用者自身调度优先级（0=最高 … 3=最低；v0.8 追加）。
pub const SYS_SET_PRIO: u64 = 7;
/// 读取调用者自身调度优先级（v0.8 追加）。
pub const SYS_GET_PRIO: u64 = 8;
/// 向子任务授予能力（收窄副本；v0.9 追加，M9-A 进程模型）。
pub const SYS_CAP_GRANT: u64 = 9;
/// 撤销调用者自身持有的能力句柄（v0.9 追加）。
pub const SYS_CAP_REVOKE: u64 = 10;
/// 读取调用者自身 pid（v0.9 追加）。
pub const SYS_GET_PID: u64 = 11;
/// 等待子任务终结并收割退出码（v0.10 追加，M10-C）。
///
/// 参数 = 目标 pid（0 = 任意直接子任务）。成功返回
/// `(1 << 32) | (child_pid << 16) | (exit_code & 0xFFFF)`（pid 域
/// 16 位、退出码域 16 位，与错误码域无交叠）；调用方无子任务或
/// 目标非直接子任务 → `ERR_CHILD(8)` 立即返回（不阻塞）。目标子任务
/// 尚未终结时调用方阻塞（M10-B 阻塞态），子任务 EXIT 时唤醒并收割。
pub const SYS_WAIT_PID: u64 = 12;
/// 创建子进程（v0.11 追加，M11-A：ring3 自主派生）。
///
/// 参数 = 保留位（v0 必须为 0，非零 → `BadArgs`）。成功返回
/// `(1 << 32) | child_pid`（pid 域低 32 位，与错误码域无交叠）。
/// v0 语义：子进程地址空间全新构建（父代码帧逐字节克隆、栈帧清零、
/// 子栈 SPAWN 遗传细胞 = 父 pid；数据分支不克隆——无 COW，如实记档）；
/// 父链内核登记（父不可伪造，WAIT_PID/GRANT 门禁同源）；子任务
/// `cap_slot = 0`（纯被授予型，父经 SYS_CAP_GRANT 授予）。帧/槽耗尽
/// → `ERR_NOMEM(9)`。
pub const SYS_SPAWN: u64 = 13;
/// 查询调用者自身句柄（v0.11 追加，M11-B 句柄枚举与查询面）。
///
/// 参数 = 句柄号（0 = NULL 保留，≥ HANDLE_MAX 越界）。成功返回
/// `(1 << 32) | (rights << 16) | global_slot`（rights 域 32 位
/// 位于 16..47，槽号域 16 位；与错误码域无交叠）；未持有/越界 →
/// `ERR_HANDLE(5)`。
pub const SYS_HANDLE_QUERY: u64 = 14;
/// 枚举调用者自身句柄表（v0.11 追加，M11-B）。
///
/// 参数 = 游标（从该句柄号之后继续枚举；0 = 从头）。返回首个占用
/// 句柄：`(1 << 32) | (handle << 16) | rights`；无更多占用 → `0`
/// （枚举尽）。调用协议：`cursor = 上次返回的 handle` 循环直至 0。
pub const SYS_HANDLE_ENUM: u64 = 15;
/// 创建运行时 IPC 通道（v0.12 追加，M12-A 通道注册表运行时化）。
///
/// 参数 = 保留位（v0 必须为 0，非零 → `BadArgs`）。成功返回
/// `(1 << 32) | handle`（句柄域与错误码域无交叠）：内核铸造新
/// 通道对象 id + 泄漏快速路径环对 + [`Capability`](能力 SEND|RECV)
/// 装入调用方句柄表首空闲位。注册表满 / 分配失败 → `ERR_NOMEM(9)`；
/// 调用方句柄表满 → `ERR_TABLE(7)`。通道的跨任务分发复用
/// [`SYS_CAP_GRANT`]（M9 父进程面——通道即能力对象，零新授权面）。
pub const SYS_IPC_BIND: u64 = 16;
/// 打开文件，返回统一句柄面句柄（v0.14 追加，M13-② 文件面；**v0.17 模式域
/// 扩展 = 文件创建面**，M16-①）。
///
/// 参数布局：路径指针 = rdi（调用方只读内存，UTF-8 绝对路径）、
/// 路径长 = rsi（字节，上限 512，结构校验）、打开模式 = rdx
/// （低 2 位 = 访问位：bit0 = 读、bit1 = 写，**必须非零**；bit2 =
/// [`O_CREAT`]、bit3 = [`O_TRUNC`]；其余位保留拒收，结构校验）。
/// 成功返回 `(1 << 32) | handle`：内核解析路径（挂载命名空间）→
/// 铸文件对象 id + [`OpenFileDescription`] 语义入注册表 →
/// [`Capability`](READ|WRITE 按访问位子集) 装入调用方句柄表首空闲位。
/// **O_CREAT**（v0.17）：目标缺失时经父走查新建常规文件（POSIX 同款：
/// 父必须已存在且为目录；中间缺失 → `ENOENT(2)`；目标已存在则直接
/// 打开——v0 无 O_EXCL，如实记档）；**O_TRUNC**（v0.17）：以可写方式
/// 打开成功后将文件截为零长（只读句柄不截——v0 简化，与 POSIX 未定
/// 义域收敛，如实记档）；目录句柄不受影响。**fd ≡ 句柄**（统一句柄面）：
/// 文件与通道共享同一句柄命名空间，靠对象 id 段位（0xF11E…）与权限位
/// （READ/WRITE）区分；句柄表满 → `EMFILE(24)`，内核文件表满 →
/// `ENFILE(23)`（Linux 语义正分）。
/// 错误域 = Linux 5.15 errno（Conduit 口径，见 `crystal::vfs::FsError::errno`（ADR-0002 迁移步））。
pub const SYS_OPEN: u64 = 18;
/// 从文件句柄读取（v0.14 追加，M13-② 文件面）。
///
/// 参数布局：句柄 = rdi、缓冲指针 = rsi（调用方可写内存）、
/// 长度 = rdx（字节，上限 512，结构校验）。成功返回
/// `(1 << 32) | count`（0 = EOF）；句柄无效/未以读方式打开 →
/// `EBADF(9)`；缓冲不可写 → `EFAULT(14)`；偏移自 OFD 私有位推进。
pub const SYS_READ: u64 = 19;
/// 向文件句柄写入（v0.14 追加，M13-② 文件面）。
///
/// 参数布局：句柄 = rdi、数据指针 = rsi（调用方只读内存）、
/// 长度 = rdx（字节，上限 512，结构校验）。成功返回
/// `(1 << 32) | count`；句柄无效/未以写方式打开 → `EBADF(9)`。
pub const SYS_WRITE: u64 = 20;
/// 关闭文件句柄（v0.14 追加，M13-② 文件面）。
///
/// 参数 = 句柄。成功返回 0；句柄回收（全局槽 + 文件对象槽）后同号
/// fd 复用为 Linux 同款语义（close 后旧句柄失效，v0 不做代际槽）。
pub const SYS_CLOSE: u64 = 21;
/// 读取文件句柄元数据快照（v0.14 追加，M13-② 文件面）。
///
/// 参数 = 句柄。成功返回 `(1 << 32) | (size << 16) | kind`（kind：
/// 0 = 常规文件、1 = 目录；size 域 31 位上限，超出按 `EOVERFLOW`
/// 处理属后续块——v0 ramfs 节点尺寸远低于此界，如实记档）；
/// 不影响 OFD 偏移。
pub const SYS_STAT: u64 = 22;
/// 重定位文件句柄偏移（v0.14 追加，M13-② 文件面）。
///
/// 参数布局：句柄 = rdi、基准 = rsi（0 = SET / 1 = CUR / 2 = END，
/// 结构校验）、偏移 = rdx（i64 位型）。成功返回
/// `(1 << 32) | new_offset`；结果为负 → `EINVAL(22)`。
pub const SYS_SEEK: u64 = 23;
/// 配额治理统计面（v0.15 追加，M14-②；**v0.17 kind 3 扩容**，M16-③）：
/// 查询调用方/注册表用量。
///
/// 参数 = 类别（rdi，结构校验 0..=3）：0 = 调用方句柄表、
/// 1 = 内核文件注册表、2 = 通道注册表、3 = **栈增长窗口**（M16-③：
/// used = 累计扩栈页数、cap = 当前窗口页数——全局口径，动态扩容
/// 见 kernel vmm 面）。成功返回
/// `(1 << 32) | (used << 16) | cap`（used/cap 各 16 位域）。
/// 本面属进程面错误域（不属文件面 errno 域）。
pub const SYS_QUOTA: u64 = 25;

/// 以纳秒为粒度睡眠当前任务（v0.14 追加；**v0.16 语义升级 = TSC 纳秒面**，
/// M15-③）。
///
/// 参数 = 时长（**纳秒**；v0.14–v0.15 为全局节拍数，v0.16 起经 TSC
/// 单调纳秒基线度量——[`ostd::time::tsc_clock::now_ns`] 同源；0 = 立即
/// 返回）。任务以 [`WaitWhat::Timer`] 等待对象阻塞（deadline = TSC
/// 纳秒时刻；探针化同款：deadline 已过即探针命中回滚）。成功（睡眠
/// 期满或已期满）返回 0。唤醒检查仍随 PIT 节拍交付（有效分辨率 ≈
/// 节拍周期；deadline 本体为纳秒精确值，如实记档）。
pub const SYS_NANOSLEEP: u64 = 24;

/// 创建目录（v0.16 追加，M15-① 目录面）。
///
/// 参数布局：路径指针 = rdi（调用方只读内存）、路径长 = rsi
/// （字节，上限 512，结构校验）。语义 = 逐段父走查后叶子建目录
/// （POSIX `mkdir` 同款：中间组件必须已存在）。成功返回 0；已存在 →
/// `EEXIST(17)`；父缺失 → `ENOENT(2)`；父组件非目录 → `ENOTDIR(20)`；
/// 路径非法（相对/越过根/建根本身）→ `EINVAL(22)`。
pub const SYS_MKDIR: u64 = 26;

/// 摘除文件或空目录（v0.16 追加，M15-① 目录面）。
///
/// 参数布局同 [`SYS_MKDIR`]（路径指针 = rdi、长 = rsi）。语义 =
/// POSIX `remove`：文件与空目录同面可摘；目录非空 →
/// `ENOTEMPTY(39)`；目标缺失 → `ENOENT(2)`；摘除根自身 →
/// `EINVAL(22)`。v0 不做占用检查（有打开句柄的节点仍可摘除——
/// ramfs 节点随名字摘除即不可达，如实记档）。
pub const SYS_REMOVE: u64 = 27;

/// 分页读取目录项（v0.16 追加，M15-① 目录面）。
///
/// 参数布局：句柄 = rdi（须为**目录**句柄）、缓冲指针 = rsi、
/// 缓冲长 = rdx（字节，上限 512，结构校验）。分页语义 = OFD 私有
/// 偏移兼任**目录项游标**（对目录 `read` 恒 `EISDIR`，偏移域专用；
/// SEEK 可重定位游标）；每次调用自游标起尽量多打包目录项直至缓冲
/// 满。项编码 = `[kind:u8][name_len:u8][name…]` 紧排（kind：
/// 0 = File / 1 = Dir / 2 = CharDev / 3 = Pipe / 4 = Symlink）。
/// 成功返回 `(1 << 32) | n_entries`（0 项 = 枚举尽/EOF）；句柄非
/// 目录 → `ENOTDIR(20)`；句柄无效 → `EBADF(9)`；缓冲不足容纳
/// 首项（< 3 字节）→ `EINVAL(22)`。游标为项序号而非稳定 cookie
/// ——枚举中途目录被修改的漂移语义同 getdents 现实，如实记档。
pub const SYS_READDIR: u64 = 28;

/// 在目录上挂载新文件系统（v0.16 追加，M15-① 目录面）。
///
/// 参数布局：挂载点路径指针 = rdi、长 = rsi、类型 = rdx（v0 恒 0 =
/// 内核侧新建 `crystal::vfs::RamFs`（ADR-0002 迁移步） 内存文件系统；结构校验）。
/// 挂载点必须已存在且为目录（内核侧校验）；同路径重复挂载 →
/// `EEXIST(17)`；挂载点缺失 → `ENOENT(2)`；非目录 → `ENOTDIR(20)`。
/// 成功返回 0（挂载后子 fs 遮蔽挂载点原内容，最长前缀解析生效）。
pub const SYS_MOUNT: u64 = 29;

/// 卸载挂载点（v0.16 追加，M15-① 目录面）。
///
/// 参数布局同 [`SYS_MKDIR`]（路径指针 = rdi、长 = rsi）。成功返回
/// 0；路径未挂载 → `ENOENT(2)`（根挂载不可卸载亦落此域——根不在
/// 挂载表中）。v0 不做占用检查（打开句柄经 `Arc` 存续，卸载后
/// 已打开对象仍可读写至关闭，如实记档）。
pub const SYS_UMOUNT: u64 = 30;

/// 复制文件句柄（v0.16 追加，M15-② 句柄面深化）。
///
/// 参数 = 源句柄（rdi）。语义 = POSIX `dup`：新句柄与源句柄共享
/// 同一开放文件描述（**共享偏移**——一侧读写推进偏移，另一侧可见）。
/// 新句柄安装于调用方句柄表首个空闲位；权限位同源复制。成功返回
/// `(1 << 32) | new_handle`；句柄无效/非文件对象 → `EBADF(9)`；
/// 句柄表满 → `EMFILE(24)`。关闭任一副本不影响另一副本（引用计数
/// 承载，见 [`SYS_CLOSE`]）。
pub const SYS_DUP: u64 = 31;

/// 句柄描述符控制（v0.16 追加，M15-② 句柄面深化）。
///
/// 参数布局：句柄 = rdi、命令 = rsi（[`F_DUPFD`] / [`F_GETFD`] /
/// [`F_SETFD`]，结构校验）、参数 = rdx。`F_DUPFD` = 以 rdx 为下界
/// 复制句柄（≥ rdx 的首个空闲位；成功 `(1 << 32) | new_handle`）；
/// `F_GETFD` = 读描述符旗标（成功 `(1 << 32) | flags`）；`F_SETFD`
/// = 写描述符旗标（rdx bit0 = [`FD_CLOEXEC`]；成功 0）。v0 仅
/// `FD_CLOEXEC` 一旗：置位句柄在 [`SYS_EXEC`] 成功路径被内核关闭
/// （未置位句柄跨 exec 存续——fd 继承语义）。命令未知 →
/// `EINVAL(22)`；句柄无效/非文件对象 → `EBADF(9)`；下界越界/无
/// 空闲位 → `EMFILE(24)`。
pub const SYS_FCNTL: u64 = 32;

/// 执行映像表查询（v0.19 追加，M18-③ ring3 查询面）。
///
/// 参数：映像号 = rdi（内核 `EXEC_IMAGES` 路径表索引）、缓冲
/// 指针 = rsi（调用方可写内存）、缓冲长 = rdx（字节，≤ 512，结构
/// 校验）。成功返回 `(1 << 32) | (总数 << 16) | 拷贝字节数`：将第
/// `index` 项路径（NUL 结尾，截断防御）拷入调用方缓冲；总数 = 表
/// 容量（ring3 可据此或以 `ERR_IMAGE` 终止枚举循环）。索引越界 →
/// `ERR_IMAGE(10)`；缓冲不可写/过短 → `EFAULT(14)`（零拷贝路径——
/// 长度校验先行）。ring3 自此免硬编码映像表。
pub const SYS_IMAGE_ENUM: u64 = 33;

/// 从 TTY 行规程取下一字节（v0.20 追加，M23-② 交互面）。
///
/// **非阻塞轮询语义**：内核侧先泵键盘环（kbd → 行规程），再按单消费
/// 者游标消费当前就绪行；返回域：
/// - `0` = 暂无数据（调用方 yield 后重试；行提交由 IRQ1 异步推进）；
/// - `0x01..=0xFF` = 行内字节（行规程只存可打印 `0x20..=0x7E`，
///   NUL 不在域内）或行终结符 `0x0A`（`\n`，虚位——不落行缓冲，
///   由消费游标在行尾虚拟给出，与 POSIX 行缓冲洗出语义同构）。
///
/// **单消费者契约（v0）**：消费游标全局唯一——init shell 是唯一
/// 长期消费者（t65 自检在 init 派生前完成，串行无并发）；多消费者
/// 竞争面属后续里程碑（M23 如实记档）。
///
/// 回显/退格编辑由内核行规程完成（M23-①），消费方只见提交后行。
pub const SYS_TTY_GETCH: u64 = 34;

/// 显示面映射（v0.21，M23-S1）：把 stdvga LFB 线性帧缓冲映射进调用方
/// 任务根（Surface 表登记面）。
///
/// 参数 = rsi：用户虚地址（页对齐，域固定 [`FB_VA_BASE`,
/// `FB_VA_LIMIT`)——PDPT[1] 显示专用分支，与用户态既有域零冲突）。
/// 成功返回 0：调用方此后可直写该窗口逐像素上屏（XRGB32，`0x00RRGGBB`），
/// 损伤面由调用方自记（v0 无内核侧合成队列）；失败：无 fb → `ENODEV(19)`，
/// 域外/不对齐 → `EFAULT(14)`，Surface 表已占用 → `EEXIST(17)`（v0
/// 单面契约：首请求者独占，二次请求拒绝——多任务 Surface 复用属后续
/// 里程碑）。域常量见 [`FB_VA_BASE`] / [`FB_VA_LIMIT`]。
pub const SYS_FB_MAP: u64 = 35;

/// 显示映射窗口域基址（PDPT[1] 分支首槽；用户态代码 0x400000/栈
/// 0x403000/信箱 0x402F00 均在 PDPT[0] 低 1 GiB 区，零冲突）。
pub const FB_VA_BASE: u64 = 0x4000_0000;
/// 显示映射窗口域上界（不含；PDPT[1] 4 GiB 分支尾——预留多 Surface
/// 并存面，v0 单面仅占首 3 MiB）。
pub const FB_VA_LIMIT: u64 = 0x8000_0000;

/// 显示损伤屏障（v0.21，M23-S1）：量化面——对损伤盒（a0=x, a1=y,
/// a2=w, a3=h，全 i64 语义可负）与全屏求交，返回交盒实际字节数
/// （w*h*4；空盒/全出界 = 0）。无 fb → `ENODEV(19)`。证据行
/// `LUMINA-FB-SYNC` 落串口（demo 取证锚点）。
pub const SYS_FB_SYNC: u64 = 36;

/// 文本渲染服务（v0.22，M23-S2）：内核侧 8x16 等宽位图字体直画
/// （a0=x, a1=y，i64 语义可负；a2=字符串指针，a3=字节数 ≤ 512）。
/// 逐字符 8x16 单元：底黑 + 前景白位展开（越屏像素静默裁剪）；
/// 返回实渲染字符数。无 fb → `ENODEV(19)`；len > 512 → `EINVAL(22)`；
/// 指针校验失败 → `EFAULT(14)`。证据行 `LUMINA-FB-TEXT` 落串口。
pub const SYS_FB_TEXT: u64 = 37;

/// shell 管道/分页面（v0.24，M24-A1）：单级 `|` 雏形的内核承接面。
///
/// 四操作（a0 = op，域 0..=3）：
/// - **0 = 捕获武装**：调用方后续 [`SYS_LOG`] 不再落串口，改写入内核
///   单捕获缓冲（每次调用按一行成帧——载荷尾追加 `\n`；`SYS_LOG`
///   载荷本身不含换行，串口路径每调用补 CRLF，行语义同源）。缓冲满
///   则**整行丢弃**并计数（fail-visible，不截半行）。全局单缓冲、
///   arm..drain/replay 窗口内所有 `SYS_LOG` 入捕（含派生子代——
///   `st | more` 即捕获子代自检输出流），纯直答命令（echo/help/ver）
///   为推荐左源。
/// - **1 = 排水**：a1 = 用户缓冲指针、a2 = 缓冲长（≤ 512）；捕获
///   内容拷出，返回实拷字节数；拷毕清账并卸臂（单发语义，二次排水
///   得 0 = 零泄漏对账锚）。指针校验失败 → `EFAULT(14)` 域返码。
/// - **2 = 分页重放**（`more` 主体）：捕获内容逐行重落串口，每满
///   页界（内核常量 4 行）停顿打 `--more--` 等键——任意键翻页、
///   `q`/`Q`/ESC/Ctrl-C 中止（残余行舍弃，实显行数为返码）。键经
///   TTY 行规程分页态投递（[`SYS_TTY_GETCH`] 同链：IRQ1 → 键盘环 →
///   pump → 行规程——分页态下键不再入行编辑，改入分页键队列）。
///   重放毕清账卸臂（无论中止与否）。
/// - **3 = 弃置**：捕获清账 + 卸臂（右命令非 `more` 的shell 侧清场）。
///
/// 返回：op 0/3 = 0；op 1 = 实拷字节数；op 2 = 实显行数。未知 op →
/// `BadArgs` 域返码。雏形定位：单级管道、单捕获缓冲、单消费者（init
/// shell 串行调用），多级管道与双缓冲属后续里程碑。
pub const SYS_PIPE: u64 = 38;

/// stage 合成面（v0.17，M28-K1）：内核后备缓冲映射请求。参数 = rsi：
/// 用户虚地址（页对齐，[`STAGE_VA_BASE`] 域内——与 LFB 显示窗同处
/// PDPT[1] 用户态分支；v0 单面契约：内核侧仅受理恰为 [`STAGE_VA_BASE`]
/// 的映射请求，多 Surface 表扩容挂账）。
///
/// 语义：ring3 写 stage（内核帧后备）→ [`SYS_FB_SYNC`] 记账损伤 →
/// 内核合成器帧边界 drain 计划、经 prism 仲裁把 stage 交盒局部上屏
/// LFB（胜者单写；交盒外字节零触碰）。ADR-0004 双轨：未登记 stage
/// 时合成退化为无操作，[`SYS_FB_MAP`] 直写路径不受影响。
pub const SYS_FB_STAGE: u64 = 39;

/// stage 映射窗基址（用户态；与 [`FB_VA_BASE`] LFB 窗同域并存）。
pub const STAGE_VA_BASE: u64 = 0x5000_0000;
/// stage 映射窗上限（256 MiB 窗——v0 单面仅用 [`STAGE_VA_BASE`] 起
/// LFB_BYTES 一段，余量给多 Surface 扩容）。
pub const STAGE_VA_LIMIT: u64 = 0x6000_0000;

/// Surface 注册面（v0.18，M37-A1b）：多 Surface 注册/更新/注销三操作
/// ——prism `SurfaceTable` 电气化承接（kernel::fb `SURFACES` 表 + 散帧
/// 后备槽 + `Stack::blend` 合成执行器）。
///
/// 参数（寄存器直传，打包域）：
/// - rdi(a0) = op：0 登记 REGISTER / 1 更新 UPDATE / 2 注销 REMOVE；
/// - rsi(a1) = id：Surface 标识（1..=u32::MAX——0 保留 stage 底层）；
/// - rdx(a2) = xy 打包：低 32 位 x（i32 语义）、高 32 位 y（i32 语义）；
/// - rcx(a3) = wh 打包：低 32 位 w、高 32 位 h（1..=0xFFFF 结构域，
///   屏域校验在内核承接面 fail-visible）；
/// - r8(a4)：REGISTER = z（i32 语义，越大越靠上）；UPDATE = 低 32 位
///   z（i32 语义）+ bit 32 visible；REMOVE 恒 0。
///
/// 返回：REGISTER 成功 = 该 Surface 用户写窗基址（[`SURF_VA_BASE`] 域
/// 按槽 stride 分窗，ring3 以**面内紧排行主序**直写 ARGB8888 像素——
/// row stride = w×4，页数 = ⌈w×h×4/4096⌉）；UPDATE/REMOVE = 0。
/// 错误域：EINVAL(22)/EEXIST(17)/ENOENT(2)/ENOSPC(28)/ENOMEM(9)/
/// EFAULT(14)/ENODEV(19)（语义见内核承接面）。
///
/// 合成语义：登记面进入 [`SYS_FB_STAGE`] stage 之上的覆盖层栈（z 序
/// 仲裁 + alpha over 逐像素混合——不透明层快速路径与胜者单写严格
/// 同构）；损伤记账仍走 [`SYS_FB_SYNC`]（唯一入口，ADR-0004 双轨
/// 共存不变）。
pub const SYS_FB_SURFACE: u64 = 40;

/// Surface 注册窗基址（用户态；与 [`FB_VA_BASE`] LFB 窗 /
/// [`STAGE_VA_BASE`] stage 窗同处 PDPT[1] 显示分支三窗并存）。
pub const SURF_VA_BASE: u64 = 0x6000_0000;
/// Surface 注册窗上限（PDPT[1] 终点，与 [`FB_VA_LIMIT`] 同源；15 槽 ×
/// 全屏窗 stride 8 MiB = 120 MiB 占用，域内余量充分）。
pub const SURF_VA_LIMIT: u64 = 0x8000_0000;
/// Surface 槽窗 stride（8 MiB = 每槽可容全屏 1080p 后备 2026 页）。
pub const SURF_SLOT_STRIDE: u64 = 0x80_0000;

/// 用户态设备端口访问面（v0.19，M42-FBDEV1）：`dev_pio(op, port, value)`。
///
/// **定位（ADR-0004 混合态渐进——M42 阶段一「用户态 fb 驱动进程」端口
/// 访问面首割）**：x86 IOPB/IOPL 硬件裁量面零起点登记（M42-计划 三域
/// 挂账之一），本号先行落 **内核代执车道**——ring3 不直接执行 in/out
/// 指令（IOPL 保持 0、TSS IOPB 不挂），端口电气由内核以白名单原语
/// （`ostd::hw::ports`）代执，授权域 = kernel::dev 端口裁量注册表
/// （per-pid 区间授予，boot/spawn 路径铸授——用户态不可自授）。硬件
/// 面转化（IOPL 提权 / IOPB 挂 TSS）随驱动进程基础设施批次落域，
/// 本号寄存器面冻结不变（代执车道与硬件车道同语义承接）。
///
/// 参数（寄存器直传）：
/// - rdi(a0) = op：0 IN8 / 1 OUT8 / 2 IN16 / 3 OUT16 / 4 IN32 / 5 OUT32；
/// - rsi(a1) = port：x86 I/O 端口号（0..=0xFFFF）；
/// - rdx(a2) = value：OUT 域写入值（按宽度掩码；IN 域忽略）。
///
/// 返回：IN = 读得值（零扩展）；OUT = 0。错误域：端口裁量未授予
/// = [`ERR_CAP`]（1）——授权注册表 miss 即拒，不泄露端口占用拓扑。
pub const SYS_DEV_PIO: u64 = 41;

/// [`SYS_DEV_PIO`] op：IN u8。
pub const PIO_IN8: u64 = 0;
/// [`SYS_DEV_PIO`] op：OUT u8。
pub const PIO_OUT8: u64 = 1;
/// [`SYS_DEV_PIO`] op：IN u16。
pub const PIO_IN16: u64 = 2;
/// [`SYS_DEV_PIO`] op：OUT u16。
pub const PIO_OUT16: u64 = 3;
/// [`SYS_DEV_PIO`] op：IN u32。
pub const PIO_IN32: u64 = 4;
/// [`SYS_DEV_PIO`] op：OUT u32。
pub const PIO_OUT32: u64 = 5;

/// [`SYS_DEV_PIO`] op 解码（宿主可测纯函数；kernel::dev 执行面单一
/// 事实源）：op →（宽度字节数，是否 OUT）。域外 op → `None`（parse
/// 层先行拒收，本函数为执行面纵深防御对账面）。
pub fn pio_op_decode(op: u64) -> Option<(u8, bool)> {
    match op {
        PIO_IN8 => Some((1, false)),
        PIO_OUT8 => Some((1, true)),
        PIO_IN16 => Some((2, false)),
        PIO_OUT16 => Some((2, true)),
        PIO_IN32 => Some((4, false)),
        PIO_OUT32 => Some((4, true)),
        _ => None,
    }
}

/// **定位（M42-阶段二首笔——ADR-0004 混合态渐进：unix socket 域 +
/// Wayland 协议语义面）**：AF_UNIX 流套接字域首割——socketpair 铸造
/// 面 + 命名监听/连接面（bind/connect/accept）+ 流 I/O 面（send/recv
/// 短写语义 + 阻塞接收）。对象模型复用通道纪律：套接字端点 = 能力
/// 对象（句柄寻址 + IPC_SEND/IPC_RECV 权限位门禁——对象 id 段
/// 0xC0DE_0000_0000_002X 与预设 0x…000X / fb 服务 0x…001X / 运行时
/// 0x…0001_0000 正交），内核环缓冲承载字节流（对齐 ADR-0005「环归
/// ostd::sync 白名单」——pulse 环归档先例同款手法）。
///
/// **多路复用 op 面**（[`SYS_DEV_PIO`] 同款手法——单号承载六操作）。
/// 参数（寄存器直传）：rdi(a0) = op；rsi(a1) = 句柄（ACCEPT/SEND/RECV
/// 域；PAIR 忽略）；rdx(a2) = 指针（慢路径语义——BIND/CONNECT 名字
/// 指针 / SEND 载荷指针 / RECV 缓冲指针；PAIR/ACCEPT 忽略）；
/// r10(a3) = 长度（BIND/CONNECT 名字长 1..=[`USOCK_NAME_MAX`] /
/// SEND 载荷长 / RECV 缓冲长 1..=[`USOCK_LEN_MAX`]）。
///
/// 返回：PAIR = `(a<<32)|b` 双句柄封装；BIND/CONNECT/ACCEPT/ACCEPT_B
/// = 新句柄（低位装载形）；SEND/RECV = 流字节数（短写语义——满环回
/// 0 = 重试类，POSIX write/read 语义对齐；对端 shutdown 后 recv 排
/// 空回 0 = EOF 域）；SHUT = 0。错误域：[`ERR_CAP`]（句柄/权限）、
/// [`ERR_EMPTY`]（accept 无 pending）、[`ERR_FULL`]（backlog 满）、
/// [`ERR_TABLE`]、[`ERR_NOMEM`] + [`ERR_INUSE`]/[`ERR_NOENT`] +
/// [`ERR_PIPE`]（对端 shutdown 后 send——M42-COMP4）/ [`ERR_HANDLE`]
/// （已 shutdown 监听者 accept——EBADF 语义面）；名字词法越域 =
/// `u64::MAX-1`（BadArgs 哨兵同面——parse 层域闸对齐）。
pub const SYS_UNIXSOCK: u64 = 42;

/// [`SYS_UNIXSOCK`] op：socketpair（铸连接对，双句柄装入调用方表）。
pub const USOCK_PAIR: u64 = 0;
/// [`SYS_UNIXSOCK`] op：bind/listen（命名监听登记——v0 bind 即 listen）。
pub const USOCK_BIND: u64 = 1;
/// [`SYS_UNIXSOCK`] op：connect（按名连接——pending 对端入监听者 backlog）。
pub const USOCK_CONNECT: u64 = 2;
/// [`SYS_UNIXSOCK`] op：accept（弹出 pending 连接装服务端句柄；v0 非阻塞）。
pub const USOCK_ACCEPT: u64 = 3;
/// [`SYS_UNIXSOCK`] op：send（流写入——短写语义，返回写入字节数）。
pub const USOCK_SEND: u64 = 4;
/// [`SYS_UNIXSOCK`] op：recv（流读取——空则阻塞，WaitWhat::UnixRecv）。
pub const USOCK_RECV: u64 = 5;
/// [`SYS_UNIXSOCK`] op：阻塞 accept（M42-COMP4 阶段三——backlog 空
/// 以 `WaitWhat::UnixAccept` 条件阻塞，connect 落队定向唤醒；v0
/// 非阻塞 accept〔op 3〕保持不动，双轨共存）。
pub const USOCK_ACCEPT_B: u64 = 6;
/// [`SYS_UNIXSOCK`] op：shutdown（M42-COMP4 阶段三——EOF 对端终结
/// 面：终结己端流域〔读写双向 v0 口径〕，对端 recv 排空后回 0 =
/// EOF、对己端/对端再 send = [`ERR_PIPE`]；对象存续纪律不变——
/// 仅旗标改写，注册表行不回收）。
pub const USOCK_SHUT: u64 = 7;
/// [`SYS_UNIXSOCK`] op：**fd 附带数据传递·发送臂**（M42-ELF5 桌面链
/// 批次——SCM_RIGHTS 语义面）：rsi = 套接字句柄，rdx = **待传递句柄
/// 值**（非指针——SCM_RIGHTS 语义域；内核铸同对象同权限新全局槽
/// 入对端附带队列）。成功 = 0。
pub const USOCK_SEND_FD: u64 = 8;
/// [`SYS_UNIXSOCK`] op：**fd 附带数据传递·接收臂**（M42-ELF5）：rsi
/// = 套接字句柄；弹出对端附带队列首全局槽装入调用方句柄表，返回新
/// 句柄。队列空 → [`ERR_EMPTY`]（重试类）。
pub const USOCK_RECV_FD: u64 = 9;

/// [`SYS_UNIXSOCK`] 名字词法上界（字节域；对齐 POSIX sun_path 108）。
pub const USOCK_NAME_MAX: u64 = 108;
/// [`SYS_UNIXSOCK`] 流载荷/缓冲上界（validate_user_slice 防拷贝预算域
/// 同源——SEND/RECV 单调用 64 KiB 封顶）。
pub const USOCK_LEN_MAX: u64 = 0x1_0000;

/// **定位（M42-ELF5 次笔——桌面链 wl_shm 池域）**：客户端像素缓冲
/// 域电气面——共享内存池对象（内核帧阵列）+ 调用方任务根映射面。
/// Wayland wl_shm.create_pool → wl_shm_pool.create_buffer →
/// wl_surface.attach 语义的承载域：客户端 CREATE 铸池 + MAP 映入
/// 自身任务根直写像素，池能力经 [`SYS_UNIXSOCK`] SEND_FD/RECV_FD
/// 传递至合成器（SCM_RIGHTS 语义面），合成器自池读像素上屏。
/// 对象 id 段 `0xC0DE_0000_0000_003X`（与预设 0x…000X / fb 服务
/// 0x…001X / socket 0x…002X / 运行时 0x…0001_0000 正交）。
///
/// **多路复用 op 面**（[`SYS_UNIXSOCK`] 同款手法）：rdi(a0) = op；
/// rsi(a1) = CREATE 尺寸 / MAP 句柄；rdx(a2) = MAP 虚地址（页对齐，
/// [`SHM_VA_BASE`] 域内——PDPT[1] 上半窗，与 LFB/stage/Surface 写窗
/// 同支互斥域正交）。
///
/// 返回：CREATE = `(1<<32)|handle`（高位装载形——错误码域无交叠）；
/// MAP = 映射窗基址（回显契约）。错误域：[`ERR_CAP`]（句柄/权限/无
/// 用户根）、[`ERR_NOMEM`]（帧耗尽/池满）、[`ERR_TABLE`]（句柄表满）、
/// 域外 = `u64::MAX-1`（BadArgs 哨兵同面）。
pub const SYS_SHM: u64 = 43;

/// [`SYS_SHM`] op：铸共享内存池（rsi = 尺寸字节 1..=[`SHM_SIZE_MAX`]；
/// 内核帧阵列 + 池对象铸造 + 句柄装入调用方表）。
pub const SHM_CREATE: u64 = 0;
/// [`SYS_SHM`] op：池映射入调用方任务根（rsi = 句柄，rdx = 页对齐
/// 虚地址，域 [`SHM_VA_BASE`]..[`SHM_VA_LIMIT`]——P|W|U 映射 + 中间
/// 层补 U）。成功回显基址。
pub const SHM_MAP: u64 = 1;

/// [`SYS_SHM`] 池尺寸上界（2 MiB = 单 PT 窗预算——[`SHM_VA_LIMIT`] −
/// [`SHM_VA_BASE`] = 128 MiB 域内多池并存预算面对账域）。
pub const SHM_SIZE_MAX: u64 = 0x20_0000;
/// [`SYS_SHM`] 映射窗基址（用户态；PDPT[1] 上半窗——LFB
/// [`FB_VA_BASE`]/stage [`STAGE_VA_BASE`]/Surface [`SURF_VA_BASE`]
/// 同支下半域正交）。
pub const SHM_VA_BASE: u64 = 0x7000_0000;
/// [`SYS_SHM`] 映射窗上限（128 MiB 窗——多池并存域）。
pub const SHM_VA_LIMIT: u64 = 0x7800_0000;

/// 套接字名词法校验（fail-visible 注册面）：1..=[`USOCK_NAME_MAX`]
/// 字节，ASCII 可打印域（0x21..=0x7E——空格/控制域拒收；平名命名域
/// v0 无路径解析，斜杠词法域放行如实记档）。宿主可测纯函数
/// （svc_name_ok 先例同款——词法域与语义域分立）。
pub fn usock_name_ok(name: &[u8]) -> bool {
    !(name.is_empty() || name.len() as u64 > USOCK_NAME_MAX)
        && name.iter().all(|c| (0x21..=0x7E).contains(c))
}

/// [`SYS_FCNTL`] 命令：复制句柄（rdx = 新句柄号下界）。
pub const F_DUPFD: u64 = 0;
/// [`SYS_FCNTL`] 命令：读描述符旗标。
pub const F_GETFD: u64 = 1;
/// [`SYS_FCNTL`] 命令：写描述符旗标（参数 = 旗标位集）。
pub const F_SETFD: u64 = 2;
/// [`SYS_FCNTL`] 命令：复制句柄至**指定槽位**（v0.19，M18-③ dup2 面：
/// 参数 = 目标句柄号；目标已开则原子关替（OFD 引用计数递减——
/// EBUSY 卸载占用面联动）；目标 == 源 → 无操作直返）。
pub const F_DUP2FD: u64 = 3;
/// 描述符旗标 bit0：exec 时关闭（`close-on-exec`）。
pub const FD_CLOEXEC: u64 = 1;

// ---- 驱动服务框架契约（M34-D1：kernel::svc 结构面单一事实源） ----

/// 服务注册表容量（定容）：M31-N1 五清点域（vnet/fb/kbd/console/block）
/// + 三余量后续驱动批次。
pub const SVC_MAX: usize = 8;
/// 服务名词法上界（字节域；注册面词法校验 [`svc_name_ok`]）。
pub const SVC_NAME_MAX: usize = 16;
/// 预设服务 id 计数（boot 注册对账闸——init 返回值必须命中本值）。
/// M42-COMP4 起 5→6（第 6 项 = 合成器进程面 [`SVC_COMPOSITOR`]）。
pub const SVC_PRESET_COUNT: usize = 6;
/// 服务 id 段基（0x5E00 段——与文件 0xF11E / 通道 0xC0DE 段正交）。
pub const SVC_ID_BASE: u64 = 0x5E00_0000_0000_0000;
/// 预设服务 id：virtio-net 电气面（M31-N1 五清点 1,743 行域）。
pub const SVC_VNET: u64 = SVC_ID_BASE + 1;
/// 预设服务 id：stdvga+SYS_FB 显示域（953 行域）。
pub const SVC_FB: u64 = SVC_ID_BASE + 2;
/// 预设服务 id：PS2 键盘电气机制面（250 行域）。
pub const SVC_KBD: u64 = SVC_ID_BASE + 3;
/// 预设服务 id：串口控制台面（212 行域）。
pub const SVC_CONSOLE: u64 = SVC_ID_BASE + 4;
/// 预设服务 id：ATA PIO 块面（134 行域）。
pub const SVC_BLOCK: u64 = SVC_ID_BASE + 5;
/// 预设服务 id：Wayland 合成器进程面（M42-COMP4 阶段三首笔——常驻
/// 合成器服务〔waycomp〕svc 登记域；通道域 (0,0) 占位——合成器对外
/// 电气 = unix socket 名域非 FastPath 环对，如实记档）。
pub const SVC_COMPOSITOR: u64 = SVC_ID_BASE + 6;

/// 服务名词法校验（fail-visible 注册面）：1..=[`SVC_NAME_MAX`] 字节，
/// ASCII 小写字母/数字/连字符。宿主可测纯函数（kernel::svc 注册闸
/// 第一道——词法域与语义域分立）。
pub fn svc_name_ok(name: &str) -> bool {
    let b = name.as_bytes();
    !(b.is_empty() || b.len() > SVC_NAME_MAX)
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// [`SYS_OPEN`] 模式 bit2：目标缺失时创建常规文件（v0.17，M16-①）。
pub const O_CREAT: u64 = 0b0100;
/// [`SYS_OPEN`] 模式 bit3：可写打开成功后截断为零长（v0.17，M16-①）。
pub const O_TRUNC: u64 = 0b1000;
/// [`SYS_OPEN`] 模式 bit4：排他创建（v0.19，M18-③）：与 [`O_CREAT`]
/// 同用时目标已存在 → `EEXIST(17)` 原子拒开（不加不删——lockfile
/// 语义基座）。不与 [`O_CREAT`] 同用时无效应（POSIX 未定义域收敛，
/// 如实记档）。
pub const O_EXCL: u64 = 0b1_0000;
/// [`SYS_OPEN`] 模式合法域掩码（访问位 0b11 | O_CREAT(bit2) | O_TRUNC(bit3)
/// | O_EXCL(bit4)）。
pub const OPEN_MODE_MASK: u64 = 0b1_1111;

/// 以内核内嵌映像重建调用方地址空间（v0.12 追加，M12-B 执行映像面）。
///
/// 参数 = 映像号（[`EXEC_IMAGES`] 表索引，越界 → `ERR_IMAGE(10)`）。
/// 成功**不返回**（新映像自用户入口执行；RIP/RSP/参数寄存器由内核
/// 全量构造；r12–r15 callee-saved 语义自然往返——r14 遗传细胞保持，
/// exec 不改父子链）；旧空间帧按 v0 存续期语义不回收（如实记档）。
/// 无独立用户空间 → `ERR_CAP`；帧耗尽 → `ERR_NOMEM(9)`。
pub const SYS_EXEC: u64 = 17;

/// 系统调用 ABI 版本（v0.22 = M42-ELF5：新增 SYS_SHM(43) wl_shm
/// 共享内存池域（CREATE/MAP 双 op——对象 id 段 0xC0DE…003X +
/// SHM_VA_BASE 0x7000_0000 映射窗）+ SYS_UNIXSOCK op 面扩容
/// SEND_FD(8)/RECV_FD(9)〔fd 附带数据传递——SCM_RIGHTS 语义面〕；
/// v0.21 = M42-COMP4：SYS_UNIXSOCK op 面扩容
/// ACCEPT_B(6)/SHUT(7)〔阻塞 accept + EOF 对端终结面——WaitWhat::
/// UnixAccept 新阻塞源 + ERR_PIPE(13) 追加〕+ svc 预设面第 6 项
/// SVC_COMPOSITOR；v0.20 = M42-UNIX3：新增 SYS_UNIXSOCK(42) unix
/// socket 域多路复用 op 面（socketpair/连接面/流 I/O 六 op——对象 id 段
/// 0xC0DE_0000_0000_002X + 错误码 11/12 追加）；v0.19 = M42-FBDEV1：新增 SYS_DEV_PIO(41) 用户态
/// 设备端口访问面（内核裁量注册表 v0——IOPB/IOPL 硬件面挂账）；
/// v0.18 = M37-A1b：新增 SYS_FB_SURFACE(40) Surface
/// 注册面（prism SurfaceTable→Stack 合成电气化承接——登记/更新/注销
/// 三操作 + SURF_VA_BASE 槽窗三窗并存）；v0.17 = M28-K1：新增 SYS_FB_STAGE(39) stage 合成面
/// （内核后备缓冲映射 + 损伤驱动局部上屏，ADR-0004 直写双轨共存）；
/// v0.16 = M24-A1：新增 SYS_PIPE(38) shell 管道/
/// 分页面（捕获武装/排水/分页重放/弃置四操作——单级 `|` 雏形 + `more`
/// 内核承接面）；v0.15 = M23-S2：新增 SYS_FB_TEXT(37) 内核侧文本
/// 渲染服务（8x16 位图字体 + 底黑前景白 + 越屏裁剪）；v0.14 = M23-S1：新增 SYS_FB_MAP(35)/SYS_FB_SYNC(36)
/// 显示服务面（Surface 表 + 任务根 LFB 映射 + 损伤屏障量化）；v0.20 = M23：新增 SYS_TTY_GETCH(34) TTY 取字
/// 轮询面——init shell 交互基座；v0.19 = M18：SYS_OPEN 模式域扩容 O_EXCL（bit4）、
/// SYS_FCNTL 命令域扩容 F_DUP2FD（0..=3）、新增 SYS_IMAGE_ENUM(33)
/// ring3 映像表查询面；v0.18 = M17：SYS_MOUNT fs_type 域扩容 0..=1
/// （1 = LFS1 盘上文件系统——块设备 + 盘上 fs，ABI 寄存器面不变）；
/// v0.17 = M16：文件创建面 SYS_OPEN 模式域扩展 O_CREAT/O_TRUNC +
/// SYS_QUOTA kind 3 栈增长窗口 + EXEC Weave 包源映像（ABI 寄存器面
/// 不变，映像表扩容）。
/// v0.16 = M15：目录面五落点 MKDIR/REMOVE/READDIR/MOUNT/UMOUNT +
/// 句柄面深化 DUP/FCNTL（CLOEXEC）+ NANOSLEEP 参数语义升级为 TSC 纳秒。
/// v0.8 = SYS_QUOTA；v0.7 = 文件面六落点 + NANOSLEEP + 统一句柄面）。
pub const ABI_VERSION: (u16, u16) = (0, 22);

/// ---------------------------------------------------------------------------
/// LXE1 v0 错误码表（具名化事实源，M25-C1）：
///
/// v0 全表（返回码契约，事实源 = kernel::procs；编号冻结只增不改）：
/// 0 = 成功；1 = [`ERR_CAP`]；2 = [`ERR_EMPTY`]；3 = [`ERR_DERIVE`]；
/// 4 = [`ERR_FULL`]；5 = [`ERR_HANDLE`]；6 = [`ERR_TARGET`]；7 = [`ERR_TABLE`]；
/// 8 = [`ERR_CHILD`]；9 = [`ERR_NOMEM`]；10 = [`ERR_IMAGE`]。
///
/// 返回域纪律：错误码为**非零 u64 小值域**（1..=10），与成功返回的载荷域
/// （`(1<<32)|…` 高位装载形）无交叠；`u64::MAX`（未知调用）/`u64::MAX-1`
/// （坏参数）为保留哨兵（`AbiError` 映射面）。兼容层双向翻译见
/// conduit::convert（M25-C1：err_to_errno / errno_to_err）。
/// ---------------------------------------------------------------------------
/// 错误码 1：能力校验未过（句柄未持有 / 权限不足 / 通道不存在同面）。
pub const ERR_CAP: u64 = 1;
/// 错误码 2：环空（IPC RECV 无数据可取——非阻塞语义的重试类）。
pub const ERR_EMPTY: u64 = 2;
/// 错误码 3：能力派生提权/空槽（派生请求超出源能力权限面）。
pub const ERR_DERIVE: u64 = 3;
/// 错误码 4：环满/容量耗尽（IPC SEND 无空间可写——非阻塞语义的重试类）。
pub const ERR_FULL: u64 = 4;
/// 错误码 5：句柄无效/未持有/主身份不可撤销。
pub const ERR_HANDLE: u64 = 5;
/// 错误码 6：目标不存在或非直接子任务（跨任务操作面）。
pub const ERR_TARGET: u64 = 6;
/// 错误码 7：目标句柄表满。
pub const ERR_TABLE: u64 = 7;
/// 错误码 8：无匹配子任务（WAIT_PID 面不阻塞直返）。
pub const ERR_CHILD: u64 = 8;
/// 错误码 9：内存/帧耗尽。
pub const ERR_NOMEM: u64 = 9;
/// 错误码 10：映像号越界或映像装载失败（EXEC/IMAGE_ENUM 面）。
pub const ERR_IMAGE: u64 = 10;
/// 错误码 11：地址占用（SYS_UNIXSOCK BIND 同名监听已登记——
/// `EADDRINUSE` 语义面；conduit 映射 `EADDRINUSE(98)`）。
pub const ERR_INUSE: u64 = 11;
/// 错误码 12：连接目标不存在（SYS_UNIXSOCK CONNECT 未登记名——
/// `ECONNREFUSED` 语义同面；conduit 映射 `ECONNREFUSED(111)`）。
pub const ERR_NOENT: u64 = 12;
/// 错误码 13：管道断裂（SYS_UNIXSOCK SEND 对端已 shutdown——`EPIPE`
/// 语义面；EOF 对端终结域的写侧显形；conduit 映射 `EPIPE(32)`）。
/// （M42-COMP4 阶段三首笔追加——“编号冻结只增不改”域）。
pub const ERR_PIPE: u64 = 13;

/// 寄存器快照形式的系统调用请求。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallRegs {
    /// 调用编号（rax）。
    pub num: u64,
    /// 五个参数寄存器（rdi、rsi、rdx、r10、r8）。
    pub args: [u64; 5],
}

/// 解析错误：未知编号或参数不符合该编号的约定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiError {
    /// 编号未注册。
    UnknownSyscall,
    /// 参数指针/长度不合法。
    BadArgs,
}

/// 已解析的系统调用意图（v0 面向 IPC 骨架的最小集）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Syscall {
    /// 打印诊断文本（指针+长度指向调用方只读内存）。
    Log {
        /// 调用方缓冲区长度（字节，上限 512）。
        len: u64,
    },
    /// 以码退出。
    Exit {
        /// 退出码。
        code: i32,
    },
    /// 让出 CPU。
    Yield,
    /// 发送：目标端点与载荷指针/长度。
    ///
    /// v0.12 语义演进（M12-A）：端点 = **调用方句柄**（任务本地名）。
    /// 内核解析 句柄 → 全局能力槽 → 对象 id → 通道注册表按对象反查。
    /// 无效句柄与通道不存在对外同面（ERR_CAP，不泄露拓扑）。
    IpcSend {
        /// 调用方持有的通道能力句柄。
        endpoint: u64,
        /// 载荷长度（字节，上限 4096）。
        len: u64,
    },
    /// 接收：目标端点与接收缓冲指针/长度（语义演进同 [`Syscall::IpcSend`]）。
    IpcRecv {
        /// 调用方持有的通道能力句柄。
        endpoint: u64,
        /// 缓冲长度（字节）。
        buf_len: u64,
    },
    /// 能力派生：父句柄 + 请求权限位。
    CapDerive {
        /// 父能力句柄（槽位号）。
        parent_handle: u64,
        /// 请求的权限位。
        rights: u32,
    },
    /// 设置调用者自身优先级（0=最高 … 3=最低；自调节，无跨任务权能）。
    SetPrio {
        /// 目标优先级。
        level: u8,
    },
    /// 读取调用者自身优先级。
    GetPrio,
    /// 跨任务能力授予：向**子任务**派生收窄副本并装入其句柄表（M9-A）。
    /// 成功返回 `(1 << 32) | new_handle`（与错误码域无交叠；错误码见
    /// kernel proc 模块文档）。
    CapGrant {
        /// 目标任务 pid（必须是调用方的子任务）。
        target_pid: u64,
        /// 调用方持有的父句柄。
        handle: u64,
        /// 授予的权限位（必须为父能力权限子集）。
        rights: u32,
    },
    /// 撤销调用者句柄（全局槽位回收 + 句柄清除；主身份句柄不可撤销）。
    CapRevoke {
        /// 待撤销的句柄号。
        handle: u64,
    },
    /// 读取调用者自身 pid（任务槽位号；主任务 = 0）。
    GetPid,
    /// 等待子任务终结并收割退出码（M10-C 雏形；成功编码见
    /// [`SYS_WAIT_PID`] 文档）。阻塞语义由内核调度面承载。
    WaitPid {
        /// 目标子任务 pid（0 = 任意直接子任务）。
        pid: u64,
    },
    /// 创建子进程（M11-A；成功编码见 [`SYS_SPAWN`] 文档）。
    Spawn {
        /// 保留参数（v0 必须为 0）。
        reserved: u64,
    },
    /// 查询自身句柄（M11-B；编码见 [`SYS_HANDLE_QUERY`] 文档）。
    HandleQuery {
        /// 待查询句柄号。
        handle: u64,
    },
    /// 枚举自身句柄表（M11-B；协议见 [`SYS_HANDLE_ENUM`] 文档）。
    HandleEnum {
        /// 枚举游标（返回该句柄号之后的首个占用项）。
        cursor: u64,
    },
    /// 创建运行时 IPC 通道（M12-A；成功编码见 [`SYS_IPC_BIND`] 文档）。
    IpcBind {
        /// 保留参数（v0 必须为 0）。
        reserved: u64,
    },
    /// 执行映像重建（M12-B；语义见 [`SYS_EXEC`] 文档）。
    Exec {
        /// 内嵌映像表索引。
        image: u64,
    },
    /// 打开文件（M13-②；v0.17 模式域扩展，指针 = rdi 慢路径语义，
    /// 结构面见 [`SYS_OPEN`]）。
    Open {
        /// 路径长（字节，≤ 512）。
        len: u64,
        /// 打开模式（低 2 位访问位非零；bit2 = O_CREAT / bit3 = O_TRUNC）。
        mode: u8,
    },
    /// 读文件（M13-②；缓冲 = rsi 慢路径语义，见 [`SYS_READ`]）。
    Read {
        /// 文件句柄。
        handle: u64,
        /// 请求长度（字节，≤ 512）。
        len: u64,
    },
    /// 写文件（M13-②；缓冲 = rsi 慢路径语义，见 [`SYS_WRITE`]）。
    Write {
        /// 文件句柄。
        handle: u64,
        /// 数据长度（字节，≤ 512）。
        len: u64,
    },
    /// 关闭文件句柄（M13-②；见 [`SYS_CLOSE`]）。
    Close {
        /// 文件句柄。
        handle: u64,
    },
    /// 句柄元数据快照（M13-②；见 [`SYS_STAT`]）。
    Stat {
        /// 文件句柄。
        handle: u64,
    },
    /// 重定位偏移（M13-②；见 [`SYS_SEEK`]）。
    Seek {
        /// 文件句柄。
        handle: u64,
        /// 基准（0 = SET / 1 = CUR / 2 = END）。
        whence: u8,
        /// 偏移（i64 位型透传）。
        offset: u64,
    },
    /// 纳秒粒度睡眠（M13-②；v0.16 TSC 纳秒语义，见 [`SYS_NANOSLEEP`]）。
    NanoSleep {
        /// 时长（**纳秒**，v0.16 TSC 纳秒语义；0 = 立即返回）。
        ticks: u64,
    },
    /// 配额用量查询（M14-②；v0.17 kind 3，见 [`SYS_QUOTA`]）。
    Quota {
        /// 类别（0 = 句柄表 / 1 = 文件注册表 / 2 = 通道注册表 /
        /// 3 = 栈增长窗口）。
        kind: u64,
    },
    /// 创建目录（M15-①；指针 = rdi 慢路径语义，见 [`SYS_MKDIR`]）。
    MkDir {
        /// 路径长（字节，≤ 512）。
        len: u64,
    },
    /// 摘除文件/空目录（M15-①；指针 = rdi 慢路径语义，见 [`SYS_REMOVE`]）。
    Remove {
        /// 路径长（字节，≤ 512）。
        len: u64,
    },
    /// 分页读目录项（M15-①；缓冲 = rsi 慢路径语义，见 [`SYS_READDIR`]）。
    ReadDir {
        /// 目录句柄。
        handle: u64,
        /// 缓冲长度（字节，≤ 512）。
        buf_len: u64,
    },
    /// 挂载新文件系统（M15-①；指针 = rdi 慢路径语义，见 [`SYS_MOUNT`]）。
    Mount {
        /// 挂载点路径长（字节，≤ 512）。
        len: u64,
        /// 文件系统类型（v0 恒 0 = RamFs）。
        fs_type: u64,
    },
    /// 卸载挂载点（M15-①；指针 = rdi 慢路径语义，见 [`SYS_UMOUNT`]）。
    Umount {
        /// 路径长（字节，≤ 512）。
        len: u64,
    },
    /// 复制文件句柄（M15-②；见 [`SYS_DUP`]）。
    Dup {
        /// 源句柄。
        handle: u64,
    },
    /// 句柄描述符控制（M15-②；见 [`SYS_FCNTL`]）。
    Fcntl {
        /// 句柄。
        handle: u64,
        /// 命令（0 = DUPFD / 1 = GETFD / 2 = SETFD / 3 = DUP2FD）。
        cmd: u64,
        /// 参数（DUPFD 下界 / SETFD 旗标位集 / DUP2FD 目标槽位）。
        arg: u64,
    },
    /// 执行映像表查询（v0.19，M18-③；见 [`SYS_IMAGE_ENUM`]）。
    ImageEnum {
        /// 映像号（表索引；越界 → `ERR_IMAGE(10)`）。
        index: u64,
        /// 调用方缓冲指针（可写；路径 NUL 结尾拷入）。
        buf: u64,
        /// 缓冲长（字节，≤ 512）。
        buf_len: u64,
    },
    /// TTY 取字（v0.20，M23-②；见 [`SYS_TTY_GETCH`]）。
    TtyGetCh,
    /// 显示面映射（v0.21，M23-S1；见 [`SYS_FB_MAP`]）。
    FbMap {
        /// 用户虚地址（页对齐，[`FB_VA_BASE`] 域内）。
        va: u64,
    },
    /// 显示损伤屏障（v0.21，M23-S1；见 [`SYS_FB_SYNC`]）。
    FbSync {
        /// 损伤盒 x（i64 语义可负）。
        x: u64,
        /// 损伤盒 y。
        y: u64,
        /// 损伤盒宽。
        w: u64,
        /// 损伤盒高。
        h: u64,
    },
    /// 文本渲染服务（v0.22，M23-S2；见 [`SYS_FB_TEXT`]）。
    FbText {
        /// 起点 x（i64 语义可负，越屏裁剪）。
        x: u64,
        /// 起点 y。
        y: u64,
        /// 字符串指针（用户恒等窗）。
        buf: u64,
        /// 字节数（≤ 512）。
        len: u64,
    },
    /// stage 合成面（v0.17，M28-K1；见 [`SYS_FB_STAGE`]）。
    FbStage {
        /// 用户虚地址（页对齐，[`STAGE_VA_BASE`] 域内）。
        va: u64,
    },
    /// shell 管道/分页面（v0.24，M24-A1；见 [`SYS_PIPE`]）。
    Pipe {
        /// 操作码（0 捕获武装 / 1 排水 / 2 分页重放 / 3 弃置）。
        op: u64,
    },
    /// Surface 注册面（v0.18，M37-A1b；见 [`SYS_FB_SURFACE`]）。
    FbSurface {
        /// 操作码（0 登记 / 1 更新 / 2 注销）。
        op: u64,
        /// Surface 标识（1..=u32::MAX；0 保留 stage 底层）。
        id: u64,
        /// 屏上域 x（i32 语义，越屏域内核承接面拒收）。
        x: i32,
        /// 屏上域 y（i32 语义）。
        y: i32,
        /// 宽（1..=0xFFFF）。
        w: u32,
        /// 高（1..=0xFFFF）。
        h: u32,
        /// z 序（i32 语义，越大越靠上）。
        z: i32,
        /// 可见性（REGISTER 恒 true；UPDATE 域 = r8 bit 32）。
        visible: bool,
    },
    /// 用户态设备端口访问面（v0.19，M42-FBDEV1；见 [`SYS_DEV_PIO`]）。
    DevPio {
        /// 操作码（0..=5，宽度 × 方向——[`pio_op_decode`] 解码域）。
        op: u64,
        /// x86 I/O 端口号（0..=0xFFFF）。
        port: u16,
        /// OUT 域写入值（宽度掩码；IN 域忽略）。
        value: u64,
    },
    /// unix socket 域多路复用 op 面（v0.20，M42-UNIX3；见
    /// [`SYS_UNIXSOCK`]）。指针类参数（名字/载荷/缓冲指针）属慢路径
    /// 语义（rdx），不在结构校验域内。
    UnixSock {
        /// 操作码（0..=9——PAIR/BIND/CONNECT/ACCEPT/SEND/RECV/
        /// ACCEPT_B/SHUT/SEND_FD/RECV_FD）。
        op: u64,
        /// 调用方句柄（ACCEPT/SEND/RECV 域；PAIR/BIND/CONNECT 忽略）。
        handle: u64,
        /// 名字长/载荷长/缓冲长（parse 域闸：BIND/CONNECT 1..=108、
        /// SEND/RECV 1..=64 KiB）。
        len: u64,
    },
    /// wl_shm 共享内存池域（v0.22，M42-ELF5 桌面链批次；见
    /// [`SYS_SHM`]）。
    Shm {
        /// 操作码（0..=1——CREATE/MAP）。
        op: u64,
        /// CREATE：池尺寸字节（1..=[`SHM_SIZE_MAX`]）；MAP：池句柄。
        a: u64,
        /// MAP：映射窗虚地址（页对齐，[`SHM_VA_BASE`] 域内）；CREATE
        /// 忽略。
        b: u64,
    },
}

/// 从寄存器快照解析调用意图。只做结构校验，不做内存访问（由慢路径完成）。
pub fn parse(regs: SyscallRegs) -> Result<Syscall, AbiError> {
    let [a0, a1, a2, a3, a4] = regs.args;
    match regs.num {
        SYS_LOG if a1 <= 512 => Ok(Syscall::Log { len: a1 }),
        SYS_LOG => Err(AbiError::BadArgs),
        SYS_EXIT => Ok(Syscall::Exit { code: a0 as i32 }),
        SYS_YIELD => Ok(Syscall::Yield),
        SYS_IPC_SEND if a1 <= 4096 => Ok(Syscall::IpcSend {
            endpoint: a0,
            len: a1,
        }),
        SYS_IPC_SEND => Err(AbiError::BadArgs),
        SYS_IPC_RECV => Ok(Syscall::IpcRecv {
            endpoint: a0,
            buf_len: a1,
        }),
        SYS_CAP_DERIVE => Ok(Syscall::CapDerive {
            parent_handle: a0,
            rights: a1 as u32,
        }),
        SYS_SET_PRIO if a0 <= 3 => Ok(Syscall::SetPrio { level: a0 as u8 }),
        SYS_SET_PRIO => Err(AbiError::BadArgs),
        SYS_GET_PRIO => Ok(Syscall::GetPrio),
        SYS_CAP_GRANT => Ok(Syscall::CapGrant {
            target_pid: a0,
            handle: a1,
            rights: a2 as u32,
        }),
        SYS_CAP_REVOKE => Ok(Syscall::CapRevoke { handle: a0 }),
        SYS_GET_PID => Ok(Syscall::GetPid),
        SYS_WAIT_PID => Ok(Syscall::WaitPid { pid: a0 }),
        SYS_SPAWN if a0 == 0 => Ok(Syscall::Spawn { reserved: a0 }),
        SYS_SPAWN => Err(AbiError::BadArgs),
        SYS_HANDLE_QUERY => Ok(Syscall::HandleQuery { handle: a0 }),
        SYS_HANDLE_ENUM => Ok(Syscall::HandleEnum { cursor: a0 }),
        SYS_IPC_BIND if a0 == 0 => Ok(Syscall::IpcBind { reserved: a0 }),
        SYS_IPC_BIND => Err(AbiError::BadArgs),
        SYS_EXEC => Ok(Syscall::Exec { image: a0 }),
        SYS_OPEN if a1 <= 512 && a2 <= OPEN_MODE_MASK && a2 & 0b11 != 0 => Ok(Syscall::Open {
            len: a1,
            mode: a2 as u8,
        }),
        SYS_OPEN => Err(AbiError::BadArgs),
        SYS_READ if a2 <= 512 => Ok(Syscall::Read {
            handle: a0,
            len: a2,
        }),
        SYS_READ => Err(AbiError::BadArgs),
        SYS_WRITE if a2 <= 512 => Ok(Syscall::Write {
            handle: a0,
            len: a2,
        }),
        SYS_WRITE => Err(AbiError::BadArgs),
        SYS_CLOSE => Ok(Syscall::Close { handle: a0 }),
        SYS_STAT => Ok(Syscall::Stat { handle: a0 }),
        SYS_SEEK if a1 <= 2 => Ok(Syscall::Seek {
            handle: a0,
            whence: a1 as u8,
            offset: a2,
        }),
        SYS_SEEK => Err(AbiError::BadArgs),
        SYS_NANOSLEEP => Ok(Syscall::NanoSleep { ticks: a0 }),
        SYS_QUOTA if a0 <= 3 => Ok(Syscall::Quota { kind: a0 }),
        SYS_QUOTA => Err(AbiError::BadArgs),
        SYS_MKDIR if a1 <= 512 => Ok(Syscall::MkDir { len: a1 }),
        SYS_MKDIR => Err(AbiError::BadArgs),
        SYS_REMOVE if a1 <= 512 => Ok(Syscall::Remove { len: a1 }),
        SYS_REMOVE => Err(AbiError::BadArgs),
        SYS_READDIR if a2 <= 512 => Ok(Syscall::ReadDir {
            handle: a0,
            buf_len: a2,
        }),
        SYS_READDIR => Err(AbiError::BadArgs),
        SYS_MOUNT if a1 <= 512 && a2 <= 1 => Ok(Syscall::Mount {
            len: a1,
            fs_type: a2,
        }),
        SYS_MOUNT => Err(AbiError::BadArgs),
        SYS_UMOUNT if a1 <= 512 => Ok(Syscall::Umount { len: a1 }),
        SYS_UMOUNT => Err(AbiError::BadArgs),
        SYS_DUP => Ok(Syscall::Dup { handle: a0 }),
        SYS_FCNTL if a1 <= 3 => Ok(Syscall::Fcntl {
            handle: a0,
            cmd: a1,
            arg: a2,
        }),
        SYS_FCNTL => Err(AbiError::BadArgs),
        SYS_IMAGE_ENUM if a2 <= 512 => Ok(Syscall::ImageEnum {
            index: a0,
            buf: a1,
            buf_len: a2,
        }),
        SYS_IMAGE_ENUM => Err(AbiError::BadArgs),
        SYS_TTY_GETCH => Ok(Syscall::TtyGetCh),
        SYS_FB_MAP if (FB_VA_BASE..FB_VA_LIMIT).contains(&a1) && a1 & 0xFFF == 0 => {
            Ok(Syscall::FbMap { va: a1 })
        }
        SYS_FB_MAP => Err(AbiError::BadArgs),
        SYS_FB_SYNC => Ok(Syscall::FbSync {
            x: a0,
            y: a1,
            w: a2,
            h: a3,
        }),
        SYS_FB_TEXT if a3 <= 512 => Ok(Syscall::FbText {
            x: a0,
            y: a1,
            buf: a2,
            len: a3,
        }),
        SYS_FB_TEXT => Err(AbiError::BadArgs),
        SYS_FB_STAGE if (STAGE_VA_BASE..STAGE_VA_LIMIT).contains(&a1) && a1 & 0xFFF == 0 => {
            Ok(Syscall::FbStage { va: a1 })
        }
        SYS_FB_STAGE => Err(AbiError::BadArgs),
        SYS_PIPE if a0 <= 3 => Ok(Syscall::Pipe { op: a0 }),
        SYS_PIPE => Err(AbiError::BadArgs),
        SYS_FB_SURFACE
            if a0 <= 2
                && a1 != 0
                && a1 <= u64::from(u32::MAX)
                && (a3 & 0xFFFF_FFFF) != 0
                && (a3 & 0xFFFF_FFFF) <= 0xFFFF
                && (a3 >> 32) != 0
                && (a3 >> 32) <= 0xFFFF =>
        {
            Ok(Syscall::FbSurface {
                op: a0,
                id: a1,
                x: a2 as u32 as i32,
                y: (a2 >> 32) as u32 as i32,
                w: (a3 & 0xFFFF_FFFF) as u32,
                h: (a3 >> 32) as u32,
                z: if a0 == 2 { 0 } else { a4 as u32 as i32 },
                visible: a0 != 1 || (a4 >> 32) & 1 == 1,
            })
        }
        SYS_FB_SURFACE => Err(AbiError::BadArgs),
        SYS_DEV_PIO if a0 <= PIO_OUT32 && a1 <= 0xFFFF => Ok(Syscall::DevPio {
            op: a0,
            port: a1 as u16,
            value: a2,
        }),
        SYS_DEV_PIO => Err(AbiError::BadArgs),
        SYS_UNIXSOCK if a0 <= USOCK_RECV_FD && unixsock_len_ok(a0, a3) => Ok(Syscall::UnixSock {
            op: a0,
            handle: a1,
            len: a3,
        }),
        SYS_UNIXSOCK => Err(AbiError::BadArgs),
        SYS_SHM if a0 <= SHM_MAP && shm_args_ok(a0, a1, a2) => Ok(Syscall::Shm {
            op: a0,
            a: a1,
            b: a2,
        }),
        SYS_SHM => Err(AbiError::BadArgs),
        _ => Err(AbiError::UnknownSyscall),
    }
}

/// [`SYS_UNIXSOCK`] 长度域闸（parse 层结构校验）：BIND/CONNECT = 名字
/// 长 1..=[`USOCK_NAME_MAX`]（词法域由 [`usock_name_ok`] 在内核注册面
/// 复审——parse 只看长度不看内容）；SEND/RECV = 载荷/缓冲长
/// 1..=[`USOCK_LEN_MAX`]（validate_user_slice 预算域同源）；
/// PAIR/ACCEPT = 不校验（长度参数无语义）。
fn unixsock_len_ok(op: u64, len: u64) -> bool {
    match op {
        USOCK_PAIR | USOCK_ACCEPT | USOCK_ACCEPT_B | USOCK_SHUT | USOCK_SEND_FD | USOCK_RECV_FD => {
            true
        }
        USOCK_BIND | USOCK_CONNECT => (1..=USOCK_NAME_MAX).contains(&len),
        USOCK_SEND | USOCK_RECV => (1..=USOCK_LEN_MAX).contains(&len),
        _ => false,
    }
}

/// [`SYS_SHM`] 参数域闸（parse 层结构校验）：CREATE = 尺寸
/// 1..=[`SHM_SIZE_MAX`]；MAP = 句柄非零 + 虚地址页对齐且落
/// [`SHM_VA_BASE`]..[`SHM_VA_LIMIT`] 窗（尺寸域内核侧复审——池实际
/// 尺寸为映射预算源）。
fn shm_args_ok(op: u64, a: u64, b: u64) -> bool {
    match op {
        SHM_CREATE => (1..=SHM_SIZE_MAX).contains(&a),
        SHM_MAP => {
            a != 0
                && a <= 0xFFFF
                && (SHM_VA_BASE..SHM_VA_LIMIT).contains(&b)
                && b.is_multiple_of(0x1000)
        }
        _ => false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        AbiError, Syscall, SyscallRegs, SYS_CAP_DERIVE, SYS_CAP_GRANT, SYS_CAP_REVOKE, SYS_EXIT,
        SYS_GET_PID, SYS_GET_PRIO, SYS_IPC_SEND, SYS_LOG, SYS_SET_PRIO, SYS_SPAWN, SYS_WAIT_PID,
        SYS_YIELD,
    };

    #[test]
    fn parse_known_calls() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        assert_eq!(super::parse(r(SYS_YIELD, [0; 5])), Ok(Syscall::Yield));
        assert_eq!(
            super::parse(r(SYS_EXIT, [3, 0, 0, 0, 0])),
            Ok(Syscall::Exit { code: 3 })
        );
        assert_eq!(
            super::parse(r(SYS_IPC_SEND, [7, 64, 0, 0, 0])),
            Ok(Syscall::IpcSend {
                endpoint: 7,
                len: 64
            })
        );
        assert_eq!(
            super::parse(r(SYS_CAP_DERIVE, [2, 0b11, 0, 0, 0])),
            Ok(Syscall::CapDerive {
                parent_handle: 2,
                rights: 0b11
            })
        );
    }

    #[test]
    fn parses_prio_calls() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        assert_eq!(
            super::parse(r(SYS_SET_PRIO, [2, 0, 0, 0, 0])),
            Ok(Syscall::SetPrio { level: 2 })
        );
        assert_eq!(super::parse(r(SYS_GET_PRIO, [0; 5])), Ok(Syscall::GetPrio));
        // 越界级数 = 坏参数（级数上限 3）
        assert_eq!(
            super::parse(r(SYS_SET_PRIO, [4, 0, 0, 0, 0])),
            Err(AbiError::BadArgs)
        );
    }

    #[test]
    fn parses_process_model_calls() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        assert_eq!(
            super::parse(r(SYS_CAP_GRANT, [7, 1, 0b11, 0, 0])),
            Ok(Syscall::CapGrant {
                target_pid: 7,
                handle: 1,
                rights: 0b11
            })
        );
        assert_eq!(
            super::parse(r(SYS_CAP_REVOKE, [2, 0, 0, 0, 0])),
            Ok(Syscall::CapRevoke { handle: 2 })
        );
        assert_eq!(super::parse(r(SYS_GET_PID, [0; 5])), Ok(Syscall::GetPid));
    }

    #[test]
    fn parses_waitpid_call() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        // 0 = 任意直接子任务；非 0 = 定向等待
        assert_eq!(
            super::parse(r(SYS_WAIT_PID, [0, 0, 0, 0, 0])),
            Ok(Syscall::WaitPid { pid: 0 })
        );
        assert_eq!(
            super::parse(r(SYS_WAIT_PID, [7, 0, 0, 0, 0])),
            Ok(Syscall::WaitPid { pid: 7 })
        );
    }

    #[test]
    fn parses_spawn_call() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        // v0 保留参数必须为 0
        assert_eq!(
            super::parse(r(SYS_SPAWN, [0, 0, 0, 0, 0])),
            Ok(Syscall::Spawn { reserved: 0 })
        );
        assert_eq!(
            super::parse(r(SYS_SPAWN, [1, 0, 0, 0, 0])),
            Err(AbiError::BadArgs)
        );
    }

    #[test]
    fn parses_ipc_bind_call() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        // v0 保留参数必须为 0
        assert_eq!(
            super::parse(r(super::SYS_IPC_BIND, [0, 0, 0, 0, 0])),
            Ok(Syscall::IpcBind { reserved: 0 })
        );
        assert_eq!(
            super::parse(r(super::SYS_IPC_BIND, [1, 0, 0, 0, 0])),
            Err(AbiError::BadArgs)
        );
    }

    #[test]
    fn parses_exec_call() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        // 映像号透传（越界由内核映像表面验 → ERR_IMAGE）
        assert_eq!(
            super::parse(r(super::SYS_EXEC, [0, 0, 0, 0, 0])),
            Ok(Syscall::Exec { image: 0 })
        );
        assert_eq!(
            super::parse(r(super::SYS_EXEC, [7, 0, 0, 0, 0])),
            Ok(Syscall::Exec { image: 7 })
        );
    }

    #[test]
    fn parses_file_face_calls() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        // OPEN：len ≤ 512 且 mode ≤ OPEN_MODE_MASK 且访问位非零
        assert_eq!(
            super::parse(r(super::SYS_OPEN, [0x2000, 11, 0b11, 0, 0])),
            Ok(Syscall::Open {
                len: 11,
                mode: 0b11
            })
        );
        assert_eq!(
            super::parse(r(super::SYS_OPEN, [0x2000, 513, 1, 0, 0])),
            Err(AbiError::BadArgs),
            "len 越界"
        );
        // v0.17 M16-①：O_CREAT/O_TRUNC 域（访问位非零前置）
        assert_eq!(
            super::parse(r(
                super::SYS_OPEN,
                [0x2000, 11, super::O_CREAT | 0b10, 0, 0]
            )),
            Ok(Syscall::Open {
                len: 11,
                mode: (super::O_CREAT | 0b10) as u8
            }),
            "O_CREAT|WRITES"
        );
        assert_eq!(
            super::parse(r(
                super::SYS_OPEN,
                [0x2000, 11, super::O_TRUNC | 0b11, 0, 0]
            )),
            Ok(Syscall::Open {
                len: 11,
                mode: (super::O_TRUNC | 0b11) as u8
            }),
            "O_TRUNC|RDWR"
        );
        assert_eq!(
            super::parse(r(super::SYS_OPEN, [0x2000, 11, 0b100, 0, 0])),
            Err(AbiError::BadArgs),
            "O_CREAT 无访问位拒收"
        );
        assert_eq!(
            super::parse(r(super::SYS_OPEN, [0x2000, 11, 0b10100, 0, 0])),
            Err(AbiError::BadArgs),
            "mode 保留位拒收"
        );
        assert_eq!(
            super::parse(r(super::SYS_OPEN, [0x2000, 11, 0, 0, 0])),
            Err(AbiError::BadArgs),
            "零模式拒收（结构面）"
        );
        // READ/WRITE：len ≤ 512 结构校验；句柄透传
        assert_eq!(
            super::parse(r(super::SYS_READ, [3, 0x402E00, 64, 0, 0])),
            Ok(Syscall::Read { handle: 3, len: 64 })
        );
        assert_eq!(
            super::parse(r(super::SYS_WRITE, [3, 0x402E00, 8, 0, 0])),
            Ok(Syscall::Write { handle: 3, len: 8 })
        );
        assert_eq!(
            super::parse(r(super::SYS_READ, [3, 0x402E00, 513, 0, 0])),
            Err(AbiError::BadArgs)
        );
        // CLOSE/STAT：句柄透传
        assert_eq!(
            super::parse(r(super::SYS_CLOSE, [3, 0, 0, 0, 0])),
            Ok(Syscall::Close { handle: 3 })
        );
        assert_eq!(
            super::parse(r(super::SYS_STAT, [3, 0, 0, 0, 0])),
            Ok(Syscall::Stat { handle: 3 })
        );
        // SEEK：whence ∈ 0..=2 结构校验；offset i64 位型透传
        assert_eq!(
            super::parse(r(super::SYS_SEEK, [3, 1, 8, 0, 0])),
            Ok(Syscall::Seek {
                handle: 3,
                whence: 1,
                offset: 8
            })
        );
        // 负偏移（i64 位型）
        assert_eq!(
            super::parse(r(super::SYS_SEEK, [3, 1, u64::MAX, 0, 0])),
            Ok(Syscall::Seek {
                handle: 3,
                whence: 1,
                offset: u64::MAX
            })
        );
        assert_eq!(
            super::parse(r(super::SYS_SEEK, [3, 3, 0, 0, 0])),
            Err(AbiError::BadArgs),
            "whence 越界"
        );
        // NANOSLEEP：ns 透传（v0.16 TSC 纳秒语义；0 合法 = 探针命中即时返回语义）
        assert_eq!(
            super::parse(r(super::SYS_NANOSLEEP, [0, 0, 0, 0, 0])),
            Ok(Syscall::NanoSleep { ticks: 0 })
        );
        assert_eq!(
            super::parse(r(super::SYS_NANOSLEEP, [5, 0, 0, 0, 0])),
            Ok(Syscall::NanoSleep { ticks: 5 })
        );
    }

    #[test]
    fn parses_directory_face_calls() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        // MKDIR/REMOVE：len ≤ 512 结构校验（指针 = rdi 慢路径语义）
        assert_eq!(
            super::parse(r(super::SYS_MKDIR, [0x2000, 14, 0, 0, 0])),
            Ok(Syscall::MkDir { len: 14 })
        );
        assert_eq!(
            super::parse(r(super::SYS_MKDIR, [0x2000, 513, 0, 0, 0])),
            Err(AbiError::BadArgs),
            "len 越界"
        );
        assert_eq!(
            super::parse(r(super::SYS_REMOVE, [0x2000, 9, 0, 0, 0])),
            Ok(Syscall::Remove { len: 9 })
        );
        // READDIR：句柄 + buf_len ≤ 512（缓冲 = rsi 慢路径语义）
        assert_eq!(
            super::parse(r(super::SYS_READDIR, [3, 0x402E00, 128, 0, 0])),
            Ok(Syscall::ReadDir {
                handle: 3,
                buf_len: 128
            })
        );
        assert_eq!(
            super::parse(r(super::SYS_READDIR, [3, 0x402E00, 513, 0, 0])),
            Err(AbiError::BadArgs),
            "buf_len 越界"
        );
        // MOUNT：len ≤ 512 且 fs_type 域 0..=1（M17-①：1 = LFS1 盘上 fs）
        assert_eq!(
            super::parse(r(super::SYS_MOUNT, [0x2000, 10, 0, 0, 0])),
            Ok(Syscall::Mount {
                len: 10,
                fs_type: 0
            })
        );
        assert_eq!(
            super::parse(r(super::SYS_MOUNT, [0x2000, 10, 1, 0, 0])),
            Ok(Syscall::Mount {
                len: 10,
                fs_type: 1
            }),
            "fs_type 1 = 盘上 fs 新域"
        );
        assert_eq!(
            super::parse(r(super::SYS_MOUNT, [0x2000, 10, 2, 0, 0])),
            Err(AbiError::BadArgs),
            "fs_type 保留域拒收"
        );
        // UMOUNT：len ≤ 512
        assert_eq!(
            super::parse(r(super::SYS_UMOUNT, [0x2000, 10, 0, 0, 0])),
            Ok(Syscall::Umount { len: 10 })
        );
    }

    #[test]
    fn parses_handle_deepening_calls() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        // DUP：句柄透传
        assert_eq!(
            super::parse(r(super::SYS_DUP, [3, 0, 0, 0, 0])),
            Ok(Syscall::Dup { handle: 3 })
        );
        // FCNTL：命令 ∈ 0..=3 结构校验（DUPFD/GETFD/SETFD/DUP2FD）；arg 透传
        assert_eq!(
            super::parse(r(super::SYS_FCNTL, [3, super::F_DUPFD, 4, 0, 0])),
            Ok(Syscall::Fcntl {
                handle: 3,
                cmd: super::F_DUPFD,
                arg: 4
            })
        );
        assert_eq!(
            super::parse(r(super::SYS_FCNTL, [3, super::F_DUP2FD, 5, 0, 0])),
            Ok(Syscall::Fcntl {
                handle: 3,
                cmd: super::F_DUP2FD,
                arg: 5
            })
        );
        assert_eq!(
            super::parse(r(
                super::SYS_FCNTL,
                [3, super::F_SETFD, super::FD_CLOEXEC, 0, 0]
            )),
            Ok(Syscall::Fcntl {
                handle: 3,
                cmd: super::F_SETFD,
                arg: super::FD_CLOEXEC
            })
        );
        assert_eq!(
            super::parse(r(super::SYS_FCNTL, [3, 4, 0, 0, 0])),
            Err(AbiError::BadArgs),
            "命令越界"
        );
        // IMAGE_ENUM：index/buf 透传，buf_len ≤ 512 结构校验
        assert_eq!(
            super::parse(r(super::SYS_IMAGE_ENUM, [1, 0x4000_0000, 64, 0, 0])),
            Ok(Syscall::ImageEnum {
                index: 1,
                buf: 0x4000_0000,
                buf_len: 64
            })
        );
        assert_eq!(
            super::parse(r(super::SYS_IMAGE_ENUM, [1, 0x4000_0000, 513, 0, 0])),
            Err(AbiError::BadArgs),
            "缓冲长越界"
        );
    }

    #[test]
    fn file_face_numbers_are_appended_in_order() {
        // 追加纪律：v0 编号不得复用或改序——18..=32 顺序落位自证
        assert_eq!(super::SYS_OPEN, 18);
        assert_eq!(super::SYS_READ, 19);
        assert_eq!(super::SYS_WRITE, 20);
        assert_eq!(super::SYS_CLOSE, 21);
        assert_eq!(super::SYS_STAT, 22);
        assert_eq!(super::SYS_SEEK, 23);
        assert_eq!(super::SYS_NANOSLEEP, 24);
        assert_eq!(super::SYS_QUOTA, 25);
        assert_eq!(super::SYS_MKDIR, 26);
        assert_eq!(super::SYS_REMOVE, 27);
        assert_eq!(super::SYS_READDIR, 28);
        assert_eq!(super::SYS_MOUNT, 29);
        assert_eq!(super::SYS_UMOUNT, 30);
        assert_eq!(super::SYS_DUP, 31);
        assert_eq!(super::SYS_FCNTL, 32);
        assert_eq!(super::SYS_IMAGE_ENUM, 33);
        assert_eq!(super::ABI_VERSION, (0, 22));
        assert_eq!(super::SYS_TTY_GETCH, 34);
        assert_eq!(
            super::parse(super::SyscallRegs {
                num: super::SYS_TTY_GETCH,
                args: [0; 5]
            }),
            Ok(Syscall::TtyGetCh),
            "TTY 取字：零参轮询面（Yield 同款零参范式）"
        );
        assert_eq!(super::SYS_FB_MAP, 35);
        assert_eq!(super::SYS_FB_SYNC, 36);
        assert_eq!(super::SYS_FB_TEXT, 37);
        assert_eq!(super::SYS_PIPE, 38);
        assert_eq!(super::SYS_FB_STAGE, 39);
        assert_eq!(super::SYS_FB_SURFACE, 40);
        // M42-FBDEV1：SYS_DEV_PIO(41) 号域续接（ABI v0.19）
        assert_eq!(super::SYS_DEV_PIO, 41);
        // M42-COMP4：op 面扩容 6/7（阻塞 accept + shutdown）+ ERR_PIPE(13)
        assert_eq!(super::USOCK_ACCEPT_B, 6);
        assert_eq!(super::USOCK_SHUT, 7);
        assert_eq!(super::ERR_PIPE, 13);
        assert_eq!(super::SVC_COMPOSITOR, super::SVC_ID_BASE + 6);
        assert_eq!(
            super::parse(super::SyscallRegs {
                num: super::SYS_PIPE,
                args: [3, 0, 0, 0, 0]
            }),
            Ok(Syscall::Pipe { op: 3 }),
            "管道面：op 域 0..=3（3 = 弃置臂自证）"
        );
        assert_eq!(
            super::parse(super::SyscallRegs {
                num: super::SYS_PIPE,
                args: [4, 0, 0, 0, 0]
            }),
            Err(AbiError::BadArgs),
            "管道面：op 越域拒收"
        );
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        // FB_MAP：va 域结构校验（FB_VA_BASE 起、页对齐；域外/不对齐 BadArgs）
        assert_eq!(
            super::parse(r(super::SYS_FB_MAP, [0, super::FB_VA_BASE, 0, 0, 0])),
            Ok(Syscall::FbMap {
                va: super::FB_VA_BASE
            }),
            "域基址 + 页对齐 → 受理"
        );
        assert_eq!(
            super::parse(r(super::SYS_FB_MAP, [0, 0x4020_1800, 0, 0, 0])),
            Err(AbiError::BadArgs),
            "页不对齐拒"
        );
        assert_eq!(
            super::parse(r(super::SYS_FB_MAP, [0, 0x1000, 0, 0, 0])),
            Err(AbiError::BadArgs),
            "域外（低于 FB_VA_BASE）拒"
        );
        // FB_SYNC：损伤盒四参透传（i64 语义可负——u64 位型透传）
        assert_eq!(
            super::parse(r(super::SYS_FB_SYNC, [0, 704, 1024, 64, 0])),
            Ok(Syscall::FbSync {
                x: 0,
                y: 704,
                w: 1024,
                h: 64
            }),
            "损伤盒四参透传"
        );
        // FB_TEXT：四参透传 + 长度域（≤ 512）
        assert_eq!(
            super::parse(r(super::SYS_FB_TEXT, [32, 560, 0x400000, 15, 0])),
            Ok(Syscall::FbText {
                x: 32,
                y: 560,
                buf: 0x400000,
                len: 15
            }),
            "文本服务四参透传"
        );
        // FB_STAGE：va 域结构校验（STAGE_VA_BASE 域内 + 页对齐；
        // 域外/不对齐 BadArgs——v0.17 M28-K1）
        assert_eq!(
            super::parse(r(super::SYS_FB_STAGE, [0, super::STAGE_VA_BASE, 0, 0, 0])),
            Ok(Syscall::FbStage {
                va: super::STAGE_VA_BASE
            }),
            "stage 基址受理"
        );
        assert_eq!(
            super::parse(r(super::SYS_FB_STAGE, [0, 0x5000_1800, 0, 0, 0])),
            Err(AbiError::BadArgs),
            "stage 页不对齐拒"
        );
        assert_eq!(
            super::parse(r(super::SYS_FB_STAGE, [0, 0x1000, 0, 0, 0])),
            Err(AbiError::BadArgs),
            "stage 域外拒"
        );
        assert_eq!(
            super::parse(r(super::SYS_FB_TEXT, [0, 0, 0, 513, 0])),
            Err(AbiError::BadArgs),
            "len 超域（> 512）拒"
        );
    }

    #[test]
    fn quota_parse_validates_kind_domain() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        for kind in 0u64..=3 {
            assert_eq!(
                super::parse(r(super::SYS_QUOTA, [kind, 0, 0, 0, 0])),
                Ok(Syscall::Quota { kind })
            );
        }
        // kind 越界（4+）= BadArgs（SEEK whence 先例同款结构校验）
        assert_eq!(
            super::parse(r(super::SYS_QUOTA, [4, 0, 0, 0, 0])),
            Err(AbiError::BadArgs)
        );
        assert_eq!(
            super::parse(r(super::SYS_QUOTA, [u64::MAX, 0, 0, 0, 0])),
            Err(AbiError::BadArgs)
        );
    }

    #[test]
    fn rejects_unknown_and_bad_args() {
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        assert_eq!(super::parse(r(999, [0; 5])), Err(AbiError::UnknownSyscall));
        assert_eq!(
            super::parse(r(SYS_LOG, [0, 513, 0, 0, 0])),
            Err(AbiError::BadArgs)
        );
        assert_eq!(
            super::parse(r(SYS_IPC_SEND, [0, 4097, 0, 0, 0])),
            Err(AbiError::BadArgs)
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod svc_abi_tests {
    use super::{
        svc_name_ok, SVC_BLOCK, SVC_COMPOSITOR, SVC_CONSOLE, SVC_FB, SVC_ID_BASE, SVC_KBD,
        SVC_NAME_MAX, SVC_PRESET_COUNT, SVC_VNET,
    };

    #[test]
    fn svc_name_lexical_gate() {
        // M34-D1 契约宿主对账：词法闸 golden
        assert!(svc_name_ok("vnet"));
        assert!(svc_name_ok("fb"));
        assert!(svc_name_ok("kbd"));
        assert!(svc_name_ok("console"));
        assert!(svc_name_ok("block"));
        assert!(svc_name_ok("compositor")); // M42-COMP4 第 6 预设
        assert!(svc_name_ok("a23-b"));
        assert!(!svc_name_ok("")); // 空
        assert!(!svc_name_ok(&"x".repeat(SVC_NAME_MAX + 1))); // 越界
        assert!(!svc_name_ok("Vnet")); // 大写拒收
        assert!(!svc_name_ok("v net")); // 空格拒收
        assert!(!svc_name_ok("v/net")); // 分隔符拒收
    }

    #[test]
    fn svc_ids_segment_orthogonal() {
        // 0x5E00 段与文件 0xF11E / 通道 0xC0DE 段正交；六预设连续
        // （M42-COMP4：第 6 项 SVC_COMPOSITOR 合成器进程面）
        assert_eq!(SVC_VNET, SVC_ID_BASE + 1);
        assert_eq!(SVC_FB, SVC_ID_BASE + 2);
        assert_eq!(SVC_KBD, SVC_ID_BASE + 3);
        assert_eq!(SVC_CONSOLE, SVC_ID_BASE + 4);
        assert_eq!(SVC_BLOCK, SVC_ID_BASE + 5);
        assert_eq!(SVC_COMPOSITOR, SVC_ID_BASE + 6);
        let ids = [
            SVC_VNET,
            SVC_FB,
            SVC_KBD,
            SVC_CONSOLE,
            SVC_BLOCK,
            SVC_COMPOSITOR,
        ];
        assert_eq!(ids.len(), SVC_PRESET_COUNT);
        for a in 0..ids.len() {
            for b in a + 1..ids.len() {
                assert_ne!(ids[a], ids[b]);
            }
        }
    }

    /// SYS_FB_SURFACE(40) 三操作 parse 域（v0.18，M37-A1b）：xy/wh 打包
    /// 解包 roundtrip + op 域 + id 0 保留域 + wh 零/越域拒收 + UPDATE
    /// visible 位解码 + REMOVE 恒零域。
    #[test]
    fn parse_fb_surface_ops() {
        let r = |num: u64, args: [u64; 5]| super::SyscallRegs { num, args };
        // REGISTER roundtrip：xy 低位 x/高位 y、wh 低位 w/高位 h、r8 = z
        assert_eq!(
            super::parse(r(
                super::SYS_FB_SURFACE,
                [0, 7, (100u64 << 32) | 40, (64u64 << 32) | 32, 5,]
            )),
            Ok(super::Syscall::FbSurface {
                op: 0,
                id: 7,
                x: 40,
                y: 100,
                w: 32,
                h: 64,
                z: 5,
                visible: true,
            }),
            "REGISTER：打包域解包 roundtrip（visible 恒 true）"
        );
        // 负坐标 i32 语义透传（位型重解释——屏域校验在内核承接面）
        assert_eq!(
            super::parse(r(
                super::SYS_FB_SURFACE,
                [
                    0,
                    7,
                    ((-8i64 as u64) << 32) | u64::from(-4i32 as u32),
                    (8u64 << 32) | 8,
                    0,
                ]
            )),
            Ok(super::Syscall::FbSurface {
                op: 0,
                id: 7,
                x: -4,
                y: -8,
                w: 8,
                h: 8,
                z: 0,
                visible: true,
            }),
            "REGISTER：负坐标 i32 语义透传"
        );
        // UPDATE：r8 低 32 = z、bit 32 = visible
        assert_eq!(
            super::parse(r(
                super::SYS_FB_SURFACE,
                [
                    1,
                    7,
                    (60u64 << 32) | 200,
                    (32u64 << 32) | 32,
                    (1u64 << 32) | (-3i64 as u64 & 0xFFFF_FFFF),
                ]
            )),
            Ok(super::Syscall::FbSurface {
                op: 1,
                id: 7,
                x: 200,
                y: 60,
                w: 32,
                h: 32,
                z: -3,
                visible: true,
            }),
            "UPDATE：z + visible 位解码（bit 32 置位）"
        );
        assert_eq!(
            super::parse(r(super::SYS_FB_SURFACE, [1, 7, 0, (8u64 << 32) | 8, 2])),
            Ok(super::Syscall::FbSurface {
                op: 1,
                id: 7,
                x: 0,
                y: 0,
                w: 8,
                h: 8,
                z: 2,
                visible: false,
            }),
            "UPDATE：bit 32 清零 = 隐藏"
        );
        // REMOVE：z 恒零域
        assert_eq!(
            super::parse(r(super::SYS_FB_SURFACE, [2, 7, 0, (8u64 << 32) | 8, 0])),
            Ok(super::Syscall::FbSurface {
                op: 2,
                id: 7,
                x: 0,
                y: 0,
                w: 8,
                h: 8,
                z: 0,
                visible: true,
            }),
            "REMOVE：z 恒零（visible 与 REGISTER 同域恒 true）"
        );
        // 坏参域：op 越域 / id 0 保留 / wh 零 / wh 越 0xFFFF
        assert_eq!(
            super::parse(r(super::SYS_FB_SURFACE, [3, 7, 0, (8u64 << 32) | 8, 0])),
            Err(super::AbiError::BadArgs),
            "op 3 越域拒收"
        );
        assert_eq!(
            super::parse(r(super::SYS_FB_SURFACE, [0, 0, 0, (8u64 << 32) | 8, 0])),
            Err(super::AbiError::BadArgs),
            "id 0 = stage 底层保留域拒收"
        );
        assert_eq!(
            super::parse(r(super::SYS_FB_SURFACE, [0, 7, 0, 8, 0])),
            Err(super::AbiError::BadArgs),
            "w = 0 拒收（wh 低 32 位 = w）"
        );
        assert_eq!(
            super::parse(r(super::SYS_FB_SURFACE, [0, 7, 0, 8u64 << 32, 0])),
            Err(super::AbiError::BadArgs),
            "h = 0 拒收（wh 高 32 位 = h）"
        );
        assert_eq!(
            super::parse(r(
                super::SYS_FB_SURFACE,
                [0, 7, 0, (0x1_0000u64 << 32) | 8, 0,]
            )),
            Err(super::AbiError::BadArgs),
            "h > 0xFFFF 结构域拒收"
        );
    }

    /// SYS_DEV_PIO(41) parse 域（v0.19，M42-FBDEV1）：op 0..=5 × port
    /// 0..=0xFFFF 收录 + op 越域/port 越域拒收 + value 透传 + 解码器
    /// 对账（pio_op_decode 六臂全谱 + 域外 None）。
    #[test]
    fn parse_dev_pio_ops() {
        let r = |num: u64, args: [u64; 5]| super::SyscallRegs { num, args };
        // IN16 roundtrip：dispi 数据口读（M42-FBDEV1 fbdev 车道）
        assert_eq!(
            super::parse(r(super::SYS_DEV_PIO, [super::PIO_IN16, 0x1CF, 0, 0, 0])),
            Ok(super::Syscall::DevPio {
                op: super::PIO_IN16,
                port: 0x1CF,
                value: 0,
            }),
            "IN16：dispi 数据口（0x1CF）收录"
        );
        // OUT16：dispi 索引口写 + value 透传
        assert_eq!(
            super::parse(r(super::SYS_DEV_PIO, [super::PIO_OUT16, 0x1CE, 0, 0, 0])),
            Ok(super::Syscall::DevPio {
                op: super::PIO_OUT16,
                port: 0x1CE,
                value: 0,
            }),
            "OUT16：dispi 索引口（0x1CE）收录"
        );
        // 六 op 全谱 + 端口边界（0 / 0xFFFF）
        for op in 0..=5u64 {
            for port in [0u64, 0xFFFF] {
                assert_eq!(
                    super::parse(r(super::SYS_DEV_PIO, [op, port, 0x1234, 0, 0])),
                    Ok(super::Syscall::DevPio {
                        op,
                        port: port as u16,
                        value: 0x1234,
                    }),
                    "op={op} port={port}：域内收录"
                );
            }
        }
        // op 越域拒收（6 起）
        assert_eq!(
            super::parse(r(super::SYS_DEV_PIO, [6, 0x1CE, 0, 0, 0])),
            Err(super::AbiError::BadArgs),
            "op 6 越域拒收"
        );
        assert_eq!(
            super::parse(r(super::SYS_DEV_PIO, [u64::MAX, 0x1CE, 0, 0, 0])),
            Err(super::AbiError::BadArgs),
            "op u64::MAX 越域拒收"
        );
        // port 越域拒收（0x10000 起）
        assert_eq!(
            super::parse(r(super::SYS_DEV_PIO, [super::PIO_IN8, 0x1_0000, 0, 0, 0])),
            Err(super::AbiError::BadArgs),
            "port 0x10000 越域拒收"
        );
        // 解码器对账：六臂全谱（宽度 × 方向）
        assert_eq!(super::pio_op_decode(super::PIO_IN8), Some((1, false)));
        assert_eq!(super::pio_op_decode(super::PIO_OUT8), Some((1, true)));
        assert_eq!(super::pio_op_decode(super::PIO_IN16), Some((2, false)));
        assert_eq!(super::pio_op_decode(super::PIO_OUT16), Some((2, true)));
        assert_eq!(super::pio_op_decode(super::PIO_IN32), Some((4, false)));
        assert_eq!(super::pio_op_decode(super::PIO_OUT32), Some((4, true)));
        assert_eq!(super::pio_op_decode(6), None);
        assert_eq!(super::pio_op_decode(u64::MAX), None);
    }

    /// SYS_UNIXSOCK(42) parse 域（v0.20，M42-UNIX3）：六 op 收录 +
    /// 名字/载荷长度域闸 + op 越域拒收 + 词法闸对账（usock_name_ok
    /// 可打印域 + sun_path 上界）。
    #[test]
    fn parse_unixsock_ops() {
        let r = |num: u64, args: [u64; 5]| super::SyscallRegs { num, args };
        // PAIR：长度参数无语义（零值透传）
        assert_eq!(
            super::parse(r(super::SYS_UNIXSOCK, [super::USOCK_PAIR, 0, 0, 0, 0])),
            Ok(super::Syscall::UnixSock {
                op: super::USOCK_PAIR,
                handle: 0,
                len: 0,
            }),
            "PAIR：长度参数无语义域收录"
        );
        // BIND/CONNECT：名字长域闸（1..=108）
        for op in [super::USOCK_BIND, super::USOCK_CONNECT] {
            assert_eq!(
                super::parse(r(super::SYS_UNIXSOCK, [op, 0, 0x3000, 9, 0])),
                Ok(super::Syscall::UnixSock {
                    op,
                    handle: 0,
                    len: 9,
                }),
                "op={op}：名字长域内收录（wayland-0 = 9 字节）"
            );
            assert_eq!(
                super::parse(r(super::SYS_UNIXSOCK, [op, 0, 0x3000, 0, 0])),
                Err(super::AbiError::BadArgs),
                "op={op}：名字长 0 拒收"
            );
            assert_eq!(
                super::parse(r(super::SYS_UNIXSOCK, [op, 0, 0x3000, 109, 0])),
                Err(super::AbiError::BadArgs),
                "op={op}：名字长 > sun_path(108) 拒收"
            );
            assert_eq!(
                super::parse(r(super::SYS_UNIXSOCK, [op, 0, 0x3000, 108, 0])),
                Ok(super::Syscall::UnixSock {
                    op,
                    handle: 0,
                    len: 108,
                }),
                "op={op}：名字长 = sun_path 上界收录"
            );
        }
        // ACCEPT：句柄透传 + 长度无语义
        assert_eq!(
            super::parse(r(super::SYS_UNIXSOCK, [super::USOCK_ACCEPT, 5, 0, 0, 0])),
            Ok(super::Syscall::UnixSock {
                op: super::USOCK_ACCEPT,
                handle: 5,
                len: 0,
            }),
            "ACCEPT：句柄透传"
        );
        // ACCEPT_B(6)/SHUT(7)：M42-COMP4 扩容面——句柄透传 + 长度无语义
        for op in [super::USOCK_ACCEPT_B, super::USOCK_SHUT] {
            assert_eq!(
                super::parse(r(super::SYS_UNIXSOCK, [op, 5, 0, 0, 0])),
                Ok(super::Syscall::UnixSock {
                    op,
                    handle: 5,
                    len: 0,
                }),
                "op={op}：M42-COMP4 扩容臂收录"
            );
        }
        // SEND/RECV：载荷/缓冲长域闸（1..=64 KiB）
        for op in [super::USOCK_SEND, super::USOCK_RECV] {
            assert_eq!(
                super::parse(r(super::SYS_UNIXSOCK, [op, 3, 0x2000, 64, 0])),
                Ok(super::Syscall::UnixSock {
                    op,
                    handle: 3,
                    len: 64,
                }),
                "op={op}：载荷长域内收录"
            );
            assert_eq!(
                super::parse(r(super::SYS_UNIXSOCK, [op, 3, 0x2000, 0, 0])),
                Err(super::AbiError::BadArgs),
                "op={op}：载荷长 0 拒收"
            );
            assert_eq!(
                super::parse(r(super::SYS_UNIXSOCK, [op, 3, 0x2000, 0x1_0001, 0])),
                Err(super::AbiError::BadArgs),
                "op={op}：载荷长 > 64 KiB 拒收"
            );
        }
        // op 越域拒收（10 起——8/9 自 M42-ELF5 起为 SEND_FD/RECV_FD 收录域）
        assert_eq!(
            super::parse(r(super::SYS_UNIXSOCK, [10, 0, 0, 0, 0])),
            Err(super::AbiError::BadArgs),
            "op 10 越域拒收"
        );
        // SEND_FD(8)/RECV_FD(9)：M42-ELF5 fd 附带数据传递域——句柄透传
        // + 长度无语义（ptr 域承载待传递句柄值，慢路径语义）
        for op in [super::USOCK_SEND_FD, super::USOCK_RECV_FD] {
            assert_eq!(
                super::parse(r(super::SYS_UNIXSOCK, [op, 5, 7, 0, 0])),
                Ok(super::Syscall::UnixSock {
                    op,
                    handle: 5,
                    len: 0,
                }),
                "op={op}：M42-ELF5 fd 传递臂收录（len 无语义域）"
            );
        }
        assert_eq!(
            super::parse(r(super::SYS_UNIXSOCK, [u64::MAX, 0, 0, 0, 0])),
            Err(super::AbiError::BadArgs),
            "op u64::MAX 越域拒收"
        );
        // 词法闸对账：可打印域 + 上界 + 空域
        assert!(super::usock_name_ok(b"wayland-0"), "标准套接字名放行");
        assert!(super::usock_name_ok(&[b'a'; 108]), "sun_path 上界放行");
        assert!(!super::usock_name_ok(&[b'a'; 109]), "越上界拒收");
        assert!(!super::usock_name_ok(b""), "空名拒收");
        assert!(!super::usock_name_ok(b"has space"), "空格域拒收");
        assert!(
            super::usock_name_ok(b"/run/wayland-0"),
            "斜杠词法域放行（平名命名域 v0 无路径解析）"
        );
    }

    /// SYS_SHM(43) parse 域（v0.22，M42-ELF5）：CREATE 尺寸域闸 +
    /// MAP 句柄/虚地址域闸 + op 越域拒收（wl_shm 池域结构面）。
    #[test]
    fn parse_shm_ops() {
        let r = |num: u64, args: [u64; 5]| super::SyscallRegs { num, args };
        // CREATE：尺寸域闸（1..=2 MiB）
        assert_eq!(
            super::parse(r(super::SYS_SHM, [super::SHM_CREATE, 0x3E800, 0, 0, 0])),
            Ok(super::Syscall::Shm {
                op: super::SHM_CREATE,
                a: 0x3E800,
                b: 0,
            }),
            "CREATE：尺寸域内收录（320×200×4）"
        );
        assert_eq!(
            super::parse(r(super::SYS_SHM, [super::SHM_CREATE, 0, 0, 0, 0])),
            Err(super::AbiError::BadArgs),
            "CREATE：尺寸 0 拒收"
        );
        assert_eq!(
            super::parse(r(
                super::SYS_SHM,
                [super::SHM_CREATE, super::SHM_SIZE_MAX + 1, 0, 0, 0]
            )),
            Err(super::AbiError::BadArgs),
            "CREATE：尺寸 > 2 MiB 拒收"
        );
        // MAP：句柄 + 虚地址域闸（页对齐 + SHM 窗内）
        assert_eq!(
            super::parse(r(
                super::SYS_SHM,
                [super::SHM_MAP, 3, super::SHM_VA_BASE, 0, 0]
            )),
            Ok(super::Syscall::Shm {
                op: super::SHM_MAP,
                a: 3,
                b: super::SHM_VA_BASE,
            }),
            "MAP：窗基址收录"
        );
        assert_eq!(
            super::parse(r(
                super::SYS_SHM,
                [super::SHM_MAP, 0, super::SHM_VA_BASE, 0, 0]
            )),
            Err(super::AbiError::BadArgs),
            "MAP：句柄 0 拒收"
        );
        assert_eq!(
            super::parse(r(
                super::SYS_SHM,
                [super::SHM_MAP, 3, super::SHM_VA_BASE + 0x800, 0, 0]
            )),
            Err(super::AbiError::BadArgs),
            "MAP：非页对齐拒收"
        );
        assert_eq!(
            super::parse(r(
                super::SYS_SHM,
                [super::SHM_MAP, 3, super::FB_VA_BASE, 0, 0]
            )),
            Err(super::AbiError::BadArgs),
            "MAP：域外（LFB 窗）拒收"
        );
        assert_eq!(
            super::parse(r(
                super::SYS_SHM,
                [super::SHM_MAP, 3, super::SHM_VA_LIMIT, 0, 0]
            )),
            Err(super::AbiError::BadArgs),
            "MAP：窗上界拒收（半开区间）"
        );
        // op 越域拒收（2 起——0/1 为 CREATE/MAP 收录域）
        assert_eq!(
            super::parse(r(super::SYS_SHM, [2, 0, 0, 0, 0])),
            Err(super::AbiError::BadArgs),
            "op 2 越域拒收"
        );
        assert_eq!(
            super::parse(r(super::SYS_SHM + 1, [0; 5])),
            Err(super::AbiError::UnknownSyscall),
            "号域 44 未注册拒收（编号冻结只增不改域探针）"
        );
    }
}
