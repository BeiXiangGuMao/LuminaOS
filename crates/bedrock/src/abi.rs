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
/// 错误域 = Linux 5.15 errno（Conduit 口径，见 [`crate::vfs::FsError::errno`]）。
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
/// 内核侧新建 [`crate::vfs::RamFs`] 内存文件系统；结构校验）。
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

/// 系统调用 ABI 版本（v0.14 = M23-S1：新增 SYS_FB_MAP(35)/SYS_FB_SYNC(36)
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
pub const ABI_VERSION: (u16, u16) = (0, 14);

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
}

/// 从寄存器快照解析调用意图。只做结构校验，不做内存访问（由慢路径完成）。
pub fn parse(regs: SyscallRegs) -> Result<Syscall, AbiError> {
    let [a0, a1, a2, a3, _] = regs.args;
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
        _ => Err(AbiError::UnknownSyscall),
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
        assert_eq!(super::ABI_VERSION, (0, 14));
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
        let r = |num: u64, args: [u64; 5]| SyscallRegs { num, args };
        // FB_MAP：va 域结构校验（FB_VA_BASE 起、页对齐；域外/不对齐 BadArgs）
        assert_eq!(
            super::parse(r(super::SYS_FB_MAP, [0, super::FB_VA_BASE, 0, 0, 0])),
            Ok(Syscall::FbMap { va: super::FB_VA_BASE }),
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
