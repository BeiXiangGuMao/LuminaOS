# busybox 覆盖度成像表（M34-B2 落库；M35-BBb 扩记）

> 口径（M34-计划 裁决注③）：busybox 覆盖度 = 转换层次批（conduit::translate 收录面）+ applet 批次实证双面推进；**全功能口径不虚报**——本表只登记已实证 applet 与其 syscall 消费面，未实证项如实挂账。介质基线：Alpine v3.19 `busybox-static 1.36.1-r21`（musl 1.36.1 静态，SJTU 镜像可覆写，`scripts/busybox-fetch.sh` 固化获取）。

## 一、已实证 applet × syscall 消费矩阵

| applet | 相位 | argv 面 | exit 码 | musl 启动链（每 applet 公共） | applet 专属 syscall 消费 |
|---|---|---|---|---|---|
| echo | t82（M33-T1） | `busybox echo LUMINA-T82-OK` | 0 | arch_prctl(158) TLS + set_tid_address(218) 桩 + brk(12) + mmap(9) 匿名 + rt_sigaction/procmask(13/14) 桩 + uname(63) + ioctl(16)→ENOTTY | writev(20)（stdout 行缓冲聚发） |
| true | t83（M34-B2） | `busybox true` | 0 | 同上 | exit_group(231)（零 I/O 路径——分发面最小活体） |
| false | t83（M34-B2） | `busybox false` | 1 | 同上 | exit_group(231)（退出码语义 1 对账） |
| printf | t83（M34-B2） | `busybox printf LUMINA-T83-PF\n` | 0 | 同上 | writev(20)（格式串无 % 直发路径） |
| wc -l | t83（M34-B2） | `busybox wc -l /bin/busybox` | 0 | 同上 | openat(257) + fstatat64(262)/fstat(5) + read(0) 循环 + close(3) + writev(20)（行计数输出） |
| yes | t85（M35-BBb） | `busybox yes`（A 段——stdout 接线写端） | 1（写错终结三路同值：writev 截断续写 EFAULT→F_ERR die 实证主路径 + EPIPE / 满环 EAGAIN 容差；SIGPIPE 递送面挂账） | 同上 | writev(20) 部分成功语义（BBb 新对齐——musl puts 溢出域双 iov 实录）+ 句柄 1 管道域真对象重定向（BBa 64 KiB 环消费面）+ exit_group(231) |
| head -n | t85（M35-BBb） | `busybox head -n 3`（B 段——stdin 接线读端） | 0 | 同上 | read(0)（句柄 0 管道域真对象重定向——BBb stdio 分流面）+ writev(20)（fd 1 控制台直通取证 3 行）+ exit_group(231) |
| ls -1 | t92（M39-BBLS） | `busybox ls -1 /t92d`（乱序制备域 12 条目——ZZZ 首建反相） | 0 | 同上 | openat(257) 目录域 + getdents64(217) 目录读 + 排序分配域（musl qsort→malloc/mmap 增长——12 条目域编制）+ writev(20) 排序输出（串口取证 pos(AAA)<pos(ZZZ)——制备反相对账，xtask 双面板位置序断言）+ exit_group(231)。**stdio 保留域根治随行**：本 applet 首拍揭形「先开后写」stdout 互踩缺口（opendir 拾 fd 1 → writev(1) 写目录 EBADF raw=0x9——lin_abi 任务 open 槽搜索自 3 起根治；t83 wc 计数行同伤回溯在案） |
| readlink | t92（M39-BBLS） | `busybox readlink /t92d/f01-t92`（非链接域负相） + `busybox readlink -f /t92d`（realpath 链恒等） | 1（非链接域 EINVAL → applet 败码）/ 0（musl realpath 首步 readlink(path) 非链接 EINVAL → lstat 环 → 恒等路径返回；**号域勘误揭雷随行：M39-计划 笔① 登记 readlink(90) 误记——x86_64 号域 readlink=89（90=chmod），首拍 LIN-DISPATCH-ERR num=89 errno=38 实录，90→89 随本笔改正后 -f 转正**） | 同上 | readlink(89)（M39-BBLS 收录——v0 无 symlink 实体语义落点：存在域 ENOENT/EFAULT 解析面显形 + 已存在非链接域 EINVAL fail-visible）+ exit_group(231) |

**对账锚**：t82/t83 相位全链 = ELF64 直载（bedrock::elf，PD[2] 槽域原生基址）→ Linux 初始栈（AT_ 哨兵集）→ fork 桩同族定点进入 ring3（lin_abi 随链）→ musl 初始化 → applet 分发（busybox 多合一 argv[1] 路由）→ 专属消费 → exit_group → waitpid 收割（exit 码逐 applet 对账：0/1/0/0）。

**t85 流水线对账锚（M35-BBb）**：`\|` 解析（conduit::sh 首割）→ pipe2(293)（编排端句柄域）→ 两段无继承接线派生（spawn_stage_wired：A 段句柄 1←写端 + B 段句柄 0←读端——fork 锁窗铸槽 = dup2 等价面）→ 预流灌注（A 段首刷有界自旋实证）→ 编排端双端关闭（段域单源引用）→ head exit 0 / yes exit 1 双收割对账——`yes \| head -n 3` 两段真流串联在环（musl writev/read 全链经 vfs 管道域）。**M36-BB3a 注**：编排端 pipe2 显式定格 O_NONBLOCK(0o4000)——缺省阻塞语义（Linux 对齐）落位后 yes EAGAIN 容差动力学字节级保持。

## 二、translate 收录面（承载上表；M35-BBa 后 29 目）

三档分层：直通 5（read/write/close/lseek/getpid）+ 适配 19（openat/writev/fstat/wait4/brk/mmap_anon/uname/getcwd/clock_gettime/getdents64/dup2/fcntl/exit/fork/execve/arch_prctl/chdir/newfstatat/unlinkat/faccessat/**pipe2**）+ 合成桩 2（rt_sigaction/rt_sigprocmask/set_tid_address 计 3 号）+ 显形拒绝（ioctl→ENOTTY、其余号→ENOSYS 不虚报）。

| 批次 | 收录号 | 承接笔 |
|---|---|---|
| 首批（M33-L1/P1/F1/T1） | 0/1/3/5/8/9/12/13/14/16/20/33/39/57/59/60/61/63/72/79/158/217/218/228/231/257 | M33 九笔 |
| 次批（M34-B1） | 80 chdir / 262 newfstatat / 263 unlinkat / 269 faccessat | M34-B1 |
| 三批（M35-BBa） | 293 pipe2（64 KiB 定容环 + EOF/EPIPE + CLOEXEC 面） | M35-BBa |

## 三、挂账面（不虚报）

| 挂账项 | 依赖缺口 | 批次归属 |
|---|---|---|
| ~~cat / ls 全谱 applet 扩容~~（**ls 深链已实证——M39-BBLS 摘牌**：t92 乱序制备域 → `busybox ls -1` 派生消费 → 排序输出串口取证 + readlink(90) 收录双相位）；**cat 全谱 applet 续挂**（sendfile(40) 消费面已在库 M36-BB3b；applet 文件域制备/派生面 t87 (e) 制备链先例已证——cat 实证随续作批次） | ~~消费面收录扩容在库~~（M36-BB3b 收录 stat(4)/lstat(6)/sendfile(40)/statx(332) + fd_stat_mode_size lseek-END 尺寸权威根治 + M39-BBLS readlink(90)） | 续作批次裁决（cat） |
| ~~sh / 管道族（`yes \| head`）~~（**sh 流水线首割已实证——M35-BBb：`\|` 解析 + fork 锁窗接线铸槽（dup2 等价）+ pipe2 + 两段真流串联**；真 busybox sh ash 全量启动面——getuid 族未收录/信号面/阻塞 read——ash 启动面挂账 BB3b；getuid 族 = M34-B2 合成桩已收（真身份面随多用户纵深）） | ash 启动面符号扩容 + SIGPIPE 递送 + ~~阻塞式管道 I/O~~（**M36-BB3a 已落**：O_NONBLOCK(0o4000) 收录 + 缺省 Linux 同款阻塞语义——WaitWhat::PipeRead/PipeWrite 等待队列 + 死亡唤醒双链；阻塞语义活体 **t87 已实证——M36-BB3b 摘牌**（四相位电化学全绿 + 探针极性根治）） | sh 批次三 |
| mkdir / rm / cd 族 | mkdir(83)/unlinkat(263) 已备/AT_REMOVEDIR 已收；rmdir 语义随 mkdir 批次 | 同上 |
| 阻塞式 tty read | v0 tty 游标非阻塞口径（read 返回 0 = 暂无数据） | 调度协作面批次 |

> 复评机制：本表随 applet 批次推进续记（M34-B2 首版成像；M35-BBb 扩记——yes/head 两行 + pipe2 三批 + sh 首割摘牌注；M36-BB3a 扩记——阻塞式管道 I/O 等待队列落位 + O_NONBLOCK 收录；**M36-BB3b 扩记——阻塞语义活体 t87 摘牌**（四相位电化学全绿 + BB3a 探针极性根治 + stat/lstat/sendfile/statx 消费驱动收录四目 + fd_stat_mode_size 尺寸权威根治）；**M39-BBLS 扩记——ls 深链/readlink 双行摘牌**（t92 乱序制备→排序输出串口取证 + readlink(90) 收录双相位））；行数增长即覆盖度证据链，未达全功能口径前 METRICS 行保持「扩容中」定性。
