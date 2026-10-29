# busybox 覆盖度成像表（M34-B2 落库）

> 口径（M34-计划 裁决注③）：busybox 覆盖度 = 转换层次批（conduit::translate 收录面）+ applet 批次实证双面推进；**全功能口径不虚报**——本表只登记已实证 applet 与其 syscall 消费面，未实证项如实挂账。介质基线：Alpine v3.19 `busybox-static 1.36.1-r21`（musl 1.36.1 静态，SJTU 镜像可覆写，`scripts/busybox-fetch.sh` 固化获取）。

## 一、已实证 applet × syscall 消费矩阵

| applet | 相位 | argv 面 | exit 码 | musl 启动链（每 applet 公共） | applet 专属 syscall 消费 |
|---|---|---|---|---|---|
| echo | t82（M33-T1） | `busybox echo LUMINA-T82-OK` | 0 | arch_prctl(158) TLS + set_tid_address(218) 桩 + brk(12) + mmap(9) 匿名 + rt_sigaction/procmask(13/14) 桩 + uname(63) + ioctl(16)→ENOTTY | writev(20)（stdout 行缓冲聚发） |
| true | t83（M34-B2） | `busybox true` | 0 | 同上 | exit_group(231)（零 I/O 路径——分发面最小活体） |
| false | t83（M34-B2） | `busybox false` | 1 | 同上 | exit_group(231)（退出码语义 1 对账） |
| printf | t83（M34-B2） | `busybox printf LUMINA-T83-PF\n` | 0 | 同上 | writev(20)（格式串无 % 直发路径） |
| wc -l | t83（M34-B2） | `busybox wc -l /bin/busybox` | 0 | 同上 | openat(257) + fstatat64(262)/fstat(5) + read(0) 循环 + close(3) + writev(20)（行计数输出） |

**对账锚**：t82/t83 相位全链 = ELF64 直载（bedrock::elf，PD[2] 槽域原生基址）→ Linux 初始栈（AT_ 哨兵集）→ fork 桩同族定点进入 ring3（lin_abi 随链）→ musl 初始化 → applet 分发（busybox 多合一 argv[1] 路由）→ 专属消费 → exit_group → waitpid 收割（exit 码逐 applet 对账：0/1/0/0）。

## 二、translate 收录面（承载上表；M34-B1 后 28 目）

三档分层：直通 5（read/write/close/lseek/getpid）+ 适配 18（openat/writev/fstat/wait4/brk/mmap_anon/uname/getcwd/clock_gettime/getdents64/dup2/fcntl/exit/fork/execve/arch_prctl/**chdir/newfstatat/unlinkat/faccessat**）+ 合成桩 2（rt_sigaction/rt_sigprocmask/set_tid_address 计 3 号）+ 显形拒绝（ioctl→ENOTTY、其余号→ENOSYS 不虚报）。

| 批次 | 收录号 | 承接笔 |
|---|---|---|
| 首批（M33-L1/P1/F1/T1） | 0/1/3/5/8/9/12/13/14/16/20/33/39/57/59/60/61/63/72/79/158/217/218/228/231/257 | M33 九笔 |
| 次批（M34-B1） | 80 chdir / 262 newfstatat / 263 unlinkat / 269 faccessat | M34-B1 |

## 三、挂账面（不虚报）

| 挂账项 | 依赖缺口 | 批次归属 |
|---|---|---|
| yes / head / cat / ls 全谱 applet 扩容 | 非阻塞 read 面 + getdents64 已备（ls 就绪度高）；批量随批次三 | M35+ 裁决 |
| sh / 管道族（`yes \| head`） | **pipe2(293) + fork 句柄表跨 fork 复制**（fork 子代 handles 全零实录——fd 继承先行，单收 pipe2 无消费方） | 同批收录（sh 批次） |
| mkdir / rm / cd 族 | mkdir(83)/unlinkat(263) 已备/AT_REMOVEDIR 已收；rmdir 语义随 mkdir 批次 | 同上 |
| 阻塞式 tty read | v0 tty 游标非阻塞口径（read 返回 0 = 暂无数据） | 调度协作面批次 |

> 复评机制：本表随 applet 批次推进续记（M34-B2 首版成像）；行数增长即覆盖度证据链，未达全功能口径前 METRICS 行保持「扩容中」定性。
