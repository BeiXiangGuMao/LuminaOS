# LuminaOS M45 关账存档与恢复底稿（沙箱回收事故定界）

> 本稿为仓库原生格式的对账底稿。源码树与远端地址恢复后，本稿随 docs/ 对账批次入库回填；
> 全部事实取自存活证据（lumina-build/ 报文与报告、构建产物、取证快照），零推测零虚报。

## 〇、结论速览

| 事项 | 状态 | 证据 |
| --- | --- | --- |
| M45-BIT245（笔㊿ / t144）真机窗口 bit24=1 CPUID 逐位对账开工 | 已关账 | msg-t144.txt；自检 143→144 |
| M45-MPMC46（笔51 / t145）MPMC 环替换 SpinLock 落域 | 已关账 | msg-t145.txt；自检 144→145 |
| M45-RECON47（笔52 / t146）bit24=1 实测对账执行面 | 已关账 | msg-t146.txt；自检 145→146 |
| 门禁 CI 11 阶段 + 冒烟 146/146 | 全绿 | ci-summary-epoch-1794891709.md 10/10 PASS（2026-11-17 13:01 CST）；boot-smoke.log：SELFTEST-PASS 146/146 + BOOT-OK + CENSUS n146 p146 f0 |
| harbor 动态链接族开工（t147 / 笔53） | 未开工 | 笔52 挂账明载「笔53 承接」；仓库本体丢失阻断 |
| M45 收尾关账定版 | 未开工 | 定版需仓库本体（版本号预定 v0.37.0，以仓库 tag 序列恢复后核对为准） |

## 一、事故定界（2026-11-17）

时间线（CST）：笔㊿ 11-16 22:46 → 笔51 23:18 → 笔52 11-17 13:02 → 门禁收绿 13:01 →
沙箱回收（约 13:02 后）→ 本会话 17:13 起清点。

- **损失**：`/home/z/my-project/lumina-os` 源码树（16+ crates：kernel/ostd/crystal/bedrock/conduit/weave/meridian/loom/cascade/aurora/quill/pulse/prism/glyph/vanguard/morse/mirror + xtask/ash/waycomp/harbor 面）与全部 git 历史本地副本；远端 URL 与访问凭据（实证远端为 GitHub——M41 关账载 GitHub Release id=438085811 四资产 + ls-remote 回环、M42 载 origin 分支双清；仓库名与凭据在存活产物中零痕迹，不可猜测不可伪造）。
- **存活**：rustup stable 1.99.0 + rsproxy（`my-project/.cargo`、`.rustup` 完整可用，cargo/rustc 实测通过）；15 本官方细则 PDF（含 Harbor 港湾开发细则 v1.0.0——t147 权威依据）；内核构建产物 lumina-kernel.bin（release，11-16 22:43）；QEMU runtime 与 busybox 1.36.1-r21 介质；三笔关账报文全文；docs 取证快照（ROADMAP M41/M42/M43 行、PDF-RECON H-P03 行、MATURITY v6 6.9）。
- **随沙箱丢失待重装**：QEMU 10.0.13 apt 闭包（恢复脚本第 3 步自动补装）。

## 二、已关账三笔实录摘录（全文见 lumina-build/msg-t144/145/146.txt）

- **笔㊿ T144**：SDM Vol.2 Table 3-8 LEAF1 ECX 32 目权威位义表 + leaf1_ecx_bitmap 逐位判读语义核 + **bit24 = tsc-deadline 主位**；实录 `LUMINA-T144-BITS ecx=0x80002001 bitmap=…0001 pop=3 named=2`（QEMU TCG 记录式锚）；挂账「真机窗口 bit24=1 实测对账（判据面在环——真硬件窗口实测挂账远线不变）」。
- **笔51 T145**：ostd::sync::mpmc::MpmcRing（Vyukov 有界 MPMC，seq 三态发布契约 + 64B 缓存行填充）落域；waycomp KEY_Q/PTR_Q/AXIS_Q 三环换装 + IN_MU 退役 + ISR 退避域退役；实录三源 20 事件零锁直推零丢失零重复 `LUMINA-T145-MPMC total=20 ptrs=+20 mps=+20 guard=+0`；自检 145/145。
- **笔52 T146**：ReconWindow 二态枚举（RealMachine 真机窗 / Recorded 记录式锚窗）+ recon_window_of 判定核三源一致 + RECON_SEGMENTS 四段计划面（真机窗全谱装载 / 锚窗逐段零执行零宣称）+ MSR 0x6E0 路由复证 `lvt=0x20043 arm=ok ticks=+1 masked 读回 0x30043`；实录 `LUMINA-T146-WINDOW window=recorded bit24=false src3=true`；自检 146/146；挂账「**harbor 动态链接族开工（笔53 承接）**」。

## 三、M45 余下路线（仓库恢复后即刻执行）

1. **t147 / 笔53 harbor 动态链接族开工**：权威依据 = Harbor 港湾开发细则 v1.0.0 + PDF-RECON H-P03「动态链接启动 ≤ 3 ms（P2）——ld-lumina.so 动态链接器未落（用户态链接面成形前置——M39-HBI 落 C ABI 指针/链接层为前置步）」。按族分解：ELF 解析 + DT_NEEDED 装载序 → 符号解析与插桩序 → 重定位家族（RELATIVE/GLOB_DAT/JUMP_SLOT/COPY）→ 惰性绑定 PLT/GOT → dlopen/dlsym/dlclose/dlerror 族 → .init_array/.fini_array 与 TLS 初始化序；本批至少打通最小可运行族，其余立桩不欠账；三面同步（SELFTEST 146→147 + 双面板标记 + ABI 版本核对）+ 门禁 11 阶段 + 冒烟 147/147。
2. **M45 收尾关账定版**：笔54 收尾对账（ROADMAP §三 M45 行收官 + §四台账收口 + METRICS P5 + MATURITY 复评注 + README 对账）→ 版本定版（预定 v0.37.0 八步：CHANGELOG / tag / 双 tar / SHA256SUMS / Release 资产 / ls-remote 回环，以仓库既有定版脚本先例为准）。

## 四、恢复操作单

```bash
# 远端 URL 到手后一条命令复工（工具链已就绪，QEMU 自动补装，克隆后自动跑门禁）
bash /home/z/my-project/scripts/lumina-restore.sh <远端URL>
```

锚点核对项：既往实录 main=dbf1e02、v0.36.0=70ae249；克隆后若锚点不在本地历史，以远端 main 为准（远端可能已前进至笔52 实施提交）。

## 五、复工执行结果（2026-11-17 终态——第二轮复工闭环）

> 本稿随 docs/ 对账批次入库回填（docs/RECOVERY-M45.md 同文）。历史注：本稿
> §五 曾记第一轮复工闭环（复刻批 f72f338 / harbor 0188989 / tag 3a25ceb /
> 脚本 84d4056——本地领先远端 4 提交 + tag，凭据墙挂账）；该本地树随沙箱
> 再次回收丢失（两轮同型事故如实登记），**第二轮复工**于凭据到手当日闭环：

- **笔52 复刻**：t146 依关账报文忠实复刻，门禁 CI-OK 11 阶段全绿、冒烟
  146/146，实录与丢失批账面逐字对齐——提交 415d3ac；随行揭雷收口一域：
  退出码通知域早现中间态（t95 零锁轮询撞窗七连实录——通知随 Zombie+
  SWITCHING 锁窗同窗落账收口，空载双核确定性翻绿）；
- **笔53 harbor 动态链接族开工**：harbor::ld 语义核判读族（H-P03 四段预算/
  GNU 哈希/查找序/重定位/TLS）宿主 12 例全绿 57→69——提交 65af6d4；
- **笔54 收尾定版**：ROADMAP M43/M44/M45 三行关账 + METRICS/MATURITY v7
  7.0/README/CHANGELOG 对账 + **tag v0.37.0**（d6a76a0）+ 定版打包（双 tar +
  SHA256SUMS）+ 定版脚本搭车件入库（release-pack/create-v0370.sh）+ 本稿
  docs/RECOVERY-M45.md 回填；
- **远端闭环**：git push origin main v0.37.0 + GitHub Release 四资产上传
  （release-create-v0370.sh——GH_TOKEN 由用户供给）+ ls-remote 回环（详见
  本稿末轮实录；凭据不落盘纪律全程维持——token 仅入 git/上传通道瞬时
  通道，零文件零日志落盘）。

## 六、第二轮复工凭据墙收口（2026-11-17）

用户供给远端 URL + GitHub PAT 后闭环全链：克隆（锚点核对 main=46cdee5 止于
笔51，tags 至 v0.36.0=70ae249——与 §四 锚点核对项对齐）→ 工具链重建（rustup
1.99.0 钉版 + rsproxy + x86_64-unknown-none std 补装）→ QEMU 10.0.13 用户态
解包运行时复原（TUNA 闭包 + ldd 零缺库——runtime/qemu-root/extracted 契约
前缀）→ busybox 1.36.1-r21 介质复原 → 门禁全谱复绿（415d3ac / 65af6d4 /
d6a76a0 三提交各随 CI-OK 11 阶段）→ push + Release 四资产 + ls-remote 回环。
