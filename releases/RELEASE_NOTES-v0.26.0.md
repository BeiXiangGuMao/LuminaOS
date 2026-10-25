# Lumina OS v0.26.0 发布说明（M29–M31 三季连发——Harbor libc + Weave 对象库 + 桌面骨架 + 自举预备）

**发布日期**：2026-10-25　|　**标签**：`v0.26.0`
**定位**：工作区里程碑第 26 版定版——三个里程碑（M29 五笔 / M30 七笔 /
M31 六笔）+ M32 计划笔共 18 笔单件事提交连续落账。三条主线：**libc 与
对象库**（ADR-0003 分配器归位 + H-P01 首批 57 符号 + Weave 内容寻址对象
库 + WE-P02 断电注入四相矩阵）；**桌面骨架**（Loom Elm 架构 + Cascade
shell 语义四面 + Glyph 同源渲染 + t79 活体）；**自举预备**（驱动旁路台账
首版成像 + morse 外移首割 + V-P05 注入矩阵 + Weave 自举装载面 + t80
活体）。裸机自检 78 → **80** 项（t79/t80 续编）。

## 0. 里程碑总览（M29 → M31）

| 里程碑 | 主题 | 验收锚结果 |
|---|---|---|
| M29 | Harbor libc 首版 + Weave 对象库 | ADR-0003 执行步分配器归 ostd::heap；H-P01 首批 57 符号 forbid unsafe；WE-P02 四相断电注入框架；恢复语义裁决（报库态不报命运）；冒烟 78/78 |
| M30 | 桌面骨架 | LO-P01 Elm 架构面；CA-P05 shell 语义四面；glyph 同源渲染本体；t79 活体 79/79 首跑即绿 + pcap 取证搭车件 |
| M31 | 自举预备 | 驱动旁路台账首版成像；morse 外移首割在环；V-P05 注入矩阵首批；Weave 自举装载面机器可验；t80 活体 80/80 |

## 1. M29 Harbor libc 首版 + Weave 对象库

- **ADR-0003 执行步**：kernel 内嵌堆分配器迁 `ostd::heap`（Bump +
  free-list 双阶，冒烟 heap 行实录）；harbor 重铸为 libc 符号面身份——
  **H-P01 首批 57 符号**（errno/string/ctype/stdlib 垂直切片，
  `forbid(unsafe_code)` 全 crate）+ allowlist 政策边销账三项（19→17）。
- **Weave store 内容寻址对象库**：ObjectId = FNV-1a 64（空串/foobar 经典
  向量锚定）+ put 去重（同内容同身份）+ 定容 CAP 槽存满拒收 fail-visible
  + get/has/verify 重哈希校验（位翻转检出 `VerifyError{id,actual}`，不在
  库 None 与在库损坏区分）+ cfg(test) 损伤后门如实登记。
- **WE-P02 断电注入框架**（journal）：GenRoot 双代际根槽 {gen,hash,CRC32}
  轮换 + 提交点 = 活跃指针翻转 + PowerFault 四相注入矩阵（AfterPrepare /
  MidRootWrite 撕裂残槽 / BeforeFlip / AfterFlip）+ CRC32 IEEE 802.3
  向量锚定（0xCBF43926 / 0x414FA339）+ 崩溃重试代龄严格递增 + 连续撕裂
  不累积。
- **恢复语义裁决**：Recovery 报库态不报事务命运——AfterPrepare 掉电后
  库态与正常态不可区分，RolledBack 伪变体删除，事务命运归策略面
  Transaction；回放不重验陷阱对位（逐节点重验入 WAL 语义）。

## 2. M30 桌面骨架（Loom / Cascade / Glyph，t79）

- **Loom Elm 架构**（LO-P01 口径挂接）：App 三件套消息折叠环
  （Model/Msg/update/view 单向数据流，同序列确定性折叠可重放）+ ViewBuf
  定容零堆平面元素树（first_child/next_sibling/parent 三索引链 + NIL
  哨兵 + 自顶向下建树结构性防环 + Full/Reparent/DoubleRoot 全闸
  fail-visible）+ 约束求解布局（8px 网格闸 OffGrid + Overflow 溢出闸 +
  Fill 余数归首子确定性分配 + 子链三遍走零堆）+ 虚拟化列表可见窗纯函数；
  布局产出 `mirror::Rect` 几何单一事实源延伸。
- **Cascade shell 语义四面**（CA-P05 结构面）：四态机非法迁移拒收 +
  `Workspaces` 定容工作区表（窗口全局唯一归属，跨区重复打开
  AlreadyOpen）+ `tiling_plan` master-stack 平铺计划（保留域消费 loom
  PANEL/DOCK/GRID 常量，产出 `mirror::Rect` 供 `prism::Stack` 直接消费）
  + Dock 定容登记面（glyph 档位闸 IllegalIcon/DuplicateApp/DockFull）；
  no_std+alloc 转换（crystal/mirror 先例）。
- **Glyph 渲染库本体**：IconDef 静态注册表（24 源网格几何基元
  Line/Rect/Circle 声明式图标 v0 四枚）+ 同源缩放光栅化器（基元坐标只能
  经 `map_point` 变换到目标画布——ADR-0007 勘误后合规模型的工程面兑现）
  + 描边宽度随档位倍率 + Bresenham 线段/中点圆八分对称 + 越界静默裁剪。
- **t79 desktop-skel 活体**：六闸相位——shell 语义面 / 平铺 golden
  （1920×1080 保留域拆分）/ Elm 布局同源对账（loom 内容域 == cascade
  content，两套面同一几何）/ 图标像素 / prism 双窗 z 序仲裁 / fb 交盒
  上屏（盒内三点等值 + 盒外哨兵零触碰 + 二拍空账）；自检 78 → 79。
- 搭车件 M30-X1：pcap 滤波升级取证（filter-dump 全账捕获 + 分阶取证分析
  器入库）——t73 设备级 RX 选择性死亡第三形态登记（netdev 75 帧 vs
  guest 10 帧，ICMP reply 4→1，guest miss/short 双闸完好）。

## 3. M31 自举预备（驱动旁路 + morse + V-P05 + Weave 自举，t80）

- **驱动旁路台账首版成像**：kernel 内驱动面五清点（vnet 1,743 / fb 953 /
  kbd 250 / console 212 / block 134）+ 策略面两区分（tty 行规程 / shell
  交互分派）+ 分类三分与缩编路径分级（电气面待用户态驱动基础设施分批 /
  纯函数面 crate 化外移先行 / 策略面随服务化批次）——每里程碑核销，
  缩编进度入 METRICS P5 旁路行。
- **morse 首割外移**：kbd scancode 集 1 翻译面 crate 化（translate /
  shift_event / is_release 纯函数，零依赖 forbid unsafe）+ 宿主测试全谱
  7 例（数字行/控制面/符号行/QWERTY 三行/非映射键/Shift 矩阵/释放码）+
  match 体机械对账逐字节零漂移 + `kernel::kbd` 消费面切换（电气面零
  改动）；allowlist 政策面 24→25。
- **V-P05 首批注入矩阵**：vanguard 能力面四相×不变式（越权派生全枚举
  拒收 + 零副作用不变式 / 撤销后使用死槽显形 / 未安装槽两级错误语义 /
  重复撤销）+ derive 链传播语义全枚举（三级合法链 + 链上回升拒 + 环满
  容量不变式 + 释放复用）；宿主 3→5 例，库本体零改动实现零缺陷显形。
- **Weave 自举装载面**：`boot::bootstrap` 幂等库态序列封装（gen1 基线
  恢复装载 + 三不变式四相复演〔活跃指针胜出/回滚不残留/撕裂残槽显形
  丢弃〕+ store 根装载同源对账 ROOT_MANIFEST）+ BootReport 结构化报告 +
  kernel 启动序列挂接（heap ready 后，装载失败 fail-visible 不进自检）
  + `LUMINA-WEAVE-BOOT` 证据行（xtask S8 必检行 5→6 机器可验）；宿主
  18→21 例。
- **t80 bootprep 活体**：三面贯通——V-P05 注入矩阵结论内核态收口 +
  Weave bootstrap 幂等复跑活体收编 + morse 翻译面活体对账（kernel::kbd
  消费面同源）；自检 79 → 80。

## 4. M32 起步（Aurora SDK/权限中心计划笔）

- ROADMAP §四 M32 七笔任务级分解落盘：笔② v0.26.0 定版（M24-⓪ 先例定版
  前置）→ 笔③ A1 权限中心首割（aurora 转 no_std+alloc + perm 四相面 +
  vanguard 承接桥零改动）→ 笔④ S1 SDK 最小服务面（App 声明式注册折叠 +
  意图路由骨架）→ 笔⑤ B1 AF-P01 基准口径 → 笔⑥ T1 t81 活体（80→81）→
  笔⑦ 收尾。§三 M32 行 🚧 + 远线行更新（Aurora 转近线）。

## 5. 工程与门禁面

- 裸机自检 78 → **80**（t79 desktop-skel / t80 bootprep），双端计数同步
  （kernel SELFTEST_TOTAL + xtask SELFTEST_EXPECTED）。
- 宿主测试：ostd 9 例 + harbor 22 例 + weave 21 例 + vanguard 5 例 +
  morse 7 例 + loom 24 例 + cascade 18 例 + glyph 10 例 + 全仓 300+ 例。
- lint 台账：政策边销账三项（M29）+ 新立 morse 边（M31）+ allowlist
  台账机检政策面 25 条零违规。
- METRICS.md：H-P01/WE-P02 登记与扩记（M29）；LO-P01/02 + CA-P05 +
  GL-P06 登记（M30）；V-P02/03/05 + WE-P02/03/07 扩记 + P5 驱动旁路
  缩编行新挂（M31）。
- 全部 18 笔提交 xtask ci 十一阶段门禁全绿（t73 设备级 flake 重试口径
  如实登记：撞窗样本取证留档）。

## 6. 既有偏差与挂账（随版延续）

- t73 设备级残余 flake（QEMU MTTCG virtio-net——环境时序面定性；死亡点
  三形态登记，第三样本 pcap 取证留档 t73-capture-epoch-1792918011.log）。
- TCP vnet 电气接线 / 重传定时器 / 滑窗 / 重组（M27-T1 偏差延续）。
- PR-P04 电源协同显示侧（未启动）；alpha 混合与多 Surface 表扩容（v0）。
- 细则 PDF 重取后逐条对账（介质失联 §七 5 登记——本轮 V/WE/LO/CA/GL/
  AF 结构面按在库引用面承接 + morse 命名偏差对账）。
- harbor C ABI 链接层（M29-H1 登记）；WE-P03/07 多事务并发/介质落盘
  （随 crystal 块域）；xxh3-128 uplift（CR-P10）。
- AF-P01 ≤120 ms 冷启动为端到端口径——M32-B1 落宿主基准口径，端到端
  基准随用户态进程基础设施挂账。
- [B] rip=-1 蹲守挂账延续（哨兵面不动）。

## 7. 资产清单

| 资产 | 说明 |
|---|---|
| src.tar.gz | 源码树全量（git tag v0.26.0 字节对齐） |
| artifacts.tar.gz | xtask 十一阶段门禁日志 + t 系活体冒烟日志（boot-smoke）+ ci-summary 报告；历史 devlog S0–S83 与 pf-hunt 台账随沙盒重置介质失联（ROADMAP §七 5 登记，见 v0.24.0 资产存档） |
| RELEASE_NOTES-v0.26.0.md | 本文件 |
| SHA256SUMS | 上列三资产校验和 |
