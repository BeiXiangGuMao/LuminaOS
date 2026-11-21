# Lumina OS v0.45.0 —— M53 e1000↔pulse ConnTable 连接表驱动纵深 + 状态族 activated/tiled 枚举域扩展轮

**发布日期**：2026-11-21 ｜ **里程碑**：M53 四笔全谱闭账（开工批笔95/96 + 续作批笔97/98 + 收尾） ｜ **门禁**：CI-OK 11 阶段全绿 + 冒烟 174/174 SMOKE-OK ｜ **MATURITY v15 = 7.3/10**（等权合成 7.32 → 7.3——分项如实升：功能 8.2 / 稳定 6.2 / 安全 7.4 / 治理 9.8 / 性能 5）

## 本轮落账

### 续作批双笔（用户点名 B 线①②续作）
- **笔97 M53-CONN84 e1000↔pulse ConnTable 连接表驱动纵深**：pulse::tcp 五面承接（组帧面——tcp_frame_build 段组帧核单事实源化〔TcpHdr::encode 编码核 + 伪头校验和 + ip_frame_build 以太/IPv4 装配——电车道 tcp_seg_tx 与 tap 车道同构〕+ 查表面——pulse::tcp::ConnTable 定容 8 槽四元组镜像键域双槽直驱 + 状态面——八态机原语逐拍消费 + 闸面——tcp_tap_inject 软件回环交接面 tap 直注 rx_dispatch 五闸〔vnet::tcp_loopback_tx 交接环同谱异件〕+ 定时面+记账面——RtoTimer 武装→on_ack 解除 + 逐拍计数全谱）+ **三相回环之上的 TCP 全握手八拍**（ConnTable 双槽表驱动回环孪生会话：SYN→SYN-ACK→ACK→DATA 16 B 回显逐位→FIN 对称拆→TimeWait 超时收敛→close_key 双槽复位；passive 端半关闭收尾押后/ISN 金值直载/wire 腿软件交接面三项偏差如实登记）+ t173 活体五相位（TAP/HS/DATA/TEARDOWN/OK）。
- **笔98 M53-XDGACT85 状态族 activated/tiled 枚举域扩展**：mod.rs tiled 边组族常量 3-6 + tiled 位域掩码 + 决策核 toplevel_state_decide 扩参（activated 焦点宣告 + tiled_bits 边组逐位展开——states 数组 4→8 槽）+ comp.rs CompSurface tiled_bits 字段 + 四臂焦点/tiled 宣告随行 + flush_xdg sbits 扩域解码（官方枚举序出域）+ set_tiled 布局政策域注入 API（官方协议无 set_tiled 请求——策略宣告面，waycomp 布局缺席 v0 如实挂账）+ surface_activated/surface_tiled 取证访问器 + prism 宿主 72→74 + t174 活体四相位（CORE/WIRE/SESS/OK）。

### 揭雷族五例（t173/t174 首割多轮实录）
- **IP 校验域基线雷**：复用缓冲二拍组帧 ck 域残留首拍值——反码折叠恰 0xFFFF → ck 写 0 → 接收闸 fail-visible 拒收；ip_frame_build 域内清零基线单事实源修复（vnet::cksum16 契约内建）。
- **发送滑窗 sent() 记账雷**：SendWindow::on_ack 要求 ack ∈ (una, nxt] 而 nxt 仅由 sent() 推进——全握手八拍发送窗记账补全（SYN/DATA/FIN 逐拍 sent + 拍二 swnd.on_ack 同拍收口）。
- **陈旧 ack 官方闸雷**：set_tiled 铸串号后 ack 才入流——config_serial 已推进官方闸拒收；feed 4a/4b 拆分官方序收口。
- **configure 对解析锚定雷**：feed2 起流内 keymap/enter 输入事件先行出域——head 锚定入 enter 域 BadLength；尾锚定收口（top_cfg 数组域 4 字节对齐恒 24 B——configure 对 = 流尾 36 B）。
- **串口长行腐蚀雷**：长中文证据行重载域字节丢弃实测——证据行紧凑 ASCII 化 + 位掩码单值短行抗扰收口。

## 三面同步

- SELFTEST 172→**174**（t173 五件 + t174 四件）；双面板 312→**321**；ABI v0.26 维持（纯驱动面/协议面/语义面零新号）；prism 宿主 72→**74**；xtask S8 required 265→**274**/longrun 273→**282**；SELFTEST_EXPECTED 174/174。
- docs 对账：ROADMAP §三 M53 行 ✅ 关账 + §四 双行 + METRICS P5 行续记 + MATURITY v15 + README 事实位终同步 + workspace 升版 0.44.0→**0.45.0**（Cargo.lock 随行）。

## 实录（定版树复跑）

LUMINA-T171-CORE disp=1 arp_served=1 udp_badcs=1 tcp_badcs=0 rt=none rx=+4 miss=+0 served=+0 / LUMINA-T171-ICMP tx=1 reply=+0 echo=1 / LUMINA-T171-UDP tx=1 ok=+1 dhcp=1 yiaddr=0xa00020f / LUMINA-T171-TCP tx=1 ok=+1 rst=+1 rst_ok=1 gw=52:55:0a:00:02:02 / LUMINA-T171-OK / LUMINA-T172-CORE max=1 full=1 clamp=1 cross=1 / LUMINA-T172-WIRE enc=1 / LUMINA-T172-SESS sess=1 neg=1 / LUMINA-T172-OK / LUMINA-T173-TAP tap=2 badcs=1 / LUMINA-T173-HS syn=1 synack=1 ack=1 est=1 rto=1 stage=0 / LUMINA-T173-DATA data=2 ok=1 / LUMINA-T173-TEARDOWN fin=2 neg=1 / LUMINA-T173-OK / LUMINA-T174-CORE core=1 / LUMINA-T174-WIRE wire=1 / LUMINA-T174-SESS bits=0x17f / LUMINA-T174-OK / **LUMINA-SELFTEST-PASS 174/174** / LUMINA-CENSUS n174 p174 f0 ff0

## 工程前置随行

- **提交人面修复**：远端 269 笔中 Z User（沙箱默认身份 <z@container>）污染 author×32/committer×35（M44→M53 开工批）——git filter-branch 条件重写为仓库主身份 BeiXiangGuMao <lyx2254183021@foxmail.com>（日期与树哈希零扰）+ v0.39.0-v0.44.0 六 tag 随迁 + GitHub API 复核清零（author/committer 双面 Z User = 0）。
- **环境复原**：QEMU 10.0.13 用户态运行时复补（deb 闭包按需收敛——libcapstone5/libssl3t64/ibverbs 族等九包 + 系统同 ABI libcrypto 直拷——截断 deb 揭雷随行）+ busybox 介质复原 1,025,960 B（与 M52 账面精确一致）+ Rust 1.99.0 工具链重建（rsproxy 镜像）。

## 挂账随行

真机三实测回填（REALHW-WINDOW R1/R2/R3 + R1′ level+low 口径复评击发）+ 环境 B 绝对门禁 + ICD 实装域 + GPU 加速车道执行面 + e1k↔pulse ConnTable 纵深续域（TCP 服务化车道——多连接并发/被动关闭 CLOSE_WAIT/LAST_ACK 收尾/零窗探测活体车道）+ 状态族 suspended 枚举域 + output 对象域语义 + state 枚举 0-based face 对官方 XML 1-based 实值偏差互操作翻账挂账。

---

**SHA256SUMS**（随 Release 四资产发布；-src.tar.gz / -artifacts.tar.gz 双包 + 本 NOTES 同源哈希入账）。
