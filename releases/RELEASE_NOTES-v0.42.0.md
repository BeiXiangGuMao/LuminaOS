# Lumina OS v0.42.0 —— M50 桌面可用性跃迁轮（六域五落一挂 + musl 真执行纵深 · 七笔闭账）

## 亮点

- **xdg_shell 电气闭环**（笔76+77）：从「合成器演示」到「可开应用窗」的分水岭——XdgWmBase/XdgSurface/XdgToplevel 三接口 wire 面（xdg-shell.xml 官方声明序 opcode 对账）+ comp 会话域角色态（configure/ack/commit 官方契约闸 + XdgUnacked fail-visible）+ send_ping/request_close 服务端双车道 + waycomp GLOBALS 4→5 目公告面演化（124B→156B）+ 窗格动态标题带消费 + t159 真车道全生命周期活体。
- **文本渲染面**（笔78/79）：图形域首次有文字——glyph::text FONT8X16 8x16 双域同源位图（gen_font8x16.py 单事实源 1520 B 直对账）+ render_text 透明合成栅格化 + waycomp 标题栏带；揭雷② title_bar_px 2M 像素回归竞窗 O(1) 化收口。
- **IOPB 挂 TSS 硬件面**（笔81）：M42 三域挂账之一转化——TssWithIopb 合成布局（iopb_offset=112 + 8192 B 位图 deny-by-default）+ 位图 API 组（grant/deny/deny_all/denied/state）+ PIO_GEN 授权纪元 + SPAWN_HOLD 跨核竞逐窗封死——t160 ring3 端口电气探针直呼 in/out GP 零显形（EXIT 0x5F）；揭雷族五例如实落账（SDM 逐字节判读/TCG 读值车道差真机挂账等）。
- **musl 动态全链真件 ring3 真执行**（笔80+82）：从「真件谱」到「真执行」纵深——Alpine musl 1.2.4 ld-musl-x86_64.so.1 + busybox 1.36.1 动态 PIE 双真件入库；bedrock::elf 双型口径演化（ET_DYN/PT_INTERP/AT_BASE 动态域发射静态链字节面零扰动）+ kernel 动态装载器（解释器 PD6[2] 槽域——PD[3+] 内核堆恒等镜像借根禁区避让 + AT_PHDR/AT_BASE/AT_ENTRY 全谱）；t161 真车道活体：真实 musl ldso 机器码 ring3 电气执行（_dlstart 自重定位 → DT_NEEDED 与自身 SONAME 自解 → 程序 386 重定位 → echo applet → exit_group(0) 收割）；揭雷① dl_new_hash 异或→官方加法口径修正（真件首撞即断，四生成器同源重产）。
- **EACCES exec 记账域**（笔75）：syscall ABI v0.25→v0.26——ERR_ACCES(16) 单码追加（Linux setpgid(2) exec 后进程组迁移禁令语义面）+ Task execed 位 + setpgid_check 判据④。

## 三面同步

| 面 | v0.41.0 | v0.42.0 |
| --- | --- | --- |
| 裸机自检 | 156/156 | **161/161**（t157–t161 五新号） |
| 双面板标记 | 245 | **265** |
| syscall ABI | v0.25 | **v0.26** |
| bedrock 宿主 | 43 | **46**（+动态解析/AT_BASE 三面） |
| prism 宿主 | 58 | **60**（+xdg wire/闭环双面） |
| glyph 宿主 | 11 | **15**（+文本渲染四面） |
| harbor 宿主 | 89 | **90**（+musl_chain_face） |

## 门禁与实录

- CI-OK 11 阶段全绿（定版树复跑——冒烟 161/161，census n161 p161 f0 ff0；撞窗族冷却复跑口径续度实证）。
- 实录锚：LUMINA-T157-MATRIX/LIVE/NEG/OK · T158-ANCHOR/RENDER/OK · T159-LOOP/TITLE/NEG/OK · T160-IOPB/LIVE/NEG/OK · T161-DYN interp_base=0x180400000 entry=0x1804628cf segs=4 · T161-DYN-OK（busybox-dyn echo 内容级） · T161-LIVE reaped exit=0 · T161-NEG static-reject=1 interp-reject=1 · T161-OK。
- 七笔全部逐笔实录对账（含揭雷收口域 10+ 处如实落账），详见 ROADMAP §四 M50 七行；MATURITY v12 = **7.1/10**（等权合成公式复归——v10/v11 总评行勘误注在库）。

## 资产

- src.tar.gz（tag v0.42.0 干净快照）/ artifacts.tar.gz（十一阶段门禁日志 + 冒烟日志 + ci-summary）/ RELEASE_NOTES / SHA256SUMS——四资产惯例随行。
