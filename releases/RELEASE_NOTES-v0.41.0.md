# Lumina OS v0.41.0 —— M49 五候选全开工轮（A–E 七笔闭账）

## 亮点

- **harbor 用户态链接面六族全谱闭环**（候选 A 三笔）：dlclose 真消费链执行域（依赖先卸 + fini 互逆台账）、.fini_array 终局执行域（全局终局序 + 终局清算）、TLS 执行域真做（四模型写面 + DTV 扩展真做 + __tls_get_addr 语义核）。
- **基准族挂账摘牌**（候选 B）：H-P02 链接器装载决议基准（load+reloc mean 3987 ns/op 宿主域）、H-P03 四段打点基准（(1,1,1,1) tenths 零超支）、H-P05 分配器基准（bump 52 ns / freelist 92 ns-pair）——环境 B 绝对门禁挂账如实维持。
- **进程组/会话域**（候选 C）：syscall ABI v0.24→v0.25——SYS_SETPGID(48)/SYS_GETPGID(49)/SYS_GETPGRP(50)/SYS_SETSID(51) 四新号 + ERR_SRCH(14)/ERR_PERM(15) 双码，Linux setpgid 族同谱语义核 + 真车道。
- **TCP 重传面补全**（候选 D）：RFC 5681 快速重传/快速恢复 + RFC 2018 SACK 选项面 + RFC 7323 TSopt/RTTM——M38-TCP1 域清单余项清账。
- **设备级残余窗口族定性**（候选 E）：四族一显形域族谱底稿 + 日志分诊器入库——撞窗不改码纪律体系化（193 冷却协议本会话七度实证）。

## 三面同步

| 面 | v0.40.0 | v0.41.0 |
| --- | --- | --- |
| 裸机自检 | 152/152 | **156/156**（t153–t156 四新号） |
| 双面板标记 | 229 | **245** |
| syscall ABI | v0.24 | **v0.25** |
| harbor 宿主 | 84 | **89**（+close/exit/tls 三面 + 双基准） |
| pulse 宿主 | 44 | **48**（+fast_rtx/sack/ts 三面） |

## 门禁与实录

- CI-OK 11 阶段全绿（定版树复跑——冒烟 156/156，census n156 p156 f0 ff0）。
- 实录锚：LUMINA-T153-CLOSE/FINI/NEG/OK · T154-EXIT/CLEAR/NEG/OK · T155-WRITE/DTV/NEG/OK · T156-MATRIX/LIVE/NEG/OK。
- 七笔全部逐笔实录对账（含揭雷收口域 10+ 处如实落账），详见 ROADMAP §四 M49 七行。

## 资产

- src.tar.gz（tag v0.41.0 干净快照）/ artifacts.tar.gz（十一阶段门禁日志 + 冒烟日志 + ci-summary）/ RELEASE_NOTES / SHA256SUMS——四资产惯例随行。
