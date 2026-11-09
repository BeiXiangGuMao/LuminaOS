//! Prism Wayland 合成器会话面 v1（M42-COMP4 阶段三首笔——「合成器进程
//! 面」核心语义域）。
//!
//! **定位**：M42-计划 阶段三「prism 仲裁 ring3 化 + wayland 合成器进程
//! 消费 SYS_FB_SURFACE」的**仲裁策略面首割**——合成器会话状态机
//! （registry 公告 / bind / surface 生命周期 / damage-commit 发布语
//! 义 / 帧回调）自内核 fb 消费域升出为**纯函数面**：no_std 零堆零
//! unsafe（crate 纪律不变），非 test 门控（`wayland` v0 同口径——
//! ring3 编译进程可直接链接；电气面消费方 = 常驻合成器服务
//! kernel-resident lane〔ADR-0004 双轨〕，ring3 编译进程承接随用户
//! 态 ELF 播种批次挂账如实登记）。
//!
//! **会话语义**（官方 wayland.xml 1.21.0 + wire 文档同源对账）：
//! - 客户端流入口 [`CompSession::feed`]：字节流推进式解析（部分消息
//!   留缓冲——[`FeedReport::consumed`] 承载流步长），签名驱动解析
//!   （v0 `SIG_*` 表复用）+ 对象表路由（v0 [`super::WlObjectTable`]
//!   复用）；
//! - registry 面：get_registry → globals 逐条公告（[`GlobalDef`] 名
//!   单 = 合成器策略面输入）；bind 校验接口名在册 + 版本上界 → 对象
//!   登记；
//! - surface 面：create_surface → 会话槽登记；damage → pending 损伤
//!   并集（surface 坐标域）；commit → **发布语义**（损伤平移屏域后与
//!   窗口几何交集裁剪 = 屏域损伤矩形；帧回调队列一次冲刷为 done 事件
//!   ——官方 commit 域语义）；
//! - 帧回调：frame(new_id) 入队 → commit 冲刷（官方语义——callback
//!   于下次 commit 完成）；
//! - sync：callback done 即时回发（官方语义，callback_data = 0）。
//!
//! **策略面钩子**：合成器窗口几何由 shell/tiling 策略承载（LuminaOS
//! 域 = cascade::tiling::tiling_plan 产出 mirror::Rect，loom 常量同
//! 源承接——t79「两套面同一几何」先例），经 [`CompSession::set_geometry`]
//! 注入会话；commit 记录（[`CommitRecord`]）携带屏域几何与损伤，电气
//! 面消费方据此驱动 SYS_FB_SURFACE 登记/更新 + SYS_FB_SYNC 损伤量化
//! ——**仲裁策略（哪个 surface 在哪个矩形、z 序）自会话面出，内核
//! 合成机械面（Stack::blend）零触碰**（ADR-0004 双轨共存）。
//!
//! **v0 子集域**（如实记档）：请求承接域 = display/registry/
//! compositor/surface 核心四接口（attach/damage/frame/commit/destroy）
//! + **shm 域（M42-ELF5 桌面链批次首割）**：wl_shm.create_pool（fd
//! 占位字记账 → 电气面 SEND_FD/RECV_FD 承接）+ wl_shm_pool.
//! create_buffer（buffer 几何/池偏移记账）+ wl_surface.attach buffer
//! 实录 → commit 记录携带 buffer 几何（电气面自池读像素上屏——
//! pane 代 Paint 替代域随行落域）；region 绑定域登记、其余请求域外
//! fail-visible；callback 对象 commit 后不回收（delete_id 复用面挂
//! 账）；fixed 原字透传（语义换算挂账）。
//!
//! 错误域 fail-visible 全谱显形（[`CompError`]）——不吞畸形不静默降
//! 级；feed 单消息失败即 Err（会话域由消费方裁决：回 error 事件或断
//! 连——v0 电气面 = 断连）。

#![forbid(unsafe_code)]

use mirror::Rect;

use super::{
    compositor, display, encode_callback_done_event, encode_registry_global_event, iface_name,
    parse_args, parse_header, registry, shm, shm_pool, surface, WlArg, WlError, WlHeader, WlIface,
    WlObjectTable, HEADER, SIG_COMPOSITOR_CREATE_REGION, SIG_COMPOSITOR_CREATE_SURFACE,
    SIG_DISPLAY_GET_REGISTRY, SIG_DISPLAY_SYNC, SIG_REGISTRY_BIND, SIG_SHM_CREATE_POOL,
    SIG_SHM_POOL_CREATE_BUFFER, SIG_SHM_POOL_DESTROY, SIG_SURFACE_ATTACH, SIG_SURFACE_COMMIT,
    SIG_SURFACE_DAMAGE, SIG_SURFACE_FRAME, WIRE_MAX,
};

/// 单会话 surface 槽容量（定容零堆——SurfaceTable 同量级先例）。
pub const SESSION_SURFACES: usize = 8;
/// 单次 feed 的 commit 记录上限（多消息流批量回执定容域）。
pub const MAX_COMMITS_PER_FEED: usize = 8;
/// 每 surface 帧回调队列深度（官方无上界——v0 定容裁量如实记档）。
pub const MAX_FRAME_CBS: usize = 4;
/// registry globals 名单上限（核心子集：compositor/seat/shm/output）。
pub const GLOBALS_MAX: usize = 4;
/// 单次 feed 的 create_pool 记录上限（定容零堆）。
pub const MAX_POOLS_PER_FEED: usize = 4;
/// 单会话 buffer 槽容量（定容零堆——SESSION_SURFACES 同量级先例）。
pub const SESSION_BUFFERS: usize = 8;

/// registry global 名单项（合成器策略面输入——公告名单与版本域）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalDef {
    /// registry global 名（uint——bind 寻址域）。
    pub name: u32,
    /// 接口语义。
    pub iface: WlIface,
    /// 公告版本（bind 版本域上界）。
    pub version: u32,
}

/// 会话内 surface 状态（生命周期 + 损伤积累 + 帧回调队列）。
#[derive(Debug, Clone, Copy)]
pub struct CompSurface {
    /// wl 对象 id（客户端域——create_surface new_id）。
    pub wl_id: u32,
    /// attach 记账位（v0 buffer 域——记 id 不承载像素，wl_shm 挂账）。
    pub attached: bool,
    /// attach 的 buffer 对象 id（M42-ELF5——0 = 无；create_buffer
    /// 登记域实-id，commit 时解析为 [`BufferRec`] 几何）。
    pub attach_buf: u32,
    /// 合成器侧窗口几何（屏域——策略面 [`CompSession::set_geometry`]
    /// 注入；未注入 = 零面积矩形，commit 产物零面积损伤域）。
    pub geom: Rect,
    /// pending 损伤并集（surface 坐标域——damage 请求积累，commit 冲
    /// 刷后清零）。
    pub damage: Option<Rect>,
    /// pending 帧回调（客户端域 id 队列——commit 冲刷为 done 事件）。
    pub frames: [u32; MAX_FRAME_CBS],
    /// 帧回调队列长度。
    pub frame_n: usize,
    /// 首映射位（commit 一次后置位——电气面 REGISTER/UPDATE 分流键）。
    pub mapped: bool,
}

/// wl_shm 池创建记录（feed 回执——电气面 fd 传递对账域：每记录恰
/// 对一 fd 占位字，消费方据 [`FeedReport::fd_need`] 承接 RECV_FD）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolRecord {
    /// 新池对象 id（客户端域——create_pool new_id）。
    pub pool_wl: u32,
    /// 池字节域（create_pool size 参——客户端 CREATE 域对账键）。
    pub size: i32,
}

/// 单次 feed 的池创建记录批（定容零堆）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolLog {
    /// 记录槽（`items[..n]` 有效）。
    pub items: [Option<PoolRecord>; MAX_POOLS_PER_FEED],
    /// 记录数。
    pub n: usize,
}

impl PoolLog {
    /// 空批。
    pub const EMPTY: PoolLog = PoolLog {
        items: [None; MAX_POOLS_PER_FEED],
        n: 0,
    };

    /// 记录入批（满容静默拒收——feed 上界定容域，如实记档）。
    fn push(&mut self, rec: PoolRecord) {
        if self.n < MAX_POOLS_PER_FEED {
            self.items[self.n] = Some(rec);
            self.n += 1;
        }
    }
}

/// 会话内 buffer 几何（M42-ELF5——客户端像素承载域）：池引用 +
/// 池内偏移 + 像素域 + 行距 + 像素格式（wl_shm 标准格式值：
/// ARGB8888 = 0 / XRGB8888 = 1——v0 双格式同承载，像素域原字透传）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferRec {
    /// buffer 对象 id（客户端域——create_buffer new_id）。
    pub wl: u32,
    /// 所属池对象 id（客户端域——create_buffer 发起方）。
    pub pool_wl: u32,
    /// 池内字节偏移（create_buffer offset 参）。
    pub offset: i32,
    /// 像素域宽。
    pub w: i32,
    /// 像素域高。
    pub h: i32,
    /// 行距（字节——row stride）。
    pub stride: i32,
    /// 像素格式（wl_shm 格式枚举原值）。
    pub format: u32,
}

/// commit 发布记录（feed 回执——电气面消费域：REGISTER/UPDATE 分流 +
/// SYS_FB_SYNC 损伤量化 + 帧冲刷计数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitRecord {
    /// 发布 surface 的 wl 对象 id。
    pub wl_id: u32,
    /// 屏域窗口几何（策略面几何——非首次 commit 亦可对账域）。
    pub geom: Rect,
    /// 屏域损伤矩形（pending 损伤平移屏域 ∩ 窗口几何；零面积 = 无实
    /// 效损伤）。
    pub damage: Rect,
    /// 本次冲刷的帧回调数（done 事件已回执）。
    pub frames_fired: usize,
    /// 首映射位（true = 电气面 REGISTER 域；false = UPDATE 域）。
    pub first_map: bool,
    /// commit 时 surface 所附 buffer 几何（M42-ELF5——None = 无附
    /// buffer，电气面代 Paint 替代域；Some = 自池读像素上屏）。
    pub buffer: Option<BufferRec>,
}

/// 单次 feed 的 commit 记录批（定容零堆——feed 回执域）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitLog {
    /// 记录槽（`items[..n]` 有效）。
    pub items: [Option<CommitRecord>; MAX_COMMITS_PER_FEED],
    /// 记录数。
    pub n: usize,
}

impl CommitLog {
    /// 空批。
    pub const EMPTY: CommitLog = CommitLog {
        items: [None; MAX_COMMITS_PER_FEED],
        n: 0,
    };

    /// 记录入批（满容静默拒收——feed 上界定容域，超量 commit 以会话
    /// 串号域为准如实记档）。
    fn push(&mut self, rec: CommitRecord) {
        if self.n < MAX_COMMITS_PER_FEED {
            self.items[self.n] = Some(rec);
            self.n += 1;
        }
    }

    /// 按 wl id 末次记录查找（同 feed 双 commit 后者胜——电气面对账
    /// 消费域）。
    pub fn last_of(&self, wl_id: u32) -> Option<CommitRecord> {
        self.items[..self.n]
            .iter()
            .flatten()
            .rev()
            .find(|r| r.wl_id == wl_id)
            .copied()
    }
}

/// feed 回执（流推进 + 产生字节 + commit 批记录）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeedReport {
    /// 流推进字节数（完整消息前缀；部分消息留缓冲——残段由消费方前
    /// 移承载）。
    pub consumed: usize,
    /// `out` 回执缓冲产出字节数（事件序列化域）。
    pub out_len: usize,
    /// commit 批记录（`commits.items[..commits.n]` 有效）。
    pub commits: CommitLog,
    /// 池创建记录批（M42-ELF5——`pools.items[..pools.n]` 有效；每记
    /// 录对一 fd 占位字）。
    pub pools: PoolLog,
    /// 本 feed 消费的 fd 占位字数（电气面 RECV_FD 承接计数——与
    /// pools 批对账：每 create_pool 恰一 fd）。
    pub fd_need: usize,
}

impl FeedReport {
    /// 是否零产出（无推进且无 commit——电气面 skip 快径判定域）。
    pub fn is_skip(&self) -> bool {
        self.consumed == 0 && self.commits.n == 0
    }
}

/// 合成器会话错误域（fail-visible 全谱显形——WlError 原样透传 + 语
/// 义域新增）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompError {
    /// wire 域错误（v0 解析壳同面透传）。
    Wire(WlError),
    /// 路由对象未登记 / 对象域不在册（不泄会话拓扑同面）。
    BadObject,
    /// 接口 × opcode 未收录（核心子集域外——fail-visible 拒收）。
    UnknownRequest,
    /// 会话 surface 槽满（[`SESSION_SURFACES`]）。
    SurfaceFull,
    /// bind 名不在公告名单 / 版本域越上界（策略面名单域——fail-visible）。
    UnknownGlobal,
    /// 会话 buffer 槽满（[`SESSION_BUFFERS`]——M42-ELF5）。
    BufferFull,
    /// 对象表域错误（v0 表纪律透传——满容/id 冲突）。
    Table(WlError),
}

/// 合成器会话状态机（registry 公告面 + surface 生命周期 + commit 发
/// 布语义——零堆定容）。
pub struct CompSession {
    /// 对象表（display 固定 id 1 装载 + 客户端域登记记录）。
    table: WlObjectTable,
    /// registry 公告名单（策略面输入——new 装载后只读）。
    globals: [GlobalDef; GLOBALS_MAX],
    /// 会话 surface 槽。
    surfaces: [Option<CompSurface>; SESSION_SURFACES],
    /// surface 在账数。
    surf_n: usize,
    /// 会话 buffer 槽（M42-ELF5——create_buffer 登记域）。
    buffers: [Option<BufferRec>; SESSION_BUFFERS],
    /// buffer 在账数。
    buf_n: usize,
    /// commit 串号（帧回调 done 事件 callback_data 事实源）。
    commit_serial: u32,
}

impl CompSession {
    /// 会话构造（display 固定 id 1 入表 + globals 名单装载）。globals
    /// 空名单 = 公告面空域（get_registry 零事件回执）。
    pub fn new(globals: [GlobalDef; GLOBALS_MAX]) -> Self {
        let mut table = WlObjectTable::new();
        // wl_display 固定 id 1（官方域——Display 固定分配）。
        let _ = table.install(1, WlIface::Display);
        Self {
            table,
            globals,
            surfaces: [None; SESSION_SURFACES],
            surf_n: 0,
            buffers: [None; SESSION_BUFFERS],
            buf_n: 0,
            commit_serial: 0,
        }
    }

    /// 会话 buffer 在账数（M42-ELF5 取证面）。
    pub fn buffers_count(&self) -> usize {
        self.buf_n
    }

    /// 会话内 buffer 只读快照（取证面——t106 对账消费）。
    pub fn buffer(&self, wl_id: u32) -> Option<BufferRec> {
        self.buffers
            .iter()
            .flatten()
            .find(|b| b.wl == wl_id)
            .copied()
    }

    /// 对象表只读视图（取证面——t104 对账消费）。
    pub fn table(&self) -> &WlObjectTable {
        &self.table
    }

    /// 会话 surface 在账数。
    pub fn surfaces_count(&self) -> usize {
        self.surf_n
    }

    /// commit 串号快照（帧回调对账域）。
    pub fn commit_serial(&self) -> u32 {
        self.commit_serial
    }

    /// 公告名单只读视图。
    pub fn globals(&self) -> &[GlobalDef; GLOBALS_MAX] {
        &self.globals
    }

    /// 策略面钩子：窗口几何注入（cascade::tiling_plan 产出域——屏域
    /// Rect）。未登记 surface → [`CompError::BadObject`]。
    pub fn set_geometry(&mut self, wl_id: u32, geom: Rect) -> Result<(), CompError> {
        let slot = self
            .surfaces
            .iter_mut()
            .find(|s| s.as_ref().is_some_and(|sf| sf.wl_id == wl_id))
            .ok_or(CompError::BadObject)?;
        if let Some(sf) = slot.as_mut() {
            sf.geom = geom;
        }
        Ok(())
    }

    /// 会话内 surface 只读快照（取证面）。
    pub fn surface(&self, wl_id: u32) -> Option<CompSurface> {
        self.surfaces
            .iter()
            .flatten()
            .find(|sf| sf.wl_id == wl_id)
            .copied()
    }

    /// 会话在册 surface id 清单（槽序 = 创建序——策略面入窗消费域；
    /// 产物 =（id 槽, 有效数），None 槽跳过）。零堆定容返回。
    pub fn surface_ids(&self) -> ([Option<u32>; SESSION_SURFACES], usize) {
        let mut ids = [None; SESSION_SURFACES];
        let mut n = 0usize;
        for s in self.surfaces.iter().flatten() {
            ids[n] = Some(s.wl_id);
            n += 1;
        }
        (ids, n)
    }

    /// global 名单查找（bind 校验域——接口名对账）。
    fn global_by_iface_name(&self, iface: &[u8]) -> Option<GlobalDef> {
        self.globals
            .iter()
            .copied()
            .find(|g| iface_name(g.iface).as_bytes() == iface)
    }

    /// 客户端流入口：推进式解析 + 事件回执（官方事件序列化域）。
    ///
    /// 流语义：`stream` 内**完整消息前缀**逐条派发（部分消息留缓冲
    /// ——`consumed` 承载推进步长，残段由消费方前移）；`out` 承载事
    /// 件回执（globals 公告 / sync done / frame done），`out_len` 承
    /// 载产出字节数。畸形头（尺寸域越界）即时 fail-visible（Err 透
    /// 传）；部分消息（尺寸域完整但残段不足）干净断流。
    pub fn feed(&mut self, stream: &[u8], out: &mut [u8]) -> Result<FeedReport, CompError> {
        let mut log = CommitLog::EMPTY;
        let mut pools = PoolLog::EMPTY;
        let mut fd_need = 0usize;
        let mut out_len = 0usize;
        let mut consumed = 0usize;
        while consumed + HEADER <= stream.len() {
            // 尺寸前窥：完整消息域判定（部分消息干净断流——非错误域；
            // 畸形尺寸域由派发层 BadLength fail-visible 显形）
            let size = u16::from_le_bytes([stream[consumed + 6], stream[consumed + 7]]) as usize;
            if (HEADER..=WIRE_MAX).contains(&size) && consumed + size > stream.len() {
                break; // 部分消息——留缓冲（流推进干净域）
            }
            let step = self.dispatch(
                &stream[consumed..],
                &mut out_len,
                out,
                &mut log,
                &mut pools,
                &mut fd_need,
            )?;
            consumed += step;
        }
        Ok(FeedReport {
            consumed,
            out_len,
            commits: log,
            pools,
            fd_need,
        })
    }

    /// 单消息派发（头 + 签名驱动解析 + 对象路由 + 事件回执写入 +
    /// commit/池记录批）。返回消息 wire 尺寸（流步长）。
    #[allow(clippy::too_many_arguments)]
    fn dispatch(
        &mut self,
        msg: &[u8],
        out_len: &mut usize,
        out: &mut [u8],
        log: &mut CommitLog,
        pools: &mut PoolLog,
        fd_need: &mut usize,
    ) -> Result<usize, CompError> {
        let header = parse_header(msg).map_err(CompError::Wire)?;
        let body = &msg[HEADER..header.size as usize];
        let Some(iface) = self.table.lookup(header.object_id) else {
            return Err(CompError::BadObject);
        };
        match iface {
            WlIface::Display => self.dispatch_display(&header, body, out_len, out)?,
            WlIface::Registry => self.dispatch_registry(&header, body)?,
            WlIface::Compositor => self.dispatch_compositor(&header, body)?,
            WlIface::Surface => self.dispatch_surface(&header, body, out_len, out, log)?,
            WlIface::Shm => self.dispatch_shm(&header, body, pools, fd_need)?,
            WlIface::ShmPool => self.dispatch_shm_pool(&header, body)?,
            // callback/seat/output/region/buffer：服务端
            // 请求域外（v0 子集——fail-visible）。
            _ => return Err(CompError::UnknownRequest),
        }
        Ok(header.size as usize)
    }

    /// wl_display 请求域（sync 即时 done / get_registry 公告面）。
    fn dispatch_display(
        &mut self,
        header: &WlHeader,
        body: &[u8],
        out_len: &mut usize,
        out: &mut [u8],
    ) -> Result<(), CompError> {
        match header.opcode {
            display::REQ_SYNC => {
                let (args, _) = parse_args(body, SIG_DISPLAY_SYNC).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(cb_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                self.table
                    .install(cb_id, WlIface::Callback)
                    .map_err(CompError::Table)?;
                // 官方语义：sync callback 即时完成（callback_data 无官
                // 方约束域——v0 记 0）。
                let n = encode_callback_done_event(&mut out[*out_len..], cb_id, 0)
                    .map_err(CompError::Wire)?;
                *out_len += n;
                Ok(())
            }
            display::REQ_GET_REGISTRY => {
                let (args, _) =
                    parse_args(body, SIG_DISPLAY_GET_REGISTRY).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(reg_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                self.table
                    .install(reg_id, WlIface::Registry)
                    .map_err(CompError::Table)?;
                for g in &self.globals {
                    let n = encode_registry_global_event(
                        &mut out[*out_len..],
                        reg_id,
                        g.name,
                        g.iface,
                        g.version,
                    )
                    .map_err(CompError::Wire)?;
                    *out_len += n;
                }
                Ok(())
            }
            _ => Err(CompError::UnknownRequest),
        }
    }

    /// wl_registry 请求域（bind——接口名名单校验 + 版本上界 + 对象登记）。
    fn dispatch_registry(&mut self, header: &WlHeader, body: &[u8]) -> Result<(), CompError> {
        match header.opcode {
            registry::REQ_BIND => {
                let (args, _) = parse_args(body, SIG_REGISTRY_BIND).map_err(CompError::Wire)?;
                let Some(WlArg::Uint(_name)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Str(iface)) = args[1] else {
                    return Err(CompError::Wire(WlError::BadString));
                };
                let Some(WlArg::Uint(ver)) = args[2] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::NewId(new_id)) = args[3] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let g = self
                    .global_by_iface_name(iface)
                    .ok_or(CompError::UnknownGlobal)?;
                // bind 版本域上界校验（公告版本为上界——越界 = 客户端
                // 违约，fail-visible；0 = 非法版本域）。
                if ver == 0 || ver > g.version {
                    return Err(CompError::UnknownGlobal);
                }
                self.table
                    .install(new_id, g.iface)
                    .map_err(CompError::Table)?;
                Ok(())
            }
            _ => Err(CompError::UnknownRequest),
        }
    }

    /// wl_compositor 请求域（create_surface / create_region）。
    fn dispatch_compositor(&mut self, header: &WlHeader, body: &[u8]) -> Result<(), CompError> {
        match header.opcode {
            compositor::REQ_CREATE_SURFACE => {
                let (args, _) =
                    parse_args(body, SIG_COMPOSITOR_CREATE_SURFACE).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(surf_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                self.session_surface_new(surf_id)
            }
            compositor::REQ_CREATE_REGION => {
                let (args, _) =
                    parse_args(body, SIG_COMPOSITOR_CREATE_REGION).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(reg_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                self.table
                    .install(reg_id, WlIface::Region)
                    .map_err(CompError::Table)?;
                Ok(())
            }
            _ => Err(CompError::UnknownRequest),
        }
    }

    /// wl_shm 请求域（M42-ELF5 桌面链批次——create_pool：池对象登记 +
    /// fd 占位字记账 + 池记录入批；resize 域外 fail-visible）。
    fn dispatch_shm(
        &mut self,
        header: &WlHeader,
        body: &[u8],
        pools: &mut PoolLog,
        fd_need: &mut usize,
    ) -> Result<(), CompError> {
        match header.opcode {
            shm::REQ_CREATE_POOL => {
                let (args, _) = parse_args(body, SIG_SHM_CREATE_POOL).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(pool_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Fd(_)) = args[1] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Int(size)) = args[2] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                self.table
                    .install(pool_id, WlIface::ShmPool)
                    .map_err(CompError::Table)?;
                pools.push(PoolRecord {
                    pool_wl: pool_id,
                    size,
                });
                *fd_need += 1; // 每 create_pool 恰一 fd（电气面 RECV_FD 承接计数）
                Ok(())
            }
            _ => Err(CompError::UnknownRequest),
        }
    }

    /// wl_shm_pool 请求域（M42-ELF5——create_buffer：buffer 几何记账
    /// + 对象登记；destroy：双清；resize 域外 fail-visible）。
    fn dispatch_shm_pool(&mut self, header: &WlHeader, body: &[u8]) -> Result<(), CompError> {
        match header.opcode {
            shm_pool::REQ_CREATE_BUFFER => {
                let (args, _) =
                    parse_args(body, SIG_SHM_POOL_CREATE_BUFFER).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(buf_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let mut vals = [0i32; 4];
                for (k, a) in args.iter().take(5).skip(1).enumerate() {
                    match a {
                        Some(WlArg::Int(v)) => vals[k] = *v,
                        _ => return Err(CompError::Wire(WlError::BadLength)),
                    }
                }
                let Some(WlArg::Uint(format)) = args[5] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                if self.buf_n >= SESSION_BUFFERS {
                    return Err(CompError::BufferFull);
                }
                let Some(slot) = self.buffers.iter_mut().find(|b| b.is_none()) else {
                    return Err(CompError::BufferFull);
                };
                self.table
                    .install(buf_id, WlIface::Buffer)
                    .map_err(CompError::Table)?;
                *slot = Some(BufferRec {
                    wl: buf_id,
                    pool_wl: header.object_id,
                    offset: vals[0],
                    w: vals[1],
                    h: vals[2],
                    stride: vals[3],
                    format,
                });
                self.buf_n += 1;
                Ok(())
            }
            shm_pool::REQ_DESTROY => {
                let _ = parse_args(body, SIG_SHM_POOL_DESTROY).map_err(CompError::Wire)?;
                // 池对象摘除（表清；会话 buffer 域不连带——buffer 生命
                // 周期独立，池亡后像素域失效由池电气面承载，如实记档）
                let _ = self.table.remove(header.object_id);
                Ok(())
            }
            _ => Err(CompError::UnknownRequest),
        }
    }

    /// wl_surface 请求域（destroy/attach/damage/frame/commit——v0 子
    /// 集；其余 opcode fail-visible）。
    fn dispatch_surface(
        &mut self,
        header: &WlHeader,
        body: &[u8],
        out_len: &mut usize,
        out: &mut [u8],
        log: &mut CommitLog,
    ) -> Result<(), CompError> {
        match header.opcode {
            surface::REQ_DESTROY => {
                if self.surface_slot(header.object_id).is_none() {
                    return Err(CompError::BadObject);
                }
                self.session_surface_drop(header.object_id);
                Ok(())
            }
            surface::REQ_ATTACH => {
                let (args, _) = parse_args(body, SIG_SURFACE_ATTACH).map_err(CompError::Wire)?;
                let Some(WlArg::Object(buf_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Int(_)) = args[1] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                let Some(WlArg::Int(_)) = args[2] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                // buffer 域校验（未登记 buffer id → BadObject fail-visible
                // ——M42-ELF5 像素承载域前置闸；借用域分离——先只读查
                // 槽后可变写位，同 session_commit 分离窗先例）
                let buf_ok = self.buffers.iter().flatten().any(|b| b.wl == buf_id);
                let Some(sf) = self.surface_slot_mut(header.object_id) else {
                    return Err(CompError::BadObject);
                };
                if buf_id == 0 {
                    // 官方语义：attach(null) = 解附（下轮 commit 无内容域）
                    sf.attached = false;
                    sf.attach_buf = 0;
                    return Ok(());
                }
                if !buf_ok {
                    return Err(CompError::BadObject);
                }
                sf.attached = true; // buffer id 记账域（M42-ELF5 像素承载实-id）
                sf.attach_buf = buf_id;
                Ok(())
            }
            surface::REQ_DAMAGE => {
                let (args, _) = parse_args(body, SIG_SURFACE_DAMAGE).map_err(CompError::Wire)?;
                let mut vals = [0i32; 4];
                for (k, a) in args.iter().take(4).enumerate() {
                    match a {
                        Some(WlArg::Int(v)) => vals[k] = *v,
                        _ => return Err(CompError::Wire(WlError::BadLength)),
                    }
                }
                // 负域非负化（官方语义 damage 可越界——交集裁剪在
                // commit 域承担，此处仅积累域规整）。
                let dx = vals[0].max(0);
                let dy = vals[1].max(0);
                let dw = vals[2].max(0) as u32;
                let dh = vals[3].max(0) as u32;
                let Some(sf) = self.surface_slot_mut(header.object_id) else {
                    return Err(CompError::BadObject);
                };
                if dw > 0 && dh > 0 {
                    let r = Rect {
                        x: dx,
                        y: dy,
                        w: dw,
                        h: dh,
                    };
                    sf.damage = Some(match sf.damage {
                        Some(prev) => prev.union(&r),
                        None => r,
                    });
                }
                Ok(())
            }
            surface::REQ_FRAME => {
                let (args, _) = parse_args(body, SIG_SURFACE_FRAME).map_err(CompError::Wire)?;
                let Some(WlArg::NewId(cb_id)) = args[0] else {
                    return Err(CompError::Wire(WlError::BadLength));
                };
                self.table
                    .install(cb_id, WlIface::Callback)
                    .map_err(CompError::Table)?;
                let Some(sf) = self.surface_slot_mut(header.object_id) else {
                    return Err(CompError::BadObject);
                };
                if sf.frame_n >= MAX_FRAME_CBS {
                    return Err(CompError::SurfaceFull);
                }
                sf.frames[sf.frame_n] = cb_id;
                sf.frame_n += 1;
                Ok(())
            }
            surface::REQ_COMMIT => {
                let _ = parse_args(body, SIG_SURFACE_COMMIT).map_err(CompError::Wire)?;
                self.session_commit(header.object_id, out_len, out, log)
            }
            _ => Err(CompError::UnknownRequest),
        }
    }

    /// 会话 surface 登记槽位分配（create_surface 域）。
    fn session_surface_new(&mut self, surf_id: u32) -> Result<(), CompError> {
        if self.surf_n >= SESSION_SURFACES {
            return Err(CompError::SurfaceFull);
        }
        let Some(slot) = self.surfaces.iter_mut().find(|s| s.is_none()) else {
            return Err(CompError::SurfaceFull);
        };
        self.table
            .install(surf_id, WlIface::Surface)
            .map_err(CompError::Table)?;
        *slot = Some(CompSurface {
            wl_id: surf_id,
            attached: false,
            attach_buf: 0,
            geom: Rect {
                x: 0,
                y: 0,
                w: 0,
                h: 0,
            },
            damage: None,
            frames: [0; MAX_FRAME_CBS],
            frame_n: 0,
            mapped: false,
        });
        self.surf_n += 1;
        Ok(())
    }

    /// 会话 surface 摘除（destroy 域——对象表 + 槽位双清；id 不复用
    /// v0 表纪律）。
    fn session_surface_drop(&mut self, wl_id: u32) {
        let _ = self.table.remove(wl_id);
        if let Some(slot) = self
            .surfaces
            .iter_mut()
            .find(|s| s.as_ref().is_some_and(|sf| sf.wl_id == wl_id))
        {
            *slot = None;
            self.surf_n -= 1;
        }
    }

    /// surface 槽位只读查找。
    fn surface_slot(&self, wl_id: u32) -> Option<&CompSurface> {
        self.surfaces.iter().flatten().find(|sf| sf.wl_id == wl_id)
    }

    /// surface 槽位可变查找。
    fn surface_slot_mut(&mut self, wl_id: u32) -> Option<&mut CompSurface> {
        self.surfaces
            .iter_mut()
            .flatten()
            .find(|sf| sf.wl_id == wl_id)
    }

    /// commit 发布语义（损伤平移屏域 ∩ 窗口几何交集裁剪 + 帧回调冲刷
    /// done 事件 + 串号推进 + commit 记录入批）。零面积几何/零损伤
    /// 域 = 记录照常入批（映射态推进语义——损伤矩形零面积，电气面
    /// sync 零量化收敛）。
    fn session_commit(
        &mut self,
        wl_id: u32,
        out_len: &mut usize,
        out: &mut [u8],
        log: &mut CommitLog,
    ) -> Result<(), CompError> {
        // 帧回调冲刷先行取值（借用域分离——状态读 + 事件写分离窗）
        let (geom, screen_damage, frames_fired, frame_ids, first_map, attach_buf) = {
            let Some(sf) = self.surface_slot_mut(wl_id) else {
                return Err(CompError::BadObject);
            };
            let screen_damage = match (sf.damage, sf.geom.area()) {
                (Some(d), a) if a > 0 => {
                    // 损伤（surface 坐标）平移屏域后与窗口几何交集裁
                    // 剪——几何外损伤无实效（官方裁剪语义）。
                    let cand = Rect {
                        x: sf.geom.x + d.x,
                        y: sf.geom.y + d.y,
                        w: d.w,
                        h: d.h,
                    };
                    cand.intersection(&sf.geom).unwrap_or(Rect {
                        x: 0,
                        y: 0,
                        w: 0,
                        h: 0,
                    })
                }
                _ => Rect {
                    x: 0,
                    y: 0,
                    w: 0,
                    h: 0,
                },
            };
            let fired = sf.frame_n;
            let ids = sf.frames;
            let first = !sf.mapped;
            let abuf = sf.attach_buf;
            sf.mapped = true;
            sf.damage = None;
            sf.frame_n = 0;
            (sf.geom, screen_damage, fired, ids, first, abuf)
        };
        // attach buffer 几何解析（M42-ELF5——commit 快照：buffer 对象
        // 在会话槽内即携几何出域；未附/已解附 = None。借用域分离：可
        // 变槽借用终结后缓冲槽只读域）
        let buffer = if attach_buf != 0 {
            self.buffers
                .iter()
                .flatten()
                .find(|b| b.wl == attach_buf)
                .copied()
        } else {
            None
        };
        self.commit_serial = self.commit_serial.wrapping_add(1);
        // 帧回调 done 事件冲刷（官方语义——callback_data = commit 串
        // 号；callback 对象不回收——delete_id 挂账）。
        for cb in frame_ids.iter().take(frames_fired) {
            let n = encode_callback_done_event(&mut out[*out_len..], *cb, self.commit_serial)
                .map_err(CompError::Wire)?;
            *out_len += n;
        }
        log.push(CommitRecord {
            wl_id,
            geom,
            damage: screen_damage,
            frames_fired,
            first_map,
            buffer,
        });
        Ok(())
    }
}

// -------------------------------------------------------- 宿主测试谱
// （M34-P4「宿主测试谱先行」——`cargo test -p prism`；事实源 = 官方
//   wayland.xml 1.21.0 会话语义 + wire 壳 v0 表复用对账）

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    extern crate std;

    use super::*;
    use crate::wayland::{
        callback, encode_display_get_registry, encode_display_sync, encode_message,
        encode_registry_bind, encode_surface_commit, surface as surf_ops, SIG_CALLBACK_DONE,
        SIG_REGISTRY_GLOBAL,
    };

    /// 测试用公告名单：核心子集四 global（compositor v4 / seat v1 /
    /// shm v1 / output v2——名 1..=4）。
    const GLOBALS: [GlobalDef; GLOBALS_MAX] = [
        GlobalDef {
            name: 1,
            iface: WlIface::Compositor,
            version: 4,
        },
        GlobalDef {
            name: 2,
            iface: WlIface::Seat,
            version: 1,
        },
        GlobalDef {
            name: 3,
            iface: WlIface::Shm,
            version: 1,
        },
        GlobalDef {
            name: 4,
            iface: WlIface::Output,
            version: 2,
        },
    ];

    /// t79 平铺 golden 域主窗几何（1920×1080 master pane——策略面几何
    /// 承接样本）。
    const PANE: Rect = Rect {
        x: 8,
        y: 56,
        w: 948,
        h: 944,
    };

    /// 多消息流拼接（std 域——测试体零堆纪律不受限）。
    fn stream_of(msgs: &[&[u8]]) -> std::vec::Vec<u8> {
        let mut v = std::vec::Vec::new();
        for m in msgs {
            v.extend_from_slice(m);
        }
        v
    }

    fn new_session() -> CompSession {
        CompSession::new(GLOBALS)
    }

    /// registry 轮转前置（get_registry + globals 回执解析——四公告
    /// 全谱断言 + registry 对象登记显形）。
    fn setup_registry(s: &mut CompSession) -> std::vec::Vec<u8> {
        let mut req = [0u8; 64];
        let n = encode_display_get_registry(&mut req, 1, 2).unwrap();
        let mut out = [0u8; 512];
        let rep = s.feed(&req[..n], &mut out).unwrap();
        assert_eq!(rep.consumed, n);
        // 回执字节数逐项对账：compositor(36) + seat(28) + shm(28) + output(32)
        assert_eq!(rep.out_len, 36 + 28 + 28 + 32);
        assert_eq!(s.table().lookup(2), Some(WlIface::Registry));
        // 回执解析：四 global 事件逐条对账（声明序 = 名单序）
        let mut off = 0usize;
        for g in GLOBALS.iter() {
            let m =
                crate::wayland::parse_message(&out[off..rep.out_len], SIG_REGISTRY_GLOBAL).unwrap();
            assert_eq!(m.header.object_id, 2);
            assert_eq!(m.header.opcode, crate::wayland::registry::EV_GLOBAL);
            assert_eq!(m.args[0], Some(WlArg::Uint(g.name)));
            assert_eq!(m.args[1], Some(WlArg::Str(iface_name(g.iface).as_bytes())));
            assert_eq!(m.args[2], Some(WlArg::Uint(g.version)));
            off += m.wire_size();
        }
        assert_eq!(off, rep.out_len, "globals 回执逐字节对账");
        out[..rep.out_len].to_vec()
    }

    /// registry 公告面轮转：get_registry → 四 global 全谱回执 + 表登记。
    #[test]
    fn session_registry_roundtrip() {
        let mut s = new_session();
        setup_registry(&mut s);
        // display 固定 id 1 在账 + registry id 2 客户端域登记
        assert_eq!(s.table().lookup(1), Some(WlIface::Display));
        assert_eq!(s.table().lookup(2), Some(WlIface::Registry));
    }

    /// bind + create_surface 双请求单流推进：接口名名单校验 + 对象登
    /// 记 + 会话槽登记。
    #[test]
    fn bind_and_create_surface() {
        let mut s = new_session();
        setup_registry(&mut s);
        let bind = {
            let mut b = [0u8; 64];
            let n = encode_registry_bind(&mut b, 2, 1, "wl_compositor", 4, 3).unwrap();
            b[..n].to_vec()
        };
        let cs = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            b[..n].to_vec()
        };
        let stream = stream_of(&[&bind, &cs]);
        let mut out = [0u8; 64];
        let rep = s.feed(&stream, &mut out).unwrap();
        assert_eq!(rep.consumed, stream.len());
        assert_eq!(rep.out_len, 0, "bind/create_surface 无事件回执");
        assert_eq!(s.table().lookup(3), Some(WlIface::Compositor));
        assert_eq!(s.table().lookup(0x21), Some(WlIface::Surface));
        assert_eq!(s.surfaces_count(), 1);
        let sf = s.surface(0x21).unwrap();
        assert!(!sf.attached && !sf.mapped && sf.damage.is_none());
    }

    /// damage → commit 发布语义：损伤交集裁剪 + 帧回调冲刷 + 首映射位
    /// + 记录批回执。
    #[test]
    fn damage_commit_report() {
        let mut s = new_session();
        setup_registry(&mut s);
        let bind = {
            let mut b = [0u8; 64];
            let n = encode_registry_bind(&mut b, 2, 1, "wl_compositor", 4, 3).unwrap();
            b[..n].to_vec()
        };
        let cs = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            b[..n].to_vec()
        };
        s.feed(&stream_of(&[&bind, &cs]), &mut [0u8; 16]).unwrap();
        s.set_geometry(0x21, PANE).unwrap();
        let dmg = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                0x21,
                surf_ops::REQ_DAMAGE,
                &[
                    WlArg::Int(0),
                    WlArg::Int(0),
                    WlArg::Int(100),
                    WlArg::Int(50),
                ],
            )
            .unwrap();
            b[..n].to_vec()
        };
        let frame = {
            let mut b = [0u8; 64];
            let n =
                encode_message(&mut b, 0x21, surf_ops::REQ_FRAME, &[WlArg::NewId(0x22)]).unwrap();
            b[..n].to_vec()
        };
        let commit = {
            let mut b = [0u8; 64];
            let n = encode_surface_commit(&mut b, 0x21).unwrap();
            b[..n].to_vec()
        };
        let mut out = [0u8; 128];
        let rep = s
            .feed(&stream_of(&[&dmg, &frame, &commit]), &mut out)
            .unwrap();
        // commit 记录：屏域损伤 = surface 域损伤平移 ∩ 几何；首映射位
        let rec = rep.commits.last_of(0x21).expect("commit 记录在批");
        assert_eq!(rec.geom, PANE);
        assert_eq!(
            rec.damage,
            Rect {
                x: 8,
                y: 56,
                w: 100,
                h: 50
            }
        );
        assert!(rec.first_map);
        assert_eq!(rec.frames_fired, 1);
        assert_eq!(rep.commits.n, 1);
        // 帧回调 done 事件回执解析（callback_data = commit 串号 1）
        let m = crate::wayland::parse_message(&out[..rep.out_len], SIG_CALLBACK_DONE).unwrap();
        assert_eq!(m.header.object_id, 0x22);
        assert_eq!(m.header.opcode, callback::EV_DONE);
        assert_eq!(m.args[0], Some(WlArg::Uint(1)));
        // 会话态：损伤冲刷清零 + 首映射位翻转 + 串号推进
        let sf = s.surface(0x21).unwrap();
        assert!(sf.mapped && sf.damage.is_none() && sf.frame_n == 0);
        assert_eq!(s.commit_serial(), 1);
    }

    /// 二次 commit（无损伤无帧）：零面积损伤域 + UPDATE 分流键 + 零
    /// 事件回执。
    #[test]
    fn second_commit_zero_damage() {
        let mut s = new_session();
        setup_registry(&mut s);
        let bind = {
            let mut b = [0u8; 64];
            let n = encode_registry_bind(&mut b, 2, 1, "wl_compositor", 4, 3).unwrap();
            b[..n].to_vec()
        };
        let cs = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            b[..n].to_vec()
        };
        s.feed(&stream_of(&[&bind, &cs]), &mut [0u8; 16]).unwrap();
        s.set_geometry(0x21, PANE).unwrap();
        let commit = {
            let mut b = [0u8; 64];
            let n = encode_surface_commit(&mut b, 0x21).unwrap();
            b[..n].to_vec()
        };
        // 首映射 commit（无损伤——映射态推进）
        let rep1 = s.feed(&commit, &mut [0u8; 16]).unwrap();
        let r1 = rep1.commits.last_of(0x21).unwrap();
        assert!(r1.first_map);
        assert_eq!(r1.damage.w, 0);
        // 二次 commit：UPDATE 分流键 + 零面积 + 零回执
        let mut out = [0u8; 64];
        let rep2 = s.feed(&commit, &mut out).unwrap();
        let r2 = rep2.commits.last_of(0x21).unwrap();
        assert!(!r2.first_map);
        assert_eq!(
            r2.damage,
            Rect {
                x: 0,
                y: 0,
                w: 0,
                h: 0
            }
        );
        assert_eq!(r2.frames_fired, 0);
        assert_eq!(rep2.out_len, 0);
    }

    /// 损伤并集 + 屏域交集裁剪：两次 damage 积累 + 越几何域裁剪。
    #[test]
    fn damage_union_and_screen_clip() {
        let mut s = new_session();
        setup_registry(&mut s);
        let bind = {
            let mut b = [0u8; 64];
            let n = encode_registry_bind(&mut b, 2, 1, "wl_compositor", 4, 3).unwrap();
            b[..n].to_vec()
        };
        let cs = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            b[..n].to_vec()
        };
        s.feed(&stream_of(&[&bind, &cs]), &mut [0u8; 16]).unwrap();
        s.set_geometry(0x21, PANE).unwrap();
        let d1 = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                0x21,
                surf_ops::REQ_DAMAGE,
                &[WlArg::Int(0), WlArg::Int(0), WlArg::Int(50), WlArg::Int(50)],
            )
            .unwrap();
            b[..n].to_vec()
        };
        // 越几何域损伤（surface 域 900×900 > 窗口 948×944）——交集裁剪
        let d2 = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                0x21,
                surf_ops::REQ_DAMAGE,
                &[
                    WlArg::Int(10),
                    WlArg::Int(10),
                    WlArg::Int(900),
                    WlArg::Int(900),
                ],
            )
            .unwrap();
            b[..n].to_vec()
        };
        let commit = {
            let mut b = [0u8; 64];
            let n = encode_surface_commit(&mut b, 0x21).unwrap();
            b[..n].to_vec()
        };
        let rep = s
            .feed(&stream_of(&[&d1, &d2, &commit]), &mut [0u8; 64])
            .unwrap();
        let rec = rep.commits.last_of(0x21).unwrap();
        // 并集 = (0,0,910,910)（union 包络）→ 平移屏域 (8,56) 交集
        // PANE(8,56,948,944) → (8,56,910,910)
        assert_eq!(
            rec.damage,
            Rect {
                x: 8,
                y: 56,
                w: 910,
                h: 910
            }
        );
    }

    /// sync 即时 done 回执（官方语义——callback_data = 0 域）。
    #[test]
    fn sync_callback_immediate() {
        let mut s = new_session();
        let mut req = [0u8; 64];
        let n = encode_display_sync(&mut req, 1, 9).unwrap();
        let mut out = [0u8; 64];
        let rep = s.feed(&req[..n], &mut out).unwrap();
        assert_eq!(rep.consumed, n);
        assert_eq!(rep.out_len, 8 + 4, "done 事件 = 头 + uint");
        let m = crate::wayland::parse_message(&out[..rep.out_len], SIG_CALLBACK_DONE).unwrap();
        assert_eq!(m.header.object_id, 9);
        assert_eq!(m.header.opcode, callback::EV_DONE);
        assert_eq!(m.args[0], Some(WlArg::Uint(0)));
        assert_eq!(s.table().lookup(9), Some(WlIface::Callback));
    }

    /// 负例域全谱：未登记对象 / 域外 opcode / 名单外 bind / 版本越上
    /// 界 / 版本 0 / 会话槽满。
    #[test]
    fn negative_domain_fail_visible() {
        let mut s = new_session();
        // 未登记对象路由拒收（合法头 + 非在册 id——BadObject 显形）
        let mut out = [0u8; 64];
        let ghost = [
            0x99u8, 0x09, 0x00, 0x00, // object_id = 0x999（未登记域）
            0x00, 0x00, 0x08, 0x00, // opcode 0 + size 8
        ];
        assert_eq!(s.feed(&ghost, &mut out), Err(CompError::BadObject));
        setup_registry(&mut s);
        // bind 名单外接口
        let bad_bind = {
            let mut b = [0u8; 64];
            let n = encode_registry_bind(&mut b, 2, 9, "wl_rogue", 1, 9).unwrap();
            b[..n].to_vec()
        };
        assert_eq!(s.feed(&bad_bind, &mut out), Err(CompError::UnknownGlobal));
        // bind 版本越上界（公告 v4，bind v5）+ 版本 0
        for ver in [5u32, 0] {
            let b = {
                let mut buf = [0u8; 64];
                let n = encode_registry_bind(&mut buf, 2, 1, "wl_compositor", ver, 9).unwrap();
                buf[..n].to_vec()
            };
            assert_eq!(s.feed(&b, &mut out), Err(CompError::UnknownGlobal));
        }
        // display 域外 opcode（EV_ERROR 属客户端向事件——服务端拒收）
        let rogue = {
            let mut b = [0u8; 64];
            let n = encode_message(&mut b, 1, 7, &[WlArg::Uint(0)]).unwrap();
            b[..n].to_vec()
        };
        assert_eq!(s.feed(&rogue, &mut out), Err(CompError::UnknownRequest));
        // 会话槽满（9 surface → SurfaceFull）
        let bind_ok = {
            let mut b = [0u8; 64];
            let n = encode_registry_bind(&mut b, 2, 1, "wl_compositor", 4, 3).unwrap();
            b[..n].to_vec()
        };
        s.feed(&bind_ok, &mut [0u8; 16]).unwrap();
        for k in 0..SESSION_SURFACES + 1 {
            let cs = {
                let mut b = [0u8; 64];
                let n = encode_message(
                    &mut b,
                    3,
                    compositor::REQ_CREATE_SURFACE,
                    &[WlArg::NewId(0x100 + k as u32)],
                )
                .unwrap();
                b[..n].to_vec()
            };
            let last = k == SESSION_SURFACES;
            match s.feed(&cs, &mut [0u8; 16]) {
                Ok(_) if !last => {}
                Err(CompError::SurfaceFull) if last => {}
                _ if last => panic!("槽满域未显形"),
                _ => {}
            }
        }
        assert_eq!(s.surfaces_count(), SESSION_SURFACES);
    }

    /// 部分消息断流：半消息 consumed=0 留缓冲，续喂全量即推进。
    #[test]
    fn partial_message_stream() {
        let mut s = new_session();
        let mut req = [0u8; 64];
        let n = encode_display_sync(&mut req, 1, 9).unwrap();
        let mut out = [0u8; 64];
        // 半消息（头 + 半参域）——干净断流
        let rep = s.feed(&req[..n - 2], &mut out).unwrap();
        assert_eq!(rep.consumed, 0);
        assert!(rep.is_skip());
        // 全量续喂——推进 + done 回执
        let rep2 = s.feed(&req[..n], &mut out).unwrap();
        assert_eq!(rep2.consumed, n);
        assert_eq!(rep2.out_len, 12);
    }

    /// 多消息单流推进：sync + get_registry 双消息同批——consumed =
    /// 双消息和 + 双回执并存。
    #[test]
    fn stream_multi_message() {
        let mut s = new_session();
        let sync = {
            let mut b = [0u8; 64];
            let n = encode_display_sync(&mut b, 1, 9).unwrap();
            b[..n].to_vec()
        };
        let gregr = {
            let mut b = [0u8; 64];
            let n = encode_display_get_registry(&mut b, 1, 2).unwrap();
            b[..n].to_vec()
        };
        let stream = stream_of(&[&sync, &gregr]);
        let mut out = [0u8; 512];
        let rep = s.feed(&stream, &mut out).unwrap();
        assert_eq!(rep.consumed, stream.len());
        // 回执 = sync done(12) + globals(36+28+28+32)
        assert_eq!(rep.out_len, 12 + 124);
        assert_eq!(s.table().lookup(9), Some(WlIface::Callback));
        assert_eq!(s.table().lookup(2), Some(WlIface::Registry));
    }

    /// destroy 生命周期：对象表 + 会话槽双清（id 不复用——表纪律）。
    #[test]
    fn destroy_surface_lifecycle() {
        let mut s = new_session();
        setup_registry(&mut s);
        let bind = {
            let mut b = [0u8; 64];
            let n = encode_registry_bind(&mut b, 2, 1, "wl_compositor", 4, 3).unwrap();
            b[..n].to_vec()
        };
        let cs = {
            let mut b = [0u8; 64];
            let n = encode_message(
                &mut b,
                3,
                compositor::REQ_CREATE_SURFACE,
                &[WlArg::NewId(0x21)],
            )
            .unwrap();
            b[..n].to_vec()
        };
        s.feed(&stream_of(&[&bind, &cs]), &mut [0u8; 16]).unwrap();
        assert_eq!(s.surfaces_count(), 1);
        let destroy = {
            let mut b = [0u8; 64];
            let n = encode_message(&mut b, 0x21, surf_ops::REQ_DESTROY, &[]).unwrap();
            b[..n].to_vec()
        };
        let rep = s.feed(&destroy, &mut [0u8; 16]).unwrap();
        assert_eq!(rep.consumed, destroy.len());
        assert_eq!(s.surfaces_count(), 0);
        assert_eq!(s.table().lookup(0x21), None);
        // 销毁后路由拒收（BadObject——不泄拓扑同面）
        assert_eq!(s.feed(&destroy, &mut [0u8; 16]), Err(CompError::BadObject));
    }

    /// attach 记账域 + 双 surface 几何注入（策略面钩子）。
    /// wl_shm 池域回环（M42-ELF5 桌面链批次）：create_pool（fd 占位字
    /// 记账）→ create_buffer → attach → commit —— 池记录批 + fd_need
    /// 计数 + buffer 几何随 commit 记录出域（客户端像素承载语义面）。
    #[test]
    fn shm_pool_buffer_commit_chain() {
        use crate::wayland::{shm, shm_pool};
        let mut s = new_session();
        let mut req = [0u8; 64];
        let n = encode_display_get_registry(&mut req, 1, 2).unwrap();
        s.feed(&req[..n], &mut [0u8; 512]).unwrap();
        // bind compositor（名 1 → new_id 3）+ bind wl_shm（名 3 → new_id 4）
        // + create_surface
        let mut batch = [0u8; 160];
        let mut bl = 0usize;
        bl += encode_registry_bind(&mut batch[bl..], 2, 1, "wl_compositor", 4, 3).unwrap();
        bl += encode_registry_bind(&mut batch[bl..], 2, 3, "wl_shm", 1, 4).unwrap();
        bl += encode_message(
            &mut batch[bl..],
            3,
            compositor::REQ_CREATE_SURFACE,
            &[WlArg::NewId(0x21)],
        )
        .unwrap();
        // create_pool(pool=5, fd 占位, size=256000) + create_buffer(buf=6)
        bl += encode_message(
            &mut batch[bl..],
            4,
            shm::REQ_CREATE_POOL,
            &[WlArg::NewId(5), WlArg::Fd(0), WlArg::Int(256000)],
        )
        .unwrap();
        bl += encode_message(
            &mut batch[bl..],
            5,
            shm_pool::REQ_CREATE_BUFFER,
            &[
                WlArg::NewId(6),
                WlArg::Int(0),
                WlArg::Int(320),
                WlArg::Int(200),
                WlArg::Int(1280),
                WlArg::Uint(1),
            ],
        )
        .unwrap();
        let mut out = [0u8; 512];
        let rep = s.feed(&batch[..bl], &mut out).unwrap();
        // 池记录批 + fd_need 对账（每 create_pool 恰一 fd）
        assert_eq!(rep.pools.n, 1);
        assert_eq!(rep.fd_need, 1);
        let pool = rep.pools.items[0].unwrap();
        assert_eq!(pool.pool_wl, 5);
        assert_eq!(pool.size, 256000);
        // 对象登记域：pool=5 ShmPool / buffer=6 Buffer
        assert_eq!(s.table().lookup(5), Some(WlIface::ShmPool));
        assert_eq!(s.table().lookup(6), Some(WlIface::Buffer));
        assert_eq!(s.buffers_count(), 1);
        // buffer 几何快照（取证面）
        let buf = s.buffer(6).unwrap();
        assert_eq!(buf.pool_wl, 5);
        assert_eq!(buf.offset, 0);
        assert_eq!(buf.w, 320);
        assert_eq!(buf.h, 200);
        assert_eq!(buf.stride, 1280);
        assert_eq!(buf.format, 1);
        // attach + commit → CommitRecord.buffer 携几何出域
        let mut batch2 = [0u8; 128];
        let mut bl2 = 0usize;
        bl2 += encode_message(
            &mut batch2[bl2..],
            0x21,
            surf_ops::REQ_ATTACH,
            &[WlArg::Object(6), WlArg::Int(0), WlArg::Int(0)],
        )
        .unwrap();
        bl2 += encode_message(
            &mut batch2[bl2..],
            0x21,
            surf_ops::REQ_DAMAGE,
            &[
                WlArg::Int(0),
                WlArg::Int(0),
                WlArg::Int(320),
                WlArg::Int(200),
            ],
        )
        .unwrap();
        bl2 += encode_surface_commit(&mut batch2[bl2..], 0x21).unwrap();
        s.set_geometry(0x21, PANE).unwrap();
        let rep2 = s.feed(&batch2[..bl2], &mut out).unwrap();
        let rec = rep2.commits.last_of(0x21).unwrap();
        let b = rec.buffer.expect("commit 须携 attach buffer 几何");
        assert_eq!(b.wl, 6);
        assert_eq!(b.w, 320);
        assert_eq!(b.stride, 1280);
        assert_eq!(
            rec.damage,
            Rect {
                x: 8,
                y: 56,
                w: 320,
                h: 200
            },
            "buffer 域损伤平移屏域 ∩ pane"
        );
    }

    /// wl_shm 负例域（M42-ELF5）：attach 未登记 buffer → BadObject；
    /// attach(null) 解附；buffer 槽满 → BufferFull；create_buffer 域外
    /// opcode 拒收。
    #[test]
    fn shm_negative_matrix() {
        use crate::wayland::{encode_surface_commit, shm, shm_pool};
        let mut s = new_session();
        let mut req = [0u8; 64];
        let n = encode_display_get_registry(&mut req, 1, 2).unwrap();
        s.feed(&req[..n], &mut [0u8; 512]).unwrap();
        let mut batch = [0u8; 128];
        let mut bl = 0usize;
        bl += encode_registry_bind(&mut batch[bl..], 2, 1, "wl_compositor", 4, 3).unwrap();
        bl += encode_message(
            &mut batch[bl..],
            3,
            compositor::REQ_CREATE_SURFACE,
            &[WlArg::NewId(0x21)],
        )
        .unwrap();
        bl += encode_registry_bind(&mut batch[bl..], 2, 3, "wl_shm", 1, 4).unwrap();
        bl += encode_message(
            &mut batch[bl..],
            4,
            shm::REQ_CREATE_POOL,
            &[WlArg::NewId(5), WlArg::Fd(0), WlArg::Int(4096)],
        )
        .unwrap();
        s.feed(&batch[..bl], &mut [0u8; 512]).unwrap();
        // attach 未登记 buffer（id 0x99）→ BadObject
        let mut bad = [0u8; 32];
        let n = encode_message(
            &mut bad,
            0x21,
            surf_ops::REQ_ATTACH,
            &[WlArg::Object(0x99), WlArg::Int(0), WlArg::Int(0)],
        )
        .unwrap();
        assert_eq!(
            s.feed(&bad[..n], &mut [0u8; 16]).map(|_| ()).unwrap_err(),
            CompError::BadObject
        );
        // buffer 槽满谱：8 buffer 入账后第 9 → BufferFull
        for k in 0..SESSION_BUFFERS {
            let mut one = [0u8; 48];
            let n = encode_message(
                &mut one,
                5,
                shm_pool::REQ_CREATE_BUFFER,
                &[
                    WlArg::NewId(0x40 + k as u32),
                    WlArg::Int(0),
                    WlArg::Int(8),
                    WlArg::Int(8),
                    WlArg::Int(32),
                    WlArg::Uint(1),
                ],
            )
            .unwrap();
            s.feed(&one[..n], &mut [0u8; 16]).unwrap();
        }
        let mut one = [0u8; 48];
        let n = encode_message(
            &mut one,
            5,
            shm_pool::REQ_CREATE_BUFFER,
            &[
                WlArg::NewId(0x50),
                WlArg::Int(0),
                WlArg::Int(8),
                WlArg::Int(8),
                WlArg::Int(32),
                WlArg::Uint(1),
            ],
        )
        .unwrap();
        assert_eq!(
            s.feed(&one[..n], &mut [0u8; 16]).map(|_| ()).unwrap_err(),
            CompError::BufferFull
        );
        // attach(null) 解附：attach 已登记 buffer → attach 0 → commit 无 buffer
        let mut pair = [0u8; 64];
        let mut pl = 0usize;
        pl += encode_message(
            &mut pair[pl..],
            0x21,
            surf_ops::REQ_ATTACH,
            &[WlArg::Object(0x40), WlArg::Int(0), WlArg::Int(0)],
        )
        .unwrap();
        pl += encode_message(
            &mut pair[pl..],
            0x21,
            surf_ops::REQ_ATTACH,
            &[WlArg::Object(0), WlArg::Int(0), WlArg::Int(0)],
        )
        .unwrap();
        pl += encode_surface_commit(&mut pair[pl..], 0x21).unwrap();
        s.set_geometry(0x21, PANE).unwrap();
        let rep = s.feed(&pair[..pl], &mut [0u8; 64]).unwrap();
        assert!(rep.commits.last_of(0x21).unwrap().buffer.is_none());
        // 域外 opcode：wl_shm resize 域外（wl_shm 无 resize——opcode 1 拒收）
        let mut bad = [0u8; 16];
        let n = encode_message(&mut bad, 4, 1, &[]).unwrap();
        assert_eq!(
            s.feed(&bad[..n], &mut [0u8; 16]).map(|_| ()).unwrap_err(),
            CompError::UnknownRequest
        );
    }
}
