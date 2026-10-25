//! sdk —— Aurora SDK 最小服务面（M32-S1）。
//!
//! 两半结构（ROADMAP M32-S1 界定）：
//!
//! - **App 声明式注册折叠**：[`AppDecl`]（清单 + 生命周期回调）经
//!   [`AppRegistry::fold_register`] 单环折叠入定容注册表——两遍扫描保原子性
//!   （第一遍全量闸：清单校验 + 注册表/能力容量，任一非法整批拒绝零注册，
//!   仿 V-P05「全拒不放行部分子集」与 M32-A1 `grant_manifest` 同构；第二遍
//!   逐声明 装载 → 能力承接授予〔`perm::PermCenter` 承接桥〕→ 登记）；
//! - **意图路由骨架**：[`IntentRouter`] 定容路由表（`intent.<域>.<动作>`
//!   命名域闸 [`check_intent_schema`] + 未注册意图显形拒收
//!   [`SdkError::UnknownIntent`]）。
//!
//! 生命周期纪律（AF-P06 全迁移经框架 + AF-P03 拦截 100%）：迁移唯一入口
//! [`AppRegistry::transition`]——`AppRuntime` 状态机校验拒绝显形
//! [`SdkError::IllegalTransition`]，合法迁移后派发应用回调
//! [`LifecycleHooks`]；**终态权限收口搭车面**（M32-S1 登记）：Terminated
//! 迁移后应用能力槽位即撤销（`perm` 四相④撤销语义同源），路由派发对终态
//! 应用显形 [`SdkError::AppTerminated`]（路由本体保留供审计）。
//!
//! v0 口径登记：注册表 / 路由表 write-once（槽位回收随 SDK 服务面后续
//! 批次）；能力对象 id = 注册表槽位号（应用命名空间锚——对象谱系随内核
//! 进程面再议）；路由 owner 语义为审计锚 + 终态派发闸。

use crate::perm::{PermCenter, PermError};
use crate::{AppRuntime, Lifecycle, LuappManifest, ManifestError};
use alloc::{string::String, vec::Vec};
use vanguard::CAPACITY;

/// SDK 服务面错误集（fail-visible，无静默吞并）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdkError {
    /// 清单校验失败（`ManifestError` 透传）。
    Manifest(ManifestError),
    /// 能力授予失败（`perm` 面透传）。
    Perm(PermError),
    /// 应用槽位不存在（越界或未注册）。
    NoSuchApp,
    /// 应用已终态（终态应用不可再登记路由；其路由派发显形拒收）。
    AppTerminated,
    /// 注册表满（声明数 > 空闲应用槽）。
    RegistryFull,
    /// 非法生命周期迁移（`AppRuntime` 状态机拦截显形——AF-P03）。
    IllegalTransition,
    /// 意图命名域 schema 非法（`intent.<域>.<动作>` 三段闸）。
    BadIntent,
    /// 重复路由注册（同名意图已占用路由槽）。
    DuplicateRoute,
    /// 路由表满。
    RouterFull,
    /// 未注册意图（派发显形拒收——路由骨架核心闸）。
    UnknownIntent,
}

/// 应用生命周期回调集（声明式注册面；全部可选——v0 骨架零回调合法）。
#[derive(Debug, Clone, Copy, Default)]
pub struct LifecycleHooks {
    /// 装载回调（Registered → Launching 成功迁移后派发）。
    pub on_launch: Option<fn()>,
    /// 进前台回调（→ Foreground）。
    pub on_foreground: Option<fn()>,
    /// 退后台回调（→ Background）。
    pub on_background: Option<fn()>,
    /// 挂起回调（→ Suspended）。
    pub on_suspend: Option<fn()>,
    /// 终止回调（→ Terminated，派发后随终态权限收口）。
    pub on_terminate: Option<fn()>,
}

/// 应用声明：清单 + 生命周期回调（注册折叠的输入单元）。
#[derive(Debug, Clone)]
pub struct AppDecl {
    /// `.luapp` 清单（注册时全量校验）。
    pub manifest: LuappManifest,
    /// 生命周期回调集。
    pub hooks: LifecycleHooks,
}

/// 注册表条目（审计面；字段只读纪律——经 [`AppRegistry`] 面操作）。
#[derive(Debug)]
pub struct AppEntry {
    /// 清单原样保留（注册时校验过的快照）。
    pub manifest: LuappManifest,
    /// 生命周期运行时（Registered 起点）。
    pub runtime: AppRuntime,
    /// 生命周期回调集。
    pub hooks: LifecycleHooks,
    /// 能力槽位表（`perm` 承接桥分配，与清单声明同序；终态撤销后清账）。
    pub cap_slots: Vec<usize>,
}

/// 校验意图命名域 schema：`intent.<域>.<动作>` 恰三段。
///
/// 第 1 段恒为 `intent`（意图命名域前缀），第 2/3 段为域与动作（非空）；
/// 全段字符集与 `perm::check_schema` 同规（小写字母 / 数字 / 下划线）——
/// 命名域纪律单一事实源分立（cap 四段 / intent 三段，前缀分段各表其义）。
pub fn check_intent_schema(name: &str) -> Result<(), SdkError> {
    let segs: Vec<&str> = name.split('.').collect();
    let ok = segs.len() == 3
        && segs[0] == "intent"
        && segs.iter().all(|s| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        });
    if ok {
        Ok(())
    } else {
        Err(SdkError::BadIntent)
    }
}

/// 意图路由表容量。
pub const ROUTE_CAPACITY: usize = 32;

/// 路由解析产物：（路由槽位号，owner 应用槽，处理器）。
pub type ResolvedRoute = (usize, usize, fn());

/// 意图路由骨架：定容路由表（意图名 → 处理器 + owner 应用槽）。
struct Route {
    /// 意图名（schema 闸后的规范形态，表内唯一）。
    name: String,
    /// owner 应用槽位号（注册表索引——审计锚 + 终态派发闸依据）。
    owner: usize,
    /// 处理器。
    handler: fn(),
}

/// 意图路由骨架（可独立使用；应用关联面见 [`AppRegistry::route_intent`]）。
pub struct IntentRouter {
    routes: Vec<Option<Route>>,
}

impl IntentRouter {
    /// 创建空路由表（定容 [`ROUTE_CAPACITY`] 槽）。
    pub fn new() -> Self {
        Self {
            routes: Vec::from_iter((0..ROUTE_CAPACITY).map(|_| None)),
        }
    }

    /// 已占用路由槽数。
    pub fn used(&self) -> usize {
        self.routes.iter().filter(|r| r.is_some()).count()
    }

    /// 登记路由：schema 闸 + 唯一性闸 + 定容闸，返回路由槽位号。
    pub fn route(&mut self, name: &str, owner: usize, handler: fn()) -> Result<usize, SdkError> {
        check_intent_schema(name)?;
        if self.find(name).is_some() {
            return Err(SdkError::DuplicateRoute);
        }
        let slot = self
            .routes
            .iter()
            .position(Option::is_none)
            .ok_or(SdkError::RouterFull)?;
        self.routes[slot] = Some(Route {
            name: String::from(name),
            owner,
            handler,
        });
        Ok(slot)
    }

    /// 解析意图：返回（路由槽位号，owner 应用槽，处理器）。
    ///
    /// 未注册意图显形 [`SdkError::UnknownIntent`]（拒收不留痕）。
    pub fn resolve(&self, name: &str) -> Result<ResolvedRoute, SdkError> {
        let slot = self.find(name).ok_or(SdkError::UnknownIntent)?;
        let r = self
            .routes
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(SdkError::UnknownIntent)?;
        Ok((slot, r.owner, r.handler))
    }

    /// 纯路由派发（解析 + 调用；无 owner 活性闸——应用关联闸在注册表面）。
    pub fn dispatch(&self, name: &str) -> Result<usize, SdkError> {
        let (slot, _, handler) = self.resolve(name)?;
        handler();
        Ok(slot)
    }

    fn find(&self, name: &str) -> Option<usize> {
        self.routes
            .iter()
            .position(|r| matches!(r, Some(rt) if rt.name == name))
    }
}

impl Default for IntentRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// 注册表容量。
pub const APP_CAPACITY: usize = 16;

/// App 注册表：声明式注册折叠 + 生命周期框架面 + 意图路由（SDK 服务面单环）。
pub struct AppRegistry {
    perm: PermCenter,
    apps: Vec<Option<AppEntry>>,
    router: IntentRouter,
}

impl AppRegistry {
    /// 创建空注册表（定容 [`APP_CAPACITY`] 应用槽 + 空路由表 + 空权限中心）。
    pub fn new() -> Self {
        Self {
            perm: PermCenter::new(),
            apps: Vec::from_iter((0..APP_CAPACITY).map(|_| None)),
            router: IntentRouter::new(),
        }
    }

    /// 单应用注册（声明式）：[`AppRegistry::fold_register`] 的单元素特例。
    pub fn register(&mut self, decl: AppDecl) -> Result<usize, SdkError> {
        let slots = self.fold_register(core::slice::from_ref(&decl))?;
        match slots.first() {
            Some(s) => Ok(*s),
            None => Err(SdkError::RegistryFull),
        }
    }

    /// App 声明式注册折叠：单环折叠声明批 → 定容注册表（SDK 注册面唯一入口）。
    ///
    /// 两遍扫描保原子性——第一遍全量闸（逐声明清单校验 → 注册表容量 → 能力
    /// 容量，确定性失败序），任一非法即整批拒绝且零注册；第二遍逐声明
    /// 装载 → 能力承接授予（`perm::PermCenter::grant_manifest`）→ 登记。
    /// 返回槽位号表（与声明顺序同序，首空槽确定性分配）。
    pub fn fold_register(&mut self, decls: &[AppDecl]) -> Result<Vec<usize>, SdkError> {
        // 第一遍：全量闸（零注册）
        let mut total_caps = 0usize;
        for d in decls {
            d.manifest.validate().map_err(SdkError::Manifest)?;
            total_caps += d.manifest.capabilities.len();
        }
        let free_apps = self.apps.iter().filter(|a| a.is_none()).count();
        if decls.len() > free_apps {
            return Err(SdkError::RegistryFull);
        }
        let free_caps = CAPACITY - self.perm.used();
        if total_caps > free_caps {
            return Err(SdkError::Perm(PermError::NoSuchSlot));
        }
        // 第二遍：单环折叠（闸已全过，装载/授予/登记不再失败）
        let mut slots = Vec::new();
        for d in decls {
            let slot = self
                .apps
                .iter()
                .position(Option::is_none)
                .ok_or(SdkError::RegistryFull)?;
            let cap_slots = self
                .perm
                .grant_manifest(&d.manifest, slot as u64)
                .map_err(SdkError::Perm)?;
            self.apps[slot] = Some(AppEntry {
                manifest: d.manifest.clone(),
                runtime: AppRuntime::new(),
                hooks: d.hooks,
                cap_slots,
            });
            slots.push(slot);
        }
        Ok(slots)
    }

    /// 生命周期迁移（全迁移经框架——AF-P06 唯一入口）。
    ///
    /// `AppRuntime` 状态机校验（非法迁移显形 [`SdkError::IllegalTransition`]，
    /// 拦截率 100%——AF-P03）→ 合法迁移后派发应用回调 [`LifecycleHooks`]；
    /// **终态权限收口**：Terminated 迁移后撤销该应用全部能力槽位
    /// （`perm` 四相④同源语义）并清账条目槽位表。
    pub fn transition(&mut self, app: usize, to: Lifecycle) -> Result<(), SdkError> {
        // 相一：状态机校验 + 回调与槽位快照（借出即还，收口面另行借权）
        let (hook, cap_slots) = {
            let entry = self
                .apps
                .get_mut(app)
                .and_then(Option::as_mut)
                .ok_or(SdkError::NoSuchApp)?;
            entry
                .runtime
                .transition(to)
                .map_err(|_| SdkError::IllegalTransition)?;
            let hook = match to {
                Lifecycle::Registered => None,
                Lifecycle::Launching => entry.hooks.on_launch,
                Lifecycle::Foreground => entry.hooks.on_foreground,
                Lifecycle::Background => entry.hooks.on_background,
                Lifecycle::Suspended => entry.hooks.on_suspend,
                Lifecycle::Terminated => entry.hooks.on_terminate,
            };
            (
                hook,
                if to == Lifecycle::Terminated {
                    Some(core::mem::take(&mut entry.cap_slots))
                } else {
                    None
                },
            )
        };
        // 相二：回调派发（handler 不捕获环境，无借用交叠）
        if let Some(f) = hook {
            f();
        }
        // 相三：终态权限收口（撤销尽max语义——逐槽撤销，任一意外失败显形；
        // 槽位源自 grant_manifest 且注册表为 perm 唯一写者，失败不可达）
        if let Some(slots) = cap_slots {
            let mut first_err = None;
            for s in slots.iter().rev() {
                if let Err(e) = self.perm.revoke(*s) {
                    first_err = first_err.or(Some(e));
                }
            }
            if let Some(e) = first_err {
                return Err(SdkError::Perm(e));
            }
        }
        Ok(())
    }

    /// 应用当前生命周期状态。
    pub fn state(&self, app: usize) -> Result<Lifecycle, SdkError> {
        self.apps
            .get(app)
            .and_then(Option::as_ref)
            .map(|e| e.runtime.state())
            .ok_or(SdkError::NoSuchApp)
    }

    /// 以 app_id 查注册槽位号（未注册返回 `None`）。
    pub fn find(&self, app_id: &str) -> Option<usize> {
        self.apps
            .iter()
            .position(|a| a.as_ref().is_some_and(|e| e.manifest.app_id == app_id))
    }

    /// 已注册应用数。
    pub fn count(&self) -> usize {
        self.apps.iter().filter(|a| a.is_some()).count()
    }

    /// 为已注册且未终态的应用登记意图路由（owner 活性闸在注册表面）。
    pub fn route_intent(
        &mut self,
        app: usize,
        name: &str,
        handler: fn(),
    ) -> Result<usize, SdkError> {
        let state = self.state(app)?;
        if state == Lifecycle::Terminated {
            return Err(SdkError::AppTerminated);
        }
        self.router.route(name, app, handler)
    }

    /// 意图派发（注册表面）：路由解析 + owner 活性闸（终态应用显形拒收）。
    pub fn dispatch(&self, name: &str) -> Result<usize, SdkError> {
        let (slot, owner, handler) = self.router.resolve(name)?;
        let state = self.state(owner)?;
        if state == Lifecycle::Terminated {
            return Err(SdkError::AppTerminated);
        }
        handler();
        Ok(slot)
    }

    /// 已占用路由槽数。
    pub fn routes_used(&self) -> usize {
        self.router.used()
    }

    /// 权限面透传：运行时检查（`perm` 四相③语义同源）。
    pub fn perm_check(&self, slot: usize, action: &str) -> Result<(), PermError> {
        self.perm.check(slot, action)
    }

    /// 权限面透传：已占用能力槽位数。
    pub fn perm_used(&self) -> usize {
        self.perm.used()
    }
}

impl Default for AppRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        check_intent_schema, AppDecl, AppRegistry, Lifecycle, LifecycleHooks, LuappManifest,
        SdkError, APP_CAPACITY, ROUTE_CAPACITY,
    };
    use crate::perm::PermError;
    use alloc::{format, string::String, vec, vec::Vec};
    use core::sync::atomic::{AtomicUsize, Ordering};

    // —— 测试回调计数器（静态自持无捕获 fn，各测试断言独立口径）——
    static LAUNCH_HITS: AtomicUsize = AtomicUsize::new(0);
    static FOREGROUND_HITS: AtomicUsize = AtomicUsize::new(0);
    static BACKGROUND_HITS: AtomicUsize = AtomicUsize::new(0);
    static SUSPEND_HITS: AtomicUsize = AtomicUsize::new(0);
    static TERMINATE_HITS: AtomicUsize = AtomicUsize::new(0);
    static DISPATCH_HITS: AtomicUsize = AtomicUsize::new(0);

    fn on_launch_fn() {
        LAUNCH_HITS.fetch_add(1, Ordering::SeqCst);
    }
    fn on_foreground_fn() {
        FOREGROUND_HITS.fetch_add(1, Ordering::SeqCst);
    }
    fn on_background_fn() {
        BACKGROUND_HITS.fetch_add(1, Ordering::SeqCst);
    }
    fn on_suspend_fn() {
        SUSPEND_HITS.fetch_add(1, Ordering::SeqCst);
    }
    fn on_terminate_fn() {
        TERMINATE_HITS.fetch_add(1, Ordering::SeqCst);
    }
    fn dispatch_fn() {
        DISPATCH_HITS.fetch_add(1, Ordering::SeqCst);
    }

    fn hooks_all() -> LifecycleHooks {
        LifecycleHooks {
            on_launch: Some(on_launch_fn),
            on_foreground: Some(on_foreground_fn),
            on_background: Some(on_background_fn),
            on_suspend: Some(on_suspend_fn),
            on_terminate: Some(on_terminate_fn),
        }
    }

    fn decl(app_id: &str, caps: &[&str], hooks: LifecycleHooks) -> AppDecl {
        AppDecl {
            manifest: LuappManifest {
                app_id: String::from(app_id),
                display_name: String::from(app_id),
                version: String::from("1.0.0"),
                capabilities: caps.iter().map(|c| String::from(*c)).collect(),
            },
            hooks,
        }
    }

    /// 声明式注册折叠：单环批量注册槽位确定性 + 清单/回调快照保真。
    #[test]
    fn fold_register_single_loop() {
        let mut reg = AppRegistry::new();
        let decls = vec![
            decl("org.lumina.notes", &["cap.fs.documents.read"], hooks_all()),
            decl(
                "org.lumina.paint",
                &["cap.ipc.channel.send", "cap.net.socket.bind"],
                hooks_all(),
            ),
            decl(
                "org.lumina.term",
                &["cap.fs.documents.read"],
                LifecycleHooks::default(),
            ),
        ];
        let slots = reg.fold_register(&decls).expect("fold");
        assert_eq!(slots, vec![0, 1, 2], "槽位与声明顺序同序");
        assert_eq!(reg.count(), 3);
        assert_eq!(reg.find("org.lumina.paint"), Some(1));
        assert_eq!(reg.find("org.lumina.absent"), None);
        // 生命周期快照：Registered 起点 + 回调集保真（零回调合法）
        assert_eq!(reg.state(0), Ok(Lifecycle::Registered));
        assert_eq!(reg.state(2), Ok(Lifecycle::Registered));
        // 能力承接：对象 id = 注册表槽位号（应用命名空间锚）
        assert_eq!(reg.perm_used(), 4, "3 声明 + 2 声明 = 4 槽");
        assert_eq!(reg.perm_check(0, "read"), Ok(()));
        assert_eq!(reg.perm_check(1, "send"), Ok(()));
        assert_eq!(reg.perm_check(2, "bind"), Ok(()));
        assert_eq!(reg.perm_check(3, "read"), Ok(()));
    }

    /// 注册折叠原子性：任一声明非法整批拒绝零注册（V-P05 同构）+ 双容量闸。
    #[test]
    fn fold_register_atomic_gates() {
        // 清单闸：app_id 非法 → 整批拒绝零注册（计数器零派发）
        let mut reg = AppRegistry::new();
        let bad = vec![
            decl(
                "org.lumina.ok",
                &["cap.fs.documents.read"],
                LifecycleHooks::default(),
            ),
            decl(
                "BadApp",
                &["cap.fs.documents.read"],
                LifecycleHooks::default(),
            ),
        ];
        assert_eq!(
            reg.fold_register(&bad),
            Err(SdkError::Manifest(crate::ManifestError::BadAppId))
        );
        assert_eq!(reg.count(), 0, "零部分注册");
        assert_eq!(reg.perm_used(), 0);
        // 能力 schema 闸（清单扩容闸透传）
        let bad_cap = vec![
            decl(
                "org.lumina.ok",
                &["cap.fs.documents.read"],
                LifecycleHooks::default(),
            ),
            decl(
                "org.lumina.bad",
                &["fs.documents.read"],
                LifecycleHooks::default(),
            ),
        ];
        assert_eq!(
            reg.fold_register(&bad_cap),
            Err(SdkError::Manifest(crate::ManifestError::BadCapability))
        );
        assert_eq!(reg.count(), 0);
        // 注册表容量闸：17 应用 > 16 槽 → 整批拒绝
        let many: Vec<AppDecl> = (0..APP_CAPACITY + 1)
            .map(|i| {
                decl(
                    &format!("org.lumina.a{i}"),
                    &["cap.fs.documents.read"],
                    LifecycleHooks::default(),
                )
            })
            .collect();
        assert_eq!(reg.fold_register(&many), Err(SdkError::RegistryFull));
        assert_eq!(reg.count(), 0);
        // 能力容量闸：13 应用 × 5 能力 = 65 > 64 → 整批拒绝；12 × 5 = 60 ≤ 64 → 全落
        let heavy: Vec<AppDecl> = (0..13)
            .map(|i| {
                decl(
                    &format!("org.lumina.h{i}"),
                    &[
                        "cap.fs.documents.read",
                        "cap.fs.documents.write",
                        "cap.ipc.channel.send",
                        "cap.ipc.channel.recv",
                        "cap.net.socket.bind",
                    ],
                    LifecycleHooks::default(),
                )
            })
            .collect();
        assert_eq!(
            reg.fold_register(&heavy),
            Err(SdkError::Perm(PermError::NoSuchSlot))
        );
        assert_eq!(reg.count(), 0, "能力容量整批拒绝零注册");
        let fit: Vec<AppDecl> = (0..12)
            .map(|i| {
                decl(
                    &format!("org.lumina.f{i}"),
                    &[
                        "cap.fs.documents.read",
                        "cap.fs.documents.write",
                        "cap.ipc.channel.send",
                        "cap.ipc.channel.recv",
                        "cap.net.socket.bind",
                    ],
                    LifecycleHooks::default(),
                )
            })
            .collect();
        assert_eq!(reg.fold_register(&fit).expect("12×5=60 贴界通过").len(), 12);
        assert_eq!(reg.count(), 12);
        assert_eq!(reg.perm_used(), 60);
    }

    /// 生命周期框架面：全迁移经框架（回调按态派发）+ 非法迁移拦截显形零派发。
    #[test]
    fn lifecycle_transition_with_hooks() {
        let mut reg = AppRegistry::new();
        let app = reg
            .register(decl(
                "org.lumina.notes",
                &["cap.fs.documents.read"],
                hooks_all(),
            ))
            .expect("register");
        // 全迁移合法步进 + 回调逐态派发
        reg.transition(app, Lifecycle::Launching).expect("launch");
        reg.transition(app, Lifecycle::Foreground).expect("fg");
        reg.transition(app, Lifecycle::Background).expect("bg");
        reg.transition(app, Lifecycle::Suspended).expect("suspend");
        reg.transition(app, Lifecycle::Background).expect("resume");
        reg.transition(app, Lifecycle::Foreground)
            .expect("fg again");
        reg.transition(app, Lifecycle::Background)
            .expect("bg before terminate");
        reg.transition(app, Lifecycle::Terminated)
            .expect("terminate");
        assert_eq!(reg.state(app), Ok(Lifecycle::Terminated));
        assert_eq!(LAUNCH_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(FOREGROUND_HITS.load(Ordering::SeqCst), 2);
        assert_eq!(
            BACKGROUND_HITS.load(Ordering::SeqCst),
            3,
            "bg→suspend→resume→fg→bg 共三次退后台"
        );
        assert_eq!(SUSPEND_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(TERMINATE_HITS.load(Ordering::SeqCst), 1);
        // 非法迁移拦截显形（AF-P03）：Registered 直达 Foreground / Foreground 直达 Suspended
        let mut reg2 = AppRegistry::new();
        let app2 = reg2
            .register(decl(
                "org.lumina.term2",
                &["cap.fs.documents.read"],
                hooks_all(),
            ))
            .expect("register");
        assert_eq!(
            reg2.transition(app2, Lifecycle::Foreground),
            Err(SdkError::IllegalTransition)
        );
        assert_eq!(FOREGROUND_HITS.load(Ordering::SeqCst), 2, "拦截零派发");
        reg2.transition(app2, Lifecycle::Launching).expect("launch");
        assert_eq!(
            reg2.transition(app2, Lifecycle::Background),
            Err(SdkError::IllegalTransition)
        );
        assert_eq!(BACKGROUND_HITS.load(Ordering::SeqCst), 3, "拦截零派发");
        // 终态为汇：Terminated 后任何迁移显形
        reg2.transition(app2, Lifecycle::Foreground).expect("fg");
        reg2.transition(app2, Lifecycle::Background)
            .expect("bg before terminate");
        reg2.transition(app2, Lifecycle::Terminated)
            .expect("terminate");
        assert_eq!(
            reg2.transition(app2, Lifecycle::Launching),
            Err(SdkError::IllegalTransition)
        );
        // 不存在应用：NoSuchApp
        assert_eq!(
            reg2.transition(99, Lifecycle::Launching),
            Err(SdkError::NoSuchApp)
        );
        assert_eq!(reg2.state(99), Err(SdkError::NoSuchApp));
    }

    /// 终态权限收口搭车面：Terminated 后应用能力槽位全撤销 + 条目槽位表清账。
    #[test]
    fn terminate_revokes_capabilities() {
        let mut reg = AppRegistry::new();
        let app = reg
            .register(decl(
                "org.lumina.notes",
                &["cap.fs.documents.read", "cap.fs.documents.write"],
                LifecycleHooks::default(),
            ))
            .expect("register");
        let _ = reg
            .register(decl(
                "org.lumina.term",
                &["cap.ipc.channel.send"],
                LifecycleHooks::default(),
            ))
            .expect("register2");
        assert_eq!(reg.perm_used(), 3);
        // 终态路径：Registered → Launching → Terminated（Foreground 不可直达 Terminated）
        reg.transition(app, Lifecycle::Launching).expect("launch");
        reg.transition(app, Lifecycle::Terminated)
            .expect("terminate");
        assert_eq!(reg.perm_used(), 1, "终态撤销后仅剩 app2 能力");
        // 撤销后访问显形（perm 四相④）：原槽位 read 检查显形 SlotEmpty
        assert_eq!(reg.perm_check(0, "read"), Err(PermError::SlotEmpty));
        assert_eq!(reg.perm_check(1, "write"), Err(PermError::SlotEmpty));
        // 邻应用能力不受牵连（隔离不变式）
        assert_eq!(reg.perm_check(2, "send"), Ok(()));
    }

    /// 意图命名域闸：合法态 + 非法态全枚举（前缀 / 段数 / 空段 / 字符集）。
    #[test]
    fn intent_schema_gate() {
        // 合法态：规范三段
        assert_eq!(check_intent_schema("intent.share.text"), Ok(()));
        assert_eq!(check_intent_schema("intent.fs.open"), Ok(()));
        assert_eq!(check_intent_schema("intent.nav_2.go"), Ok(()));
        // 前缀闸
        assert_eq!(
            check_intent_schema("intents.share.text"),
            Err(SdkError::BadIntent)
        );
        assert_eq!(
            check_intent_schema("INTENT.share.text"),
            Err(SdkError::BadIntent)
        );
        // 段数闸：两段（缺动作）与四段（越深）均显形
        assert_eq!(
            check_intent_schema("intent.share"),
            Err(SdkError::BadIntent)
        );
        assert_eq!(check_intent_schema("share.text"), Err(SdkError::BadIntent));
        assert_eq!(
            check_intent_schema("intent.share.text.now"),
            Err(SdkError::BadIntent)
        );
        // 空段与字符集闸
        assert_eq!(
            check_intent_schema("intent..text"),
            Err(SdkError::BadIntent)
        );
        assert_eq!(
            check_intent_schema("intent.Share.text"),
            Err(SdkError::BadIntent)
        );
        assert_eq!(
            check_intent_schema("intent.share.tex-t"),
            Err(SdkError::BadIntent)
        );
        assert_eq!(
            check_intent_schema("intent.share."),
            Err(SdkError::BadIntent)
        );
        assert_eq!(check_intent_schema(""), Err(SdkError::BadIntent));
    }

    /// 意图路由骨架：登记 → 派发命中 → 未注册显形拒收 + 唯一性/定容闸 + owner 活性闸。
    #[test]
    fn intent_route_and_dispatch() {
        let mut reg = AppRegistry::new();
        let app = reg
            .register(decl(
                "org.lumina.notes",
                &["cap.fs.documents.read"],
                LifecycleHooks::default(),
            ))
            .expect("register");
        // 登记路由 + 派发命中
        let r0 = reg
            .route_intent(app, "intent.share.text", dispatch_fn)
            .expect("route");
        assert_eq!(r0, 0);
        let r1 = reg
            .route_intent(app, "intent.fs.open", dispatch_fn)
            .expect("route2");
        assert_eq!(r1, 1);
        assert_eq!(reg.routes_used(), 2);
        assert_eq!(reg.dispatch("intent.share.text"), Ok(0));
        assert_eq!(DISPATCH_HITS.load(Ordering::SeqCst), 1);
        assert_eq!(reg.dispatch("intent.fs.open"), Ok(1));
        assert_eq!(DISPATCH_HITS.load(Ordering::SeqCst), 2);
        // 未注册意图显形拒收（路由骨架核心闸）
        assert_eq!(
            reg.dispatch("intent.absent.now"),
            Err(SdkError::UnknownIntent)
        );
        assert_eq!(DISPATCH_HITS.load(Ordering::SeqCst), 2, "拒收零调用");
        // schema 非法意图登记显形
        assert_eq!(
            reg.route_intent(app, "intents.x.y", dispatch_fn),
            Err(SdkError::BadIntent)
        );
        // 重复路由注册显形
        assert_eq!(
            reg.route_intent(app, "intent.share.text", dispatch_fn),
            Err(SdkError::DuplicateRoute)
        );
        // 不存在应用登记路由显形
        assert_eq!(
            reg.route_intent(99, "intent.ghost.route", dispatch_fn),
            Err(SdkError::NoSuchApp)
        );
        // owner 活性闸：终态应用不可再登记路由；其存量路由派发显形拒收
        let app2 = reg
            .register(decl(
                "org.lumina.ghost",
                &["cap.ipc.channel.send"],
                LifecycleHooks::default(),
            ))
            .expect("register2");
        let _ = reg
            .route_intent(app2, "intent.ghost.ping", dispatch_fn)
            .expect("route3");
        reg.transition(app2, Lifecycle::Launching).expect("launch");
        reg.transition(app2, Lifecycle::Terminated)
            .expect("terminate");
        assert_eq!(
            reg.route_intent(app2, "intent.ghost.new", dispatch_fn),
            Err(SdkError::AppTerminated),
            "终态应用不可登记路由"
        );
        assert_eq!(
            reg.dispatch("intent.ghost.ping"),
            Err(SdkError::AppTerminated),
            "终态 owner 派发显形拒收"
        );
        assert_eq!(DISPATCH_HITS.load(Ordering::SeqCst), 2, "拒收零调用");
        // 定容闸：填满 32 路由槽后显形 RouterFull
        let mut reg3 = AppRegistry::new();
        let a3 = reg3
            .register(decl(
                "org.lumina.router",
                &["cap.fs.documents.read"],
                LifecycleHooks::default(),
            ))
            .expect("register");
        for i in 0..ROUTE_CAPACITY {
            let name = format!("intent.r{i}.go");
            assert_eq!(
                reg3.route_intent(a3, &name, dispatch_fn),
                Ok(i),
                "fill route {i}"
            );
        }
        assert_eq!(
            reg3.route_intent(a3, "intent.overflow.x", dispatch_fn),
            Err(SdkError::RouterFull),
            "满表拒绝"
        );
    }
}
