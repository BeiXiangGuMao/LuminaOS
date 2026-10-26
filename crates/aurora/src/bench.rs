//! bench —— AF-P01 宿主框架冷启动基准桩（M32-B1）。
//!
//! AF-P01 口径（指标手册第 16 章）：框架冷启动开销 ≤120 ms（P0 硬门禁）。
//! 本模块落**宿主框架面基准桩**（M32 计划 ④ 裁决：记录型 + 合理余量闸；
//! 端到端基准随用户态进程基础设施挂账）：
//!
//! - 库面（no_std 可编译，零时钟依赖）：[`load_manifests`]（段① 清单装载）
//!   与 [`cold_start_path`]（规范冷启动路径组合：清单装载 → 注册折叠 →
//!   Registered→Foreground 全迁移路径），分段归属由 [`ColdStartStages`]
//!   结构化记录——计时由宿主注入（内核 t81 / 后续端到端基准可复用同一路径）；
//! - 宿主测试面（`cfg(test)`）：`std::time::Instant` 分段计时 + 实测记录行 +
//!   ≤120 ms 口径闸（宿主框架面远小于端到端预算——闸意义为口径显形 +
//!   回归哨兵）。
//!
//! 分段口径（冷启动路径三段，与 [`cold_start_path`] 执行序一致）：
//! ① 清单装载（`LuappManifest::validate` 逐声明——应用框架入口语义）；
//! ② 注册折叠（`AppRegistry::fold_register`——含能力承接授予）；③ 生命周期
//! 迁移（Registered→Launching→Foreground，每应用 2 拍，迁移唯一入口
//! `AppRegistry::transition`——AF-P06）。

use crate::sdk::{AppDecl, AppRegistry, SdkError};
use crate::Lifecycle;
use alloc::vec::Vec;

/// 冷启动路径分段计数（结构化记录面——分段归属单一事实源）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColdStartStages {
    /// 段① 清单装载（`validate` 逐声明）。
    pub loads: usize,
    /// 段② 注册折叠（声明数——含能力承接授予）。
    pub folds: usize,
    /// 段③ 生命周期迁移拍数（Registered→Launching→Foreground，每应用 2 拍）。
    pub transitions: usize,
}

/// 段① 清单装载：逐声明 `validate`（应用框架入口语义；装载即校验）。
///
/// 返回装载清单数；任一声明非法显形 [`SdkError::Manifest`]（fail-visible，
/// 不放行部分子集）。
pub fn load_manifests(decls: &[AppDecl]) -> Result<usize, SdkError> {
    for d in decls {
        d.manifest.validate().map_err(SdkError::Manifest)?;
    }
    Ok(decls.len())
}

/// AF-P01 规范冷启动路径：段① 清单装载 → 段② 注册折叠 → 段③
/// Registered→Foreground 全迁移路径（经 Launching 中转——合法迁移唯一路径）。
///
/// 返回（应用槽位号表〔与声明顺序同序，首空槽确定性分配〕，分段计数）。
/// 迁移经 [`AppRegistry::transition`] 唯一入口（AF-P06 全迁移经框架），
/// 合法迁移后回调按态派发；非法迁移显形 [`SdkError::IllegalTransition`]
/// （AF-P03 拦截 100%）。
pub fn cold_start_path(
    decls: &[AppDecl],
    registry: &mut AppRegistry,
) -> Result<(Vec<usize>, ColdStartStages), SdkError> {
    let loads = load_manifests(decls)?;
    let slots = registry.fold_register(decls)?;
    for &s in &slots {
        registry.transition(s, Lifecycle::Launching)?;
        registry.transition(s, Lifecycle::Foreground)?;
    }
    let n = slots.len();
    Ok((
        slots,
        ColdStartStages {
            loads,
            folds: decls.len(),
            transitions: n * 2,
        },
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    // no_std crate 宿主测试面：std 显式引入（计时 Instant + println! 记录行——
    // 仅 cfg(test) 构建生效，库本体保持 no_std 纪律）
    extern crate std;
    use super::{cold_start_path, load_manifests};
    use crate::sdk::{AppDecl, AppRegistry, APP_CAPACITY};
    use crate::{Lifecycle, LuappManifest};
    use alloc::vec::Vec;
    use std::{println, time::Instant};

    /// AF-P01 口径闸：≤120 ms（指标手册第 16 章，P0 硬门禁）。
    const BUDGET_NS: u128 = 120_000_000;

    /// 构造声明批：`org.lumina.app<k>` × 每应用 `caps_per_app` 条能力声明
    /// （能力对象 id = 注册表槽位号——对象 id 仅作授予锚，批内可重复同资源段）。
    fn make_decls(n: usize, caps_per_app: usize) -> Vec<AppDecl> {
        (0..n)
            .map(|k| AppDecl {
                manifest: LuappManifest {
                    app_id: alloc::format!("org.lumina.app{k}"),
                    display_name: alloc::format!("App{k}"),
                    version: "0.1.0".into(),
                    capabilities: (0..caps_per_app)
                        .map(|c| alloc::format!("cap.fs.zone{c}_app{k}.read"))
                        .collect(),
                },
                hooks: Default::default(),
            })
            .collect()
    }

    /// 分段计时 + 记录行 + 口径闸（记录型基准桩主循环）。
    ///
    /// 分段计时（装载 / 折叠 / 迁移）与组合规范路径（`cold_start_path`——
    /// 总闸口径：框架冷启动路径整体）双面执行，分段计数交叉对账。
    fn run_cold_start_bench(n_apps: usize, caps_per_app: usize) {
        let decls = make_decls(n_apps, caps_per_app);
        let total_caps = n_apps * caps_per_app;

        // 分段计时：段① 清单装载
        let t0 = Instant::now();
        let loads = load_manifests(&decls).unwrap();
        let load_ns = t0.elapsed().as_nanos();

        // 分段计时：段② 注册折叠（含能力承接授予）
        let mut reg = AppRegistry::new();
        let t1 = Instant::now();
        let slots = reg.fold_register(&decls).unwrap();
        let fold_ns = t1.elapsed().as_nanos();

        // 分段计时：段③ Registered→Foreground 全迁移路径（每应用 2 拍）
        let t2 = Instant::now();
        for &s in &slots {
            reg.transition(s, Lifecycle::Launching).unwrap();
            reg.transition(s, Lifecycle::Foreground).unwrap();
        }
        let trans_ns = t2.elapsed().as_nanos();

        // 组合规范路径（新注册表同声明批——总闸口径：冷启动路径整体）
        let mut reg2 = AppRegistry::new();
        let t3 = Instant::now();
        let (_, stages) = cold_start_path(&decls, &mut reg2).unwrap();
        let total_ns = t3.elapsed().as_nanos();

        // 记录行（记录型口径——cargo test -- --nocapture 可见；CI 日志留档）
        let (s_loads, s_folds, s_trans) = (stages.loads, stages.folds, stages.transitions);
        println!(
            "AF-P01-BENCH apps={n_apps} caps={total_caps} load={load_ns}ns fold={fold_ns}ns \
             transition={trans_ns}ns total={total_ns}ns budget={BUDGET_NS}ns \
             stages={s_loads}/{s_folds}/{s_trans} ok=true"
        );

        // 口径闸（AF-P01 ≤120 ms——合理余量闸：宿主框架面远小于端到端预算）
        assert!(
            total_ns <= BUDGET_NS,
            "AF-P01 cold start {total_ns}ns > budget {BUDGET_NS}ns"
        );
        // 分段计数交叉对账（组合路径与手拼分段同源）
        assert_eq!(stages.loads, loads, "load stage count mismatch");
        assert_eq!(stages.folds, slots.len(), "fold stage count mismatch");
        assert_eq!(
            stages.transitions,
            slots.len() * 2,
            "transition stage count mismatch"
        );
    }

    /// 最小注册路径基准：单应用单能力。
    #[test]
    fn afp01_cold_start_single_app() {
        run_cold_start_bench(1, 1);
    }

    /// 满载注册表基准：`APP_CAPACITY` 应用 × 3 能力（48 能力贴界 64 槽内）。
    #[test]
    fn afp01_cold_start_full_registry() {
        run_cold_start_bench(APP_CAPACITY, 3);
    }
}
