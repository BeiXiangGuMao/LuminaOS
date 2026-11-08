//! Prism 计算域 —— Vulkan 计算着色器**软件语义面**（M40-PRP04 首割）。
//!
//! PR-P04 口径 = 「Vulkan 1.3 计算着色器可用」（手册 v1.0/v1.2 与 Prism
//! 细则双源一致——docs/PDF-RECON.md §二 2.11 勘误既录）。GPU 域零起点
//! 裁决：「语义面先行、电气面挂账」M34-P4 手法同款——本面落**软件
//! 语义面 v0**：
//! - **SPIR-V 二进制解析壳**：魔数/版本/字边界/段遍历 fail-visible 防
//!   线（bedrock::elf 十三目先例同款纪律；no_std 零堆零 unsafe）；
//! - **计算管线登记面**：定容表 fail-visible 三闸（SurfaceTable 注册
//!   表纪律同款——登记/重复拒/更新/注销）；
//! - **标量求算核**：GLSLstd450 受支持算子子集逐位确定性感（同参同
//!   初值任何机器逐位一致——ripple「GPU 确定性」口径同源）；数值验收
//!   挂环境 B 不虚报（PDF-RECON §五③ 口径）。
//!
//! 硬件 Vulkan 队列（ICD/真机 GPU）挂账不变如实登记——QEMU TCG 无
//! Vulkan ICD，真机窗口裁决不变（ROADMAP 远线 M40+）。

#![forbid(unsafe_code)]

/// SPIR-V 魔数（spec §2.3：little-endian 0x07230203）。
pub const SPIRV_MAGIC: u32 = 0x0723_0203;
/// SPIR-V 版本上限（1.3——PR-P04 口径域；>1.3 拒收 fail-visible）。
pub const SPIRV_VERSION_MAX: u8 = 3;
/// 计算管线登记表容量（定容 fail-visible——SurfaceTable 同量级先例）。
pub const PIPELINE_CAP: usize = 8;
/// 管线名字节上限（定容；越域截断拒绝）。
pub const NAME_MAX: usize = 24;

/// 解析错误域（fail-visible 全谱显形——不静默不虚报）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// 输入为空或非 4 字节倍数（SPIR-V 以 32 位字为最小单元）。
    BadLength,
    /// 魔数不符（非 SPIR-V 模块）。
    BadMagic,
    /// 版本域超上限（>1.3 拒收——PR-P04 口径域）。
    BadVersion,
    /// 头域生成器/序号边界越域。
    BadHeader,
    /// 指令字数域为 0 或越出模块边界（WordCount 域防线）。
    BadWordCount,
    /// OpEntryPoint 缺席（计算模块必须含入口点）。
    NoEntryPoint,
    /// 入口点执行模型非 GLCompute（5）。
    NotCompute,
    /// 名字域含非 UTF-8 或越界。
    BadName,
}

/// 入口点定容名（零堆——解析壳产出 owned 域；≤ [`NAME_MAX`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedName {
    buf: [u8; NAME_MAX],
    len: u8,
}

impl FixedName {
    /// as_str 域（UTF-8 已由解析面校验）。
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len as usize]).unwrap_or("")
    }
}

/// 计算模块解析产出（SPIR-V 头 + 入口点摘要）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputeModule {
    /// SPIR-V 版本（minor 域；major 恒 1）。
    pub version_minor: u8,
    /// 生成器 id（头域透传——取证面）。
    pub generator: u16,
    /// 入口点名字域（OpEntryPoint 字面量，≤ [`NAME_MAX`]）。
    pub entry_name: FixedName,
    /// OpEntryPoint 后随的 id 域（入口点接口 id 个数 = WordCount-3-len）。
    pub interface_ids: u32,
}

/// SPIR-V 计算模块解析壳（M40-PRP04）：头五字（magic/版本/生成器/
/// 绑定/序号）+ 指令流遍历（WordCount 域防线）+ OpEntryPoint 抽取
/// （执行模型 GLCompute=5 判定）。**解析面零分配零 unsafe**——产出
/// 借用输入字流。
pub fn parse_compute_module(words: &[u32]) -> Result<ComputeModule, ParseError> {
    if words.len() < 5 {
        return Err(ParseError::BadLength);
    }
    if words[0] != SPIRV_MAGIC {
        return Err(ParseError::BadMagic);
    }
    // 版本域：word1 = [major:8][minor:8][patch:16]——major 恒 1、minor ≤ 3。
    let version_word = words[1];
    let major = ((version_word >> 24) & 0xFF) as u8;
    let minor = ((version_word >> 16) & 0xFF) as u8;
    if major != 1 || minor > SPIRV_VERSION_MAX {
        return Err(ParseError::BadVersion);
    }
    let generator = (version_word & 0xFFFF) as u16;
    if words[2] == 0 {
        return Err(ParseError::BadHeader); // generator high = 0 保留域
    }
    let _bound = words[3]; // bound 域（id 上界；解析壳不消费——透传）
    let _schema = words[4]; // schema = 0（spec 定值；非 0 拒收域留待段面）
                            // 指令流遍历（word 5 起）：WordCount 高 16 位 + OpCode 低 16 位。
    let mut i = 5usize;
    let mut entry: Option<(FixedName, u32)> = None;
    while i < words.len() {
        let instr = words[i];
        let wc = (instr >> 16) as usize;
        let opcode = instr & 0xFFFF;
        if wc == 0 || i + wc > words.len() {
            return Err(ParseError::BadWordCount);
        }
        // OpEntryPoint = 15：[wc|15][exec_model][entry_id][name...][ids...]
        if opcode == 15 && wc >= 4 {
            let exec_model = words[i + 1];
            // GLCompute = 5（spec §3.3 Execution Model）
            if exec_model == 5 {
                // 名字域自 i+3 起的 u32 字面量串（每字 4 字节 LE、NUL 收尾）
                let name_words = &words[i + 3..i + wc];
                let mut nbuf = [0u8; NAME_MAX * 4 + 4];
                let mut nlen = 0usize;
                for w in name_words {
                    for b in w.to_le_bytes() {
                        if nlen < nbuf.len() {
                            nbuf[nlen] = b;
                            nlen += 1;
                        }
                    }
                }
                // NUL 截断
                let cut = nbuf[..nlen].iter().position(|&b| b == 0).unwrap_or(nlen);
                if cut == 0 || cut > NAME_MAX {
                    return Err(ParseError::BadName);
                }
                let _ = core::str::from_utf8(&nbuf[..cut]).map_err(|_| ParseError::BadName)?;
                let mut fname = FixedName {
                    buf: [0; NAME_MAX],
                    len: cut as u8,
                };
                fname.buf[..cut].copy_from_slice(&nbuf[..cut]);
                let interface_ids = (wc - 3 - name_words.len()) as u32;
                entry = Some((fname, interface_ids));
            }
        }
        i += wc;
    }
    match entry {
        Some((entry_name, interface_ids)) => Ok(ComputeModule {
            version_minor: minor,
            generator,
            entry_name,
            interface_ids,
        }),
        None => Err(ParseError::NoEntryPoint),
    }
}

// ---- 计算管线登记面（定容表 fail-visible 三闸） ----

/// 登记表满容（fail-visible——SurfaceTableFull 同款）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineTableFull;

/// 计算管线登记条目：名字 + 工作组域（local_size x/y/z）+ 入口 id。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineEntry {
    /// 管线 id（登记面铸号——单调自 1 起，0 = NULL 哨兵）。
    pub id: u32,
    /// 入口点名字（解析产出域）。
    pub entry: &'static str,
    /// 工作组 x 维（local_size_x——v0 登记面，派发面挂账）。
    pub wg_x: u32,
    /// 工作组 y 维。
    pub wg_y: u32,
    /// 工作组 z 维。
    pub wg_z: u32,
}

/// 计算管线登记表（定容 [`PIPELINE_CAP`] 槽——fail-visible 三闸：
/// 登记/重复拒/注销；释放槽复用 + id 单调铸号）。
pub struct PipelineTable {
    slots: [Option<PipelineEntry>; PIPELINE_CAP],
    next_id: u32,
}

impl Default for PipelineTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PipelineTable {
    /// 空表。
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; PIPELINE_CAP],
            next_id: 1,
        }
    }

    /// 登记（id 单调铸号；重复 entry 拒——fail-visible）。
    pub fn install(
        &mut self,
        entry: &'static str,
        wg_x: u32,
        wg_y: u32,
        wg_z: u32,
    ) -> Result<u32, PipelineTableFull> {
        if self.slots.iter().flatten().any(|e| e.entry == entry) {
            return Err(PipelineTableFull); // 重复拒（语义域复用满容哨兵）
        }
        let Some(slot) = self.slots.iter_mut().find(|s| s.is_none()) else {
            return Err(PipelineTableFull);
        };
        let id = self.next_id;
        self.next_id += 1;
        *slot = Some(PipelineEntry {
            id,
            entry,
            wg_x,
            wg_y,
            wg_z,
        });
        Ok(id)
    }

    /// 注销（id 命中摘槽；缺席幂等成功——fail-visible 双向）。
    pub fn remove(&mut self, id: u32) -> bool {
        for slot in self.slots.iter_mut() {
            if slot.is_some_and(|e| e.id == id) {
                *slot = None;
                return true;
            }
        }
        false
    }

    /// 查询（id → 条目快照）。
    pub fn get(&self, id: u32) -> Option<PipelineEntry> {
        self.slots.iter().flatten().find(|e| e.id == id).copied()
    }

    /// 在环计数。
    pub fn len(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// 空表判定。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---- 标量求算核（GLSLstd450 受支持算子子集——逐位确定性） ----

/// GLSLstd450 算子子集（M40-PRP04 求算核域——逐位确定性感：同参同
/// 初值任何机器逐位一致；浮点域 v0 整数算子面，浮点算子挂账随 GPU
/// 域批次——软/硬逐位一致性口径环境 B 挂账）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op450 {
    /// GLSLstd450 Round? 不在 v0 域——整数域：SAbs（5）。
    SAbs,
    /// SSign（7）：符号提取（-1/0/1）。
    SSign,
    /// UMin（39）。
    UMin,
    /// UMax(40)。
    UMax,
    /// UMulExtended 不在 v0 域——IMulHi 替代登记面（v0 简化域：低
    /// 32 位积——溢出域偏差如实登记）。
    IMul,
}

/// 求算核执行（GLSLstd450 子集逐位确定性感——纯函数零副作用）。
pub fn eval_op450(op: Op450, a: u32, b: u32) -> u32 {
    match op {
        Op450::SAbs => {
            let s = a as i32;
            s.unsigned_abs()
        }
        Op450::SSign => match a as i32 {
            x if x < 0 => (-1i32) as u32,
            0 => 0,
            _ => 1,
        },
        Op450::UMin => a.min(b),
        Op450::UMax => a.max(b),
        Op450::IMul => a.wrapping_mul(b),
    }
}

// -------------------------------------------------------- 宿主测试面

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec as StdVec;

    /// 测试定容字节缓冲（min_module 产出域）。
    struct FixedBuf {
        buf: [u8; 128],
        len: usize,
    }
    impl FixedBuf {
        fn new() -> Self {
            Self {
                buf: [0; 128],
                len: 0,
            }
        }
        fn push(&mut self, b: u8) {
            if self.len < 128 {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
        fn as_slice(&self) -> &[u8] {
            &self.buf[..self.len]
        }
    }

    fn to_words(bytes: &[u8]) -> StdVec<u32> {
        let mut out = StdVec::new();
        let mut i = 0;
        while i + 4 <= bytes.len() {
            out.push(u32::from_le_bytes([
                bytes[i],
                bytes[i + 1],
                bytes[i + 2],
                bytes[i + 3],
            ]));
            i += 4;
        }
        out
    }

    /// 最小 GLCompute SPIR-V 模块骨架（魔数 + 版本 1.3 + entry）。
    fn min_module(exec_model: u32, name: &str) -> FixedBuf {
        let mut w = FixedBuf::new();
        let push = |w: &mut FixedBuf, x: u32| {
            for b in x.to_le_bytes() {
                w.push(b);
            }
        };
        push(&mut w, SPIRV_MAGIC);
        push(&mut w, (1 << 24) | (3 << 16)); // 1.3.0
        push(&mut w, 0x0001_0006); // generator
        push(&mut w, 4); // bound
        push(&mut w, 0); // schema
                         // OpEntryPoint(15) wc=5: [wc|15][model][id]['m','a','i','n'][0]
        push(&mut w, (5u32 << 16) | 15);
        push(&mut w, exec_model);
        push(&mut w, 1); // entry id
        for b in name.as_bytes() {
            w.push(*b);
        }
        w.push(0);
        push(&mut w, 0); // NUL 字对齐补位
        w
    }

    #[test]
    fn parse_min_compute_module() {
        let bytes = min_module(5, "main");
        let words = to_words(bytes.as_slice());
        let m = parse_compute_module(&words).expect("parse");
        assert_eq!(m.version_minor, 3);
        assert_eq!(m.entry_name.as_str(), "main");
        assert_eq!(m.interface_ids, 0); // wc=5 - 3 - 2 name words（"main\0"+补位字）
    }

    #[test]
    fn parse_fail_visible_matrix() {
        // 空输入
        assert_eq!(parse_compute_module(&[]), Err(ParseError::BadLength));
        // 魔数
        assert_eq!(
            parse_compute_module(&[0, 0, 0, 0, 0]),
            Err(ParseError::BadMagic)
        );
        // 版本 1.4 越域
        let mut words: StdVec<u32> = vec![SPIRV_MAGIC, (1 << 24) | (4 << 16), 1, 4, 0];
        words.resize(10, 0);
        assert_eq!(parse_compute_module(&words), Err(ParseError::BadVersion));
        // fragment 模型（非 compute）→ NoEntryPoint
        let bytes = min_module(4, "main");
        let words = to_words(bytes.as_slice());
        assert_eq!(parse_compute_module(&words), Err(ParseError::NoEntryPoint));
    }

    #[test]
    fn pipeline_table_gates() {
        let mut t = PipelineTable::new();
        let id1 = t.install("main", 8, 1, 1).expect("install");
        assert_eq!(id1, 1);
        // 重复拒
        assert!(t.install("main", 8, 1, 1).is_err());
        let id2 = t.install("second", 4, 4, 1).expect("install");
        assert_eq!(id2, 2);
        assert_eq!(t.len(), 2);
        let e = t.get(2).expect("get");
        assert_eq!((e.wg_x, e.wg_y, e.wg_z), (4, 4, 1));
        // 注销 + 槽复用
        assert!(t.remove(1));
        assert!(!t.remove(1)); // 幂等缺度
        let id3 = t.install("third", 1, 1, 1).expect("reuse");
        assert_eq!(id3, 3); // id 单调铸号
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn op450_bit_determinism() {
        // 逐位确定性感锚：同参恒同值（纯函数——无浮点/无环境域）
        assert_eq!(eval_op450(Op450::SAbs, (-5i32) as u32, 0), 5);
        assert_eq!(eval_op450(Op450::SSign, (-7i32) as u32, 0), (-1i32) as u32);
        assert_eq!(eval_op450(Op450::SSign, 0, 0), 0);
        assert_eq!(eval_op450(Op450::SSign, 9, 0), 1);
        assert_eq!(eval_op450(Op450::UMin, 3, 7), 3);
        assert_eq!(eval_op450(Op450::UMax, 3, 7), 7);
        assert_eq!(eval_op450(Op450::IMul, 6, 7), 42);
        // 回绕域（wrapping——溢出偏差如实登记域）
        assert_eq!(eval_op450(Op450::IMul, u32::MAX, 2), (-2i32) as u32);
    }

    #[test]
    fn parse_bad_word_count_defense() {
        // WordCount=0 防线（指令字数域 0 拒收）
        let words = [
            SPIRV_MAGIC,
            (1 << 24) | (3 << 16),
            1,
            4,
            0,
            0x0000_000F,
            5,
            1,
        ];
        assert_eq!(parse_compute_module(&words), Err(ParseError::BadWordCount));
    }
}
