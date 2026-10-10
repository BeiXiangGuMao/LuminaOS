//! 引导期信息布局。
//!
//! Bedrock 启动时由引导层（未来为 bedrock-boot）填写 [`BootInfo`]；
//! 本模块只定义数据布局与校验规则，不涉及页表等机器细节。

/// 引导层交给内核的信息块。字段语义与《指标与规范手册》第 2 章（Bedrock）对齐。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootInfo {
    /// 内核映像的物理基址（4 KiB 对齐）。
    pub kernel_phys_base: u64,
    /// 内核映像大小（字节，不含对齐填充）。
    pub kernel_size: u64,
    /// 物理地址到虚拟地址的线性映射偏移。
    pub phys_offset: u64,
    /// 帧缓冲物理基址；0 表示暂无图形输出。
    pub framebuffer_phys: u64,
    /// 帧缓冲宽度（像素）。
    pub framebuffer_width: u32,
    /// 帧缓冲高度（像素）。
    pub framebuffer_height: u32,
    /// 帧缓冲每行字节数（stride）。
    pub framebuffer_stride: u32,
}

/// 引导信息校验错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootError {
    /// 内核基址未按 4 KiB 对齐。
    KernelBaseMisaligned,
    /// 内核大小为 0。
    ZeroKernelSize,
    /// 帧缓冲 stride 小于宽度的最小行距。
    FramebufferStrideTooSmall,
}

impl BootInfo {
    /// 校验引导信息的结构不变式；Bedrock 启动路径的第一个断言。
    pub fn validate(&self) -> Result<(), BootError> {
        const PAGE: u64 = 4096;
        if !self.kernel_phys_base.is_multiple_of(PAGE) {
            return Err(BootError::KernelBaseMisaligned);
        }
        if self.kernel_size == 0 {
            return Err(BootError::ZeroKernelSize);
        }
        let has_fb = self.framebuffer_phys != 0 && self.framebuffer_width > 0;
        if has_fb && (self.framebuffer_stride as u64) < (self.framebuffer_width as u64) * 4 {
            return Err(BootError::FramebufferStrideTooSmall);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{BootError, BootInfo};

    fn sample() -> BootInfo {
        BootInfo {
            kernel_phys_base: 0x0020_0000,
            kernel_size: 0x0010_0000,
            phys_offset: 0xffff_8000_0000_0000,
            framebuffer_phys: 0xfd00_0000,
            framebuffer_width: 1920,
            framebuffer_height: 1080,
            framebuffer_stride: 1920 * 4,
        }
    }

    #[test]
    fn valid_boot_info_passes() {
        assert_eq!(sample().validate(), Ok(()));
    }

    #[test]
    fn rejects_misaligned_base_and_bad_stride() {
        let mut bad = sample();
        bad.kernel_phys_base = 0x123;
        assert_eq!(bad.validate(), Err(BootError::KernelBaseMisaligned));

        let mut bad = sample();
        bad.framebuffer_stride = 100;
        assert_eq!(bad.validate(), Err(BootError::FramebufferStrideTooSmall));
    }
}
