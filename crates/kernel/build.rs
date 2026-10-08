//! 内核链接定制：把 multiboot1 版 LLD 链接参数注入构建。
//!
//! 链接脚本与本文件同目录（linker.ld）；重定位模型/代码模型由
//! targets/x86_64-lumina.json 目标定义承载。

use std::env;

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    println!("cargo:rustc-link-arg=-T{manifest}/linker.ld");
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-changed=build.rs");
}
