use std::{env, process::Command};

use which::which;
use xtask::AYA_BUILD_INTEGRATION_BPF;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary. This would be
/// better expressed by [artifact-dependencies][bindeps] but issues such as
/// https://github.com/rust-lang/cargo/issues/12385 make their use impractical for the time being.
///
/// This file implements an imperfect solution: it causes cargo to rebuild the crate whenever the
/// mtime of `which bpf-linker` changes. Note that possibility that a new bpf-linker is added to
/// $PATH ahead of the one used as the cache key still exists. Solving this in the general case
/// would require rebuild-if-changed-env=PATH *and* rebuild-if-changed={every-directory-in-PATH}
/// which would likely mean far too much cache invalidation.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
fn check_bpf_linker() {
    println!("cargo:rerun-if-env-changed={}", AYA_BUILD_INTEGRATION_BPF);

    let build_integration_bpf = env::var(AYA_BUILD_INTEGRATION_BPF)
        .as_deref()
        .map(str::parse)
        .map(Result::unwrap)
        .unwrap_or_default();

    if build_integration_bpf {
        let bpf_linker = which("bpf-linker").unwrap();
        println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
    }
}

/// "C-shim" is a C module which provides utility functions for accessing
/// kernel data structures. We link it to the eBPF programs written in Rust
/// and call its functions through FFI. It's a workaround for lack of
/// possibility to emit BTF relocations in rustc/bpf-linker.
fn build_c_shim() {
    println!("cargo:rerun-if-changed=c-shim/vmlinux.c");
    println!("cargo:rerun-if-changed=c-shim/vmlinux.h");

    let out_dir = env::var("OUT_DIR").unwrap();
    let _ = Command::new("clang")
        .arg("-I")
        .arg("src/")
        .arg("-O2")
        .arg("-emit-llvm")
        .arg("-target")
        .arg("bpf")
        .arg("-c")
        .arg("-g")
        .arg("src/vmlinux.c")
        .arg("-o")
        .arg(format!("{out_dir}/vmlinux.o"))
        .status()
        .expect("Failed to compile the C-shim");

    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=link-arg={out_dir}/vmlinux.o");
}

fn main() {
    check_bpf_linker();
    build_c_shim();
}
