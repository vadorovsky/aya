use std::{fs::create_dir_all, path::Path};

use anyhow::{Context as _, Result};
use aya_tool::bindgen;

use crate::codegen::{Architecture, SysrootOptions};

pub(crate) fn codegen(opts: &SysrootOptions, libbpf_dir: &Path) -> Result<()> {
    let dir = Path::new("aya-netlink");
    let generated = dir.join("src/generated");
    create_dir_all(&generated)?;

    let builder = || {
        let mut bindgen = bindgen::user_builder()
            .header(dir.join("include/linux_wrapper.h").to_str().unwrap())
            .clang_args(["-I", libbpf_dir.join("include/uapi").to_str().unwrap()])
            .clang_args(["-I", libbpf_dir.join("include").to_str().unwrap()]);

        let types = [
            // NETLINK
            "ifinfomsg",
            "tcmsg",
            "nlmsgerr_attrs",
        ];

        let vars = [
            // NETLINK
            "NLMSG_ALIGNTO",
            "IFLA_XDP_FD",
            "TCA_KIND",
            "TCA_OPTIONS",
            "TCA_BPF_FD",
            "TCA_BPF_NAME",
            "TCA_BPF_FLAGS",
            "TCA_BPF_FLAG_ACT_DIRECT",
            "XDP_FLAGS_.*",
            "TC_H_MAJ_MASK",
            "TC_H_MIN_MASK",
            "TC_H_UNSPEC",
            "TC_H_ROOT",
            "TC_H_INGRESS",
            "TC_H_CLSACT",
            "TC_H_MIN_PRIORITY",
            "TC_H_MIN_INGRESS",
            "TC_H_MIN_EGRESS",
        ];

        for x in &types {
            bindgen = bindgen.allowlist_type(x);
        }

        for x in &vars {
            bindgen = bindgen.allowlist_var(x);
        }

        bindgen
    };

    for arch in Architecture::supported() {
        let mut bindgen = builder();

        // Set target triple. This will set the right flags (which you can see
        // running clang -target=X  -E - -dM </dev/null)
        let target = arch.target();
        bindgen = bindgen.clang_args(&["-target", target]);

        // Set the sysroot. This is needed to ensure that the correct arch
        // specific headers are imported.
        let sysroot = arch.sysroot(opts);
        bindgen = bindgen.clang_args(["-I", sysroot.to_str().unwrap()]);

        let bindings = bindgen.generate().context("bindgen failed")?;

        // write the bindings, with the original helpers removed
        bindings.write_to_file(generated.join(format!("linux_bindings_{arch}.rs")))?;
    }

    Ok(())
}
