#![expect(unused_crate_dependencies, reason = "used in lib")]

use anyhow::Result;
use clap::Parser as _;

fn main() -> Result<()> {
    let opts = aya_test_runner::Options::parse();
    let workspace_root = aya_test_runner::workspace_root()?;
    aya_test_runner::maybe_init_libbpf_submodule(&workspace_root)?;
    aya_test_runner::run(opts, &workspace_root)
}
