//! Tests ability of different program types to use eBPF helpers.

#![no_std]
#![no_main]

use aya_ebpf::{
    cty::c_long,
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task},
    macros::cgroup_skb,
    programs::SkBuffContext,
};

/// [`cgroup_skb`] programs support the following helpers:
///
/// - [`bpf_get_current_comm`]
/// - [`bpf_get_current_pid_tgid`]
/// - [`bpf_get_current_task`]
/// - [`bpf_probe_read_user`]
/// - [`bpf_probe_read_kernel`]
#[cgroup_skb]
pub fn test_cgroup_skb(ctx: SkBuffContext) -> i32 {
    match try_test_cgroup_skb(ctx) {
        Ok(res) => res,
        Err(_) => 1,
    }
}

fn try_test_cgroup_skb(ctx: SkBuffContext) -> Result<i32, c_long> {
    let _comm = bpf_get_current_comm();
    let _pid_tgid = bpf_get_current_pid_tgid();

    Ok(1)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
