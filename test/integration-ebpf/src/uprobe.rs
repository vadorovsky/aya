#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::{
    cty::c_char,
    helpers::bpf_probe_read_user,
    macros::{map, uprobe},
    maps::RingBuf,
    programs::ProbeContext,
};

#[cfg(not(test))]
extern crate ebpf_panic;

#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(0, 0);

#[uprobe]
fn uprobe_atoi(ctx: ProbeContext) {
    let Some(s): Option<*const c_char> = ctx.arg(0) else {
        return;
    };
    let Ok(s) = (unsafe { bpf_probe_read_user(s) }) else {
        return;
    };
    // let s = unsafe { &*s };
    let _res = RING_BUF.output::<[u8]>(s.to_ne_bytes(), 0);
}
