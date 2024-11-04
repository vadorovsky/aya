#![no_std]
#![no_main]

use aya_ebpf::{bpf_seq_printf, macros::iter, programs::IterContext};

#[iter(target = "tcp")]
pub fn iter_tcp4(ctx: IterContext) -> i32 {
    bpf_seq_printf!(ctx.seq_file(), c"foo");
    return 0;
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
