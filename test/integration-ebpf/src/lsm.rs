#![no_std]
#![no_main]

use aya_ebpf::{macros::lsm, programs::LsmContext};

#[lsm(hook = "file_open")]
pub fn file_open(_ctx: LsmContext) -> i32 {
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
