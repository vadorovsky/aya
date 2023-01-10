#![no_std]
#![no_main]

use aya_bpf::{
    macros::{map, uprobe},
    maps::RingBuf,
    programs::ProbeContext,
};

#[map]
static EVENTS: RingBuf = RingBuf::with_max_entries(256 * 1024, 0); // 256 KB

#[uprobe]
pub fn test_ringbuf(ctx: ProbeContext) -> u32 {
    match unsafe { try_test_ringbuf(ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_test_ringbuf(ctx: ProbeContext) -> Result<u32, u32> {
    let val: u64 = ctx.arg(0).ok_or(1u32)?;

    EVENTS.output(&val, 0).map_err(|_| 1u32)?;

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
