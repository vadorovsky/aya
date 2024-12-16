#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::{PerCpuArray, RingBuf},
    macros::{btf_map, uprobe},
    programs::ProbeContext,
};

use integration_common::ring_buf::Registers;

#[btf_map]
static RING_BUF: RingBuf<0> = RingBuf::new();

// Use a PerCpuArray to store the registers so that we can update the values from multiple CPUs
// without needing synchronization. Atomics exist [1], but aren't exposed.
//
// [1]: https://lwn.net/Articles/838884/
#[btf_map]
static REGISTERS: PerCpuArray<Registers, 1> = PerCpuArray::new();

#[uprobe]
pub fn ring_buf_test(ctx: ProbeContext) {
    let Registers { dropped, rejected } = match REGISTERS.get_ptr_mut(0) {
        Some(regs) => unsafe { &mut *regs },
        None => return,
    };
    let mut entry = match RING_BUF.reserve::<u64>(0) {
        Some(entry) => entry,
        None => {
            *dropped += 1;
            return;
        }
    };
    // Write the first argument to the function back out to RING_BUF if it is even,
    // otherwise increment the counter in REJECTED. This exercises discarding data.
    let arg: u64 = match ctx.arg(0) {
        Some(arg) => arg,
        None => return,
    };
    if arg % 2 == 0 {
        entry.write(arg);
        entry.submit(0);
    } else {
        *rejected += 1;
        entry.discard(0);
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}