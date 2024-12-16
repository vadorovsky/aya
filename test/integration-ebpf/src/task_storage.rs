#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::TaskStorage,
    cty::{c_long, c_void},
    macros::{btf_map, kprobe},
    programs::ProbeContext,
};

#[btf_map]
static STORE: TaskStorage<u32> = TaskStorage::new();

#[kprobe]
pub fn task_alloc(ctx: ProbeContext) -> u32 {
    match try_task_alloc(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_task_alloc(ctx: ProbeContext) -> Result<u32, c_long> {
    let task: *mut c_void = ctx.arg(0).ok_or(-1)?;

    unsafe { STORE.get_or_insert(task, &0) };

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
