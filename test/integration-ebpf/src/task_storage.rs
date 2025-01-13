#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::task_struct,
    btf_maps::TaskStorage,
    cty::c_long,
    macros::{btf_map, fentry},
    programs::FEntryContext,
};

#[btf_map]
static STORE: TaskStorage<u32> = TaskStorage::new();

#[fentry]
pub fn task_alloc(ctx: FEntryContext) -> u32 {
    match try_task_alloc(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_task_alloc(ctx: FEntryContext) -> Result<u32, c_long> {
    unsafe {
        let task: *const task_struct = ctx.arg(0);
        STORE.get_or_insert(task as *mut _, &420);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
