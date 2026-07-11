#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    EbpfContext as _,
    btf_maps::TaskStorage,
    macros::{btf_map, lsm, map},
    maps::Array,
    programs::LsmContext,
};
use integration_common::local_storage::SENTINEL;

#[btf_map]
static TASK_STORAGE: TaskStorage<u64> = TaskStorage::new();

// Userspace writes the test's tgid to index 0 so the probe only records storage
// for this process, avoiding contamination from unrelated task accesses.
#[map]
static TARGET_TGID: Array<u32> = Array::with_max_entries(1, 0);

#[lsm(hook = "bprm_check")]
fn task_storage_test(ctx: LsmContext) -> i32 {
    // `bprm_check(bprm)` has 1 argument; the prior LSM program's return value
    // is exposed as a synthetic last argument.
    let retval: i32 = ctx.arg(1);
    if TARGET_TGID.get(0).copied() != Some(ctx.tgid()) {
        return retval;
    }
    let storage = unsafe { TASK_STORAGE.get_or_insert_ptr_mut_current(None) };
    if !storage.is_null() {
        unsafe { *storage = SENTINEL }
    }
    retval
}
