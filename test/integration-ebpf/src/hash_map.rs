#![no_std]
#![no_main]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    btf_maps::{Array, HashMap},
    cty::c_long,
    macros::{btf_map, map, uprobe},
    maps::{Array as LegacyArray, HashMap as LegacyHashMap},
    programs::ProbeContext,
};
use integration_common::hash_map::GET_INDEX;

#[btf_map]
static RESULT: Array<u32, 3 /* max_elements */, 0> = Array::new();
#[btf_map]
static HASH_MAP: HashMap<u32, u32, 10 /* max_elements */, 0> = HashMap::new();

#[map]
static RESULT_LEGACY: LegacyArray<u32> = LegacyArray::with_max_entries(3, 0);
#[map]
static HASH_MAP_LEGACY: LegacyHashMap<u32, u32> = LegacyHashMap::with_max_entries(10, 0);

macro_rules! define_hash_map_test {
    (
        $result_map:ident,
        $hash_map:ident,
        $result_set_fn:ident,
        $insert_prog:ident,
        $get_prog:ident
        $(,)?
    ) => {
        #[inline(always)]
        fn $result_set_fn(index: u32, value: u32) -> Result<(), c_long> {
            let ptr = $result_map.get_ptr_mut(index).ok_or(-1)?;
            let dst = unsafe { ptr.as_mut() };
            let dst_res = dst.ok_or(-1)?;
            *dst_res = value;
            Ok(())
        }

        #[uprobe]
        pub fn $insert_prog(ctx: ProbeContext) -> Result<(), c_long> {
            let key = ctx.arg(0).ok_or(-1)?;
            let value = ctx.arg(1).ok_or(-1)?;
            $hash_map.insert(&key, &value, 0)?;
            Ok(())
        }

        #[uprobe]
        pub fn $get_prog(ctx: ProbeContext) -> Result<(), c_long> {
            let key = ctx.arg(0).ok_or(-1)?;
            let value = unsafe { $hash_map.get(&key).ok_or(-1)? };
            $result_set_fn(GET_INDEX, *value)?;
            Ok(())
        }
    };
}

define_hash_map_test!(RESULT, HASH_MAP, result_set, insert, get);
define_hash_map_test!(
    RESULT_LEGACY,
    HASH_MAP_LEGACY,
    result_set_legacy,
    insert_legacy,
    get_legacy,
);
