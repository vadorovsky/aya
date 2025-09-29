#![no_std]
#![no_main]

#[cfg(not(test))]
extern crate ebpf_panic;

use aya_ebpf::{
    btf_maps::{Array, HashMap, LruHashMap},
    cty::c_long,
    macros::{btf_map, map, uprobe},
    maps::{Array as LegacyArray, HashMap as LegacyHashMap, LruHashMap as LegacyLruHashMap},
    programs::ProbeContext,
};
use integration_common::hash_map::GET_INDEX;

#[btf_map]
static RESULT: Array<u32, 3 /* max_elements */, 0> = Array::new();
#[btf_map]
static HASH_MAP: HashMap<u32, u32, 10 /* max_elements */, 0> = HashMap::new();
#[btf_map]
static LRU_HASH_MAP: LruHashMap<u32, u32, 10 /* max_elements */, 0> = LruHashMap::new();

#[map]
static RESULT_LEGACY: LegacyArray<u32> = LegacyArray::with_max_entries(3, 0);
#[map]
static HASH_MAP_LEGACY: LegacyHashMap<u32, u32> = LegacyHashMap::with_max_entries(10, 0);
#[map]
static LRU_HASH_MAP_LEGACY: LegacyLruHashMap<u32, u32> = LegacyLruHashMap::with_max_entries(10, 0);

macro_rules! define_result_set {
    (
        $result_map:ident,
        $result_set_fn:ident
    ) => {
        #[inline(always)]
        fn $result_set_fn(index: u32, value: u32) -> Result<(), c_long> {
            let ptr = $result_map.get_ptr_mut(index).ok_or(-1)?;
            let dst = unsafe { ptr.as_mut() };
            let dst_res = dst.ok_or(-1)?;
            *dst_res = value;
            Ok(())
        }
    };
}

define_result_set!(RESULT, result_set);
define_result_set!(RESULT_LEGACY, result_set_legacy);

macro_rules! define_hash_map_test {
    (
        $hash_map:ident,
        $result_set_fn:ident,
        $insert_prog:ident,
        $get_prog:ident
        $(,)?
    ) => {
        #[uprobe]
        fn $insert_prog(ctx: ProbeContext) -> Result<(), c_long> {
            let key = ctx.arg(0).ok_or(-1)?;
            let value = ctx.arg(1).ok_or(-1)?;
            $hash_map.insert(&key, &value, 0)?;
            Ok(())
        }

        #[uprobe]
        fn $get_prog(ctx: ProbeContext) -> Result<(), c_long> {
            let key = ctx.arg(0).ok_or(-1)?;
            let value = unsafe { $hash_map.get(&key).ok_or(-1)? };
            $result_set_fn(GET_INDEX, *value)?;
            Ok(())
        }
    };
}

define_hash_map_test!(HASH_MAP, result_set, hash_map_insert, hash_map_get);
define_hash_map_test!(
    HASH_MAP_LEGACY,
    result_set_legacy,
    hash_map_insert_legacy,
    hash_map_get_legacy,
);

define_hash_map_test!(
    LRU_HASH_MAP,
    result_set,
    lru_hash_map_insert,
    lru_hash_map_get
);
define_hash_map_test!(
    LRU_HASH_MAP_LEGACY,
    result_set_legacy,
    lru_hash_map_insert_legacy,
    lru_hash_map_get_legacy,
);
