use core::{cell::UnsafeCell, marker::PhantomData, mem, ptr::NonNull};

use aya_bpf_bindings::helpers::bpf_map_lookup_elem;
use aya_bpf_cty::c_void;

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_HASH_OF_MAPS},
    maps::PinningType,
};

#[repr(transparent)]
pub struct HashOfMaps<K, V> {
    def: UnsafeCell<bpf_map_def>,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

unsafe impl<K: Sync, V: Sync> Sync for HashOfMaps<K, V> {}

impl<K, V> HashOfMaps<K, V> {
    pub const fn with_max_entries(max_entries: u32, flags: u32) -> HashOfMaps<K, V> {
        HashOfMaps {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_HASH_OF_MAPS,
                key_size: mem::size_of::<K>() as u32,
                value_size: mem::size_of::<V>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    pub const fn pinned(max_entries: u32, flags: u32) -> HashOfMaps<K, V> {
        HashOfMaps {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_HASH_OF_MAPS,
                key_size: mem::size_of::<K>() as u32,
                value_size: mem::size_of::<V>() as u32,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: PinningType::ByName as u32,
            }),
            _k: PhantomData,
            _v: PhantomData,
        }
    }

    #[inline(always)]
    pub unsafe fn get(&self, key: &K) -> Option<&V> {
        self.get_ptr(key).map(|p| &*p)
    }

    #[inline(always)]
    pub fn get_ptr(&self, key: &K) -> Option<*const V> {
        self.get_ptr_mut(key).map(|p| p as *const V)
    }

    #[inline(always)]
    pub fn get_ptr_mut(&self, key: &K) -> Option<*mut V> {
        unsafe {
            let value =
                bpf_map_lookup_elem(self.def.get() as *mut _, key as *const _ as *const c_void);
            // FIXME: alignment
            NonNull::new(value as *mut V).map(|p| p.as_ptr())
        }
    }
}
