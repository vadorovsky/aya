use core::{cell::UnsafeCell, ptr::NonNull};

use aya_ebpf_bindings::bindings::bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH;

use crate::{
    bindings::bpf_map_type::{BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_LRU_HASH},
    btf_map_def,
    cty::{c_long, c_void},
    helpers::{bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_update_elem},
};

btf_map_def!(HashMapDef, BPF_MAP_TYPE_HASH);

#[repr(transparent)]
pub struct HashMap<K, V, const M: usize, const F: usize = 0>(UnsafeCell<HashMapDef<K, V, M, F>>);

unsafe impl<K: Sync, V: Sync, const M: usize, const F: usize> Sync for HashMap<K, V, M, F> {}

impl<K, V, const M: usize, const F: usize> HashMap<K, V, M, F> {
    // Implementing `Default` makes no sense in this case. Maps are always
    // global variables, so they need to be instantiated with a `const` method.
    // `Default::default` method is not `const`.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> HashMap<K, V, M, F> {
        HashMap(UnsafeCell::new(HashMapDef::new()))
    }

    /// Retrieve the value associate with `key` from the map.
    /// This function is unsafe. Unless the map flag `BPF_F_NO_PREALLOC` is used, the kernel does not
    /// make guarantee on the atomicity of `insert` or `remove`, and any element removed from the
    /// map might get aliased by another element in the map, causing garbage to be read, or
    /// corruption in case of writes.
    #[inline]
    pub unsafe fn get(&self, key: &K) -> Option<&V> {
        get(self.0.get() as _, key)
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, but this returns a raw pointer and it's up to the caller
    /// to decide whether it's safe to dereference the pointer or not.
    #[inline]
    pub fn get_ptr(&self, key: &K) -> Option<*const V> {
        get_ptr(self.0.get() as _, key)
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, and additionally cares should be taken to avoid
    /// concurrent writes, but it's up to the caller to decide whether it's safe to dereference the
    /// pointer or not.
    #[inline]
    pub fn get_ptr_mut(&self, key: &K) -> Option<*mut V> {
        get_ptr_mut(self.0.get() as _, key)
    }

    #[inline]
    pub fn insert(&self, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
        insert(self.0.get() as _, key, value, flags)
    }

    #[inline]
    pub fn remove(&self, key: &K) -> Result<(), c_long> {
        remove(self.0.get() as _, key)
    }
}

btf_map_def!(LruHashMapDef, BPF_MAP_TYPE_LRU_HASH);

#[repr(transparent)]
pub struct LruHashMap<K, V, const M: usize, const F: usize = 0>(
    UnsafeCell<LruHashMapDef<K, V, M, F>>,
);

unsafe impl<K: Sync, V: Sync, const M: usize, const F: usize> Sync for LruHashMap<K, V, M, F> {}

impl<K, V, const M: usize, const F: usize> LruHashMap<K, V, M, F> {
    // Implementing `Default` makes no sense in this case. Maps are always
    // global variables, so they need to be instantiated with a `const` method.
    // The `Default::default` method is not `const`.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> LruHashMap<K, V, M, F> {
        LruHashMap(UnsafeCell::new(LruHashMapDef::new()))
    }

    /// Retrieve the value associate with `key` from the map.
    /// This function is unsafe. Unless the map flag `BPF_F_NO_PREALLOC` is used, the kernel does not
    /// make guarantee on the atomicity of `insert` or `remove`, and any element removed from the
    /// map might get aliased by another element in the map, causing garbage to be read, or
    /// corruption in case of writes.
    #[inline]
    pub unsafe fn get(&self, key: &K) -> Option<&V> {
        get(self.0.get() as _, key)
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, but this returns a raw pointer and it's up to the caller
    /// to decide whether it's safe to dereference the pointer or not.
    #[inline]
    pub fn get_ptr(&self, key: &K) -> Option<*const V> {
        get_ptr(self.0.get() as _, key)
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, and additionally cares should be taken to avoid
    /// concurrent writes, but it's up to the caller to decide whether it's safe to dereference the
    /// pointer or not.
    #[inline]
    pub fn get_ptr_mut(&self, key: &K) -> Option<*mut V> {
        get_ptr_mut(self.0.get() as _, key)
    }

    #[inline]
    pub fn insert(&self, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
        insert(self.0.get() as _, key, value, flags)
    }

    #[inline]
    pub fn remove(&self, key: &K) -> Result<(), c_long> {
        remove(self.0.get() as _, key)
    }
}

btf_map_def!(PerCpuHashMapDef, BPF_MAP_TYPE_PERCPU_HASH);

#[repr(transparent)]
pub struct PerCpuHashMap<K, V, const M: usize, const F: usize = 0>(
    UnsafeCell<PerCpuHashMapDef<K, V, M, F>>,
);

unsafe impl<K, V, const M: usize, const F: usize> Sync for PerCpuHashMap<K, V, M, F> {}

impl<K, V, const M: usize, const F: usize> PerCpuHashMap<K, V, M, F> {
    // Implementing `Default` makes no sense in this case. Maps are always
    // global variables, so they need to be instantiated with a `const` method.
    // The `Default::default` method is not `const`.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> PerCpuHashMap<K, V, M, F> {
        PerCpuHashMap(UnsafeCell::new(PerCpuHashMapDef::new()))
    }

    /// Retrieve the value associate with `key` from the map.
    /// This function is unsafe. Unless the map flag `BPF_F_NO_PREALLOC` is used, the kernel does not
    /// make guarantee on the atomicity of `insert` or `remove`, and any element removed from the
    /// map might get aliased by another element in the map, causing garbage to be read, or
    /// corruption in case of writes.
    #[inline]
    pub unsafe fn get(&self, key: &K) -> Option<&V> {
        get(self.0.get() as _, key)
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, but this returns a raw pointer and it's up to the caller
    /// to decide whether it's safe to dereference the pointer or not.
    #[inline]
    pub fn get_ptr(&self, key: &K) -> Option<*const V> {
        get_ptr(self.0.get() as _, key)
    }

    /// Retrieve the value associate with `key` from the map.
    /// The same caveat as `get` applies, and additionally cares should be taken to avoid
    /// concurrent writes, but it's up to the caller to decide whether it's safe to dereference the
    /// pointer or not.
    #[inline]
    pub fn get_ptr_mut(&self, key: &K) -> Option<*mut V> {
        get_ptr_mut(self.0.get() as _, key)
    }

    #[inline]
    pub fn insert(&self, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
        insert(self.0.get() as _, key, value, flags)
    }

    #[inline]
    pub fn remove(&self, key: &K) -> Result<(), c_long> {
        remove(self.0.get() as _, key)
    }
}

#[inline]
fn get_ptr_mut<K, V>(def: *mut c_void, key: &K) -> Option<*mut V> {
    unsafe {
        let value = bpf_map_lookup_elem(def as *mut _, key as *const _ as *const c_void);
        // FIXME: alignment
        NonNull::new(value as *mut V).map(|p| p.as_ptr())
    }
}

#[inline]
fn get_ptr<K, V>(def: *mut c_void, key: &K) -> Option<*const V> {
    get_ptr_mut(def, key).map(|p| p as *const V)
}

#[inline]
unsafe fn get<'a, K, V>(def: *mut c_void, key: &K) -> Option<&'a V> {
    get_ptr(def, key).map(|p| &*p)
}

#[inline]
fn insert<K, V>(def: *mut c_void, key: &K, value: &V, flags: u64) -> Result<(), c_long> {
    let ret = unsafe {
        bpf_map_update_elem(
            def as *mut _,
            key as *const _ as *const _,
            value as *const _ as *const _,
            flags,
        )
    };
    (ret == 0).then_some(()).ok_or(ret)
}

#[inline]
fn remove<K>(def: *mut c_void, key: &K) -> Result<(), c_long> {
    let ret = unsafe { bpf_map_delete_elem(def as *mut _, key as *const _ as *const c_void) };
    (ret == 0).then_some(()).ok_or(ret)
}