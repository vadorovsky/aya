//! A task local storage map backed by `BPF_MAP_TYPE_TASK_STORAGE`.

use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
};

use crate::{
    Pod,
    maps::{MapData, MapError, check_kv_size, hash_map},
};

/// A task local storage map backed by `BPF_MAP_TYPE_TASK_STORAGE`.
///
/// This map type stores values that are owned by individual tasks. The map keys
/// are task IDs and the values can be accessed both from eBPF using
/// [`bpf_task_storage_get`] and from user space through the methods on this type.
///
/// [`bpf_task_storage_get`]: https://docs.ebpf.io/linux/helper-function/bpf_task_storage_get/
///
/// The minimum kernel version required to use this feature is 5.11.
#[doc(alias = "BPF_MAP_TYPE_TASK_STORAGE")]
#[derive(Debug)]
pub struct TaskStorage<T, V: Pod> {
    pub(crate) inner: T,
    _v: PhantomData<V>,
}

impl<T: Borrow<MapData>, V: Pod> TaskStorage<T, V> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<i32, V>(data)?;

        Ok(Self {
            inner: map,
            _v: PhantomData,
        })
    }

    /// Returns the value associated with `pid`.
    pub fn get(&self, pid: i32, flags: u64) -> Result<V, MapError> {
        hash_map::get(self.inner.borrow(), &pid, flags)
    }
}

impl<T: BorrowMut<MapData>, V: Pod> TaskStorage<T, V> {
    /// Creates or updates the value associated with `pid`.
    pub fn insert(
        &mut self,
        pid: i32,
        value: impl Borrow<V>,
        flags: u64,
    ) -> Result<(), MapError> {
        hash_map::insert(self.inner.borrow_mut(), &pid, value.borrow(), flags)
    }

    /// Removes the storage associated with `pid`.
    pub fn remove(&mut self, pid: i32) -> Result<(), MapError> {
        hash_map::remove(self.inner.borrow_mut(), &pid)
    }
}
