use core::{
    cell::UnsafeCell,
    ptr::{self, NonNull},
};

use aya_ebpf_cty::c_long;

use crate::{
    bindings::{
        bpf_map_type::BPF_MAP_TYPE_TASK_STORAGE, task_struct, BPF_F_NO_PREALLOC,
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    },
    cty::{c_int, c_void},
    helpers::{bpf_task_storage_delete, bpf_task_storage_get},
};

#[allow(dead_code)]
pub struct TaskStorageDef<T, const F: usize = { BPF_F_NO_PREALLOC as usize }> {
    r#type: *const [i32; BPF_MAP_TYPE_TASK_STORAGE as usize],
    key: *const c_int,
    value: *const T,
    map_flags: *const [i32; F],
}

#[repr(transparent)]
pub struct TaskStorage<T, const F: usize = { BPF_F_NO_PREALLOC as usize }>(
    UnsafeCell<TaskStorageDef<T, F>>,
);

unsafe impl<T, const F: usize> Sync for TaskStorage<T, F> {}

impl<T, const F: usize> TaskStorage<T, F> {
    pub const fn new() -> Self {
        Self(UnsafeCell::new(TaskStorageDef {
            r#type: &[0i32; BPF_MAP_TYPE_TASK_STORAGE as usize],
            key: ptr::null(),
            value: ptr::null(),
            map_flags: &[0i32; F],
        }))
    }

    #[inline]
    pub unsafe fn get_or_insert(&self, task: *mut task_struct, initial: &T) -> Option<&mut T> {
        self.get_or_insert_ptr(task, initial).map(|p| &mut *p)
    }

    #[inline]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    // pub fn get_or_insert_ptr(&self, task: *mut c_void, initial: &T) -> Option<*mut T> {
    pub fn get_or_insert_ptr(&self, task: *mut task_struct, initial: &T) -> Option<*mut T> {
        unsafe {
            let ptr = bpf_task_storage_get(
                self.0.get() as *mut c_void,
                task,
                initial as *const T as *const c_void as *mut c_void,
                u64::from(BPF_LOCAL_STORAGE_GET_F_CREATE),
            );
            NonNull::new(ptr as *mut T).map(|p| p.as_ptr())
        }
    }

    /// Get a local storage entry associated with this task, or [`None`] if no such value exists.
    ///
    /// # Safety
    ///
    /// This function is marked unsafe as accessing the same tasks's local storage immutably at the
    /// same time as mutably (e.g., but way of [`TaskStorage::get_mut`]) is not supported by Rust's
    /// memory model.
    #[inline]
    pub unsafe fn get(&self, task: *mut c_void) -> Option<&T> {
        self.get_ptr(task).map(|p| &*p)
    }

    /// Mutably access a local storage entry associated with this task, or [`None`] if no such
    /// value exists.
    ///
    /// ## Safety
    ///
    /// This function is marked unsafe as accessing the same task's local storage mutably multiple
    /// times is not supported by Rust's memory model.
    #[inline]
    pub unsafe fn get_mut(&self, task: *mut c_void) -> Option<&mut T> {
        self.get_ptr_mut(task).map(|p| &mut *p)
    }

    /// Get a pointer to the local storage entry associated with this task, or [`None`] if no such
    /// value exists.
    #[inline]
    pub fn get_ptr(&self, task: *mut c_void) -> Option<*const T> {
        self.get_ptr_mut(task).map(|p| p as *const T)
    }

    /// Get a mutable pointer to the local storage entry associated with this task, or [`None`] if
    /// no such value exists. You are responsible for ensuring that at most one mutable reference to
    /// the same task local storage exists at a given time.
    #[inline]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn get_ptr_mut(&self, task: *mut c_void) -> Option<*mut T> {
        unsafe {
            let ptr = bpf_task_storage_get(
                self.0.get() as *mut c_void,
                task as *mut _,
                core::ptr::null_mut(),
                0,
            );
            NonNull::new(ptr as *mut T).map(|p| p.as_ptr())
        }
    }

    /// Remove a local storage entry associated with this task. Returns `Err(-ENOENT)` if no such
    /// value was present.
    #[inline]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn remove(&self, task: *mut c_void) -> Result<(), c_long> {
        let ret = unsafe { bpf_task_storage_delete(self.0.get() as *mut c_void, task as *mut _) };
        if ret == 0 {
            Ok(())
        } else {
            Err(ret)
        }
    }
}
