use core::ptr;

use aya_ebpf_bindings::bindings::{
    BPF_F_NO_PREALLOC, BPF_LOCAL_STORAGE_GET_F_CREATE, task_struct,
};

use crate::{
    btf_maps::btf_map_def,
    helpers::generated::{bpf_get_current_task_btf, bpf_task_storage_delete, bpf_task_storage_get},
};

btf_map_def!(
    /// A BTF-compatible BPF task storage map.
    ///
    /// Task storage maps require `BPF_F_NO_PREALLOC` flag and `max_entries: 0`.
    pub struct TaskStorage<T>,
    map_type: BPF_MAP_TYPE_TASK_STORAGE,
    max_entries: 0,
    // TODO(https://github.com/rust-lang/rust/issues/76560): this should be:
    //
    // { F | BPF_F_NO_PREALLOC as usize }.
    map_flags: BPF_F_NO_PREALLOC as usize,
    key_type: i32,
    value_type: T,
);

impl<T> TaskStorage<T> {
    #[inline(always)]
    fn get_ptr(&self, task: *mut task_struct, value: *mut T, flags: u64) -> *mut T {
        unsafe { bpf_task_storage_get(self.as_ptr(), task.cast(), value.cast(), flags) }
            .cast::<T>()
    }

    /// Gets a mutable reference to the value associated with `task`.
    ///
    /// Returns a null pointer if no value is associated with the task.
    ///
    /// # Safety
    ///
    /// This function may dereference the pointer `task`.
    #[inline(always)]
    pub unsafe fn get_ptr_mut(&self, task: *mut task_struct) -> *mut T {
        self.get_ptr(task, ptr::null_mut(), 0)
    }

    /// Gets a mutable reference to the value associated with the current task.
    ///
    /// If no value is associated with the current task, `value` will be inserted.
    ///
    /// # Safety
    ///
    /// The returned pointer should be treated as mutable and exclusive for the
    /// duration of the eBPF program.
    #[inline(always)]
    pub unsafe fn get_or_insert_ptr_mut_current(&self, value: Option<&mut T>) -> *mut T {
        let task = unsafe { bpf_get_current_task_btf() };
        self.get_ptr(
            task,
            value.map_or(ptr::null_mut(), ptr::from_mut),
            BPF_LOCAL_STORAGE_GET_F_CREATE.into(),
        )
    }

    /// Deletes the value associated with `task`.
    ///
    /// # Safety
    ///
    /// This function may dereference the pointer `task`.
    #[inline(always)]
    pub unsafe fn delete(&self, task: *mut task_struct) -> Result<(), i32> {
        let ret = unsafe { bpf_task_storage_delete(self.as_ptr(), task.cast()) };
        if ret == 0 { Ok(()) } else { Err(ret as i32) }
    }
}
