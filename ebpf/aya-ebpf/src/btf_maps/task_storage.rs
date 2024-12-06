use core::{cell::UnsafeCell, mem};

use crate::{bindings::bpf_map_type::BPF_MAP_TYPE_TASK_STORAGE, cty::c_void};

pub struct TaskStorageDef<const F: usize = 0> {
    r#type: *const [i32; BPF_MAP_TYPE_TASK_STORAGE as usize],
    key_size: *const [i32; mem::size_of::<u32>()],
    value_size: *const [i32; 32],
    max_entries: *const [i32; 1],
    map_flags: *const [i32; F],
}

#[repr(transparent)]
pub struct TaskStorage<const F: usize = 0>(UnsafeCell<TaskStorage<F>>);

unsafe impl<const F: usize> Sync for TaskStorage<F> {}

impl<const F: usize> TaskStorage<F> {
    #[inline]
    pub unsafe fn get_or_insert(&self, inode: *mut c_void, initial: &V) -> Option<&mut V> {
        self.get_or_insert_ptr(inode, initial).map(|p| &mut *p)
    }

    #[inline]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn get_or_insert_ptr(&self, task: *mut c_void, initial: &V) -> Option<*mut V> {
        unsafe {
            let ptr = bpf_task_storage_get(
                self.0.get() as *mut c_void,
                inode,
                initial as *const V as *const c_void as *mut c_void,
                u64::from(BPF_LOCAL_STORAGE_GET_F_CREATE),
            );
            NonNull::new(ptr as *mut V).map(|p| p.as_ptr())
        }
    }

    /// Get a local storage entry associated with this inode, or [`None`] if no such value exists.
    ///
    /// ## Safety
    ///
    /// This function is marked unsafe as accessing the same inode's local storage immutably at the
    /// same time as mutably (e.g., but way of [`InodeStorage::get_mut`]) is not supported by Rust's
    /// memory model.
    #[inline]
    pub unsafe fn get(&self, inode: *mut c_void) -> Option<&V> {
        self.get_ptr(inode).map(|p| &*p)
    }

    /// Mutably access a local storage entry associated with this inode, or [`None`] if no such
    /// value exists.
    ///
    /// ## Safety
    ///
    /// This function is marked unsafe as accessing the same inode's local storage mutably multiple
    /// times is not supported by Rust's memory model.
    #[inline]
    pub unsafe fn get_mut(&self, inode: *mut c_void) -> Option<&mut V> {
        self.get_ptr_mut(inode).map(|p| &mut *p)
    }

    /// Get a pointer to the local storage entry associated with this inode, or [`None`] if no such
    /// value exists.
    #[inline]
    pub fn get_ptr(&self, inode: *mut c_void) -> Option<*const V> {
        self.get_ptr_mut(inode).map(|p| p as *const V)
    }

    /// Get a mutable pointer to the local storage entry associated with this inode, or [`None`] if
    /// no such value exists. You are responsible for ensuring that at most one mutable reference to
    /// the same inode local storage exists at a given time.
    #[inline]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn get_ptr_mut(&self, inode: *mut c_void) -> Option<*mut V> {
        unsafe {
            let ptr = bpf_inode_storage_get(
                self.def.get() as *mut c_void,
                inode,
                core::ptr::null_mut(),
                0,
            );
            NonNull::new(ptr as *mut V).map(|p| p.as_ptr())
        }
    }

    /// Remove a local storage entry associated with this inode. Returns `Err(-ENOENT)` if no such
    /// value was present.
    #[inline]
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn remove(&self, inode: *mut c_void) -> Result<(), c_int> {
        let ret = unsafe { bpf_inode_storage_delete(self.def.get() as *mut c_void, inode) };
        if ret == 0 {
            Ok(())
        } else {
            Err(ret)
        }
    }
}
