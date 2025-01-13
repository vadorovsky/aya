//! Task storage.

use std::{
    borrow::Borrow,
    ffi::c_int,
    marker::PhantomData,
    os::fd::{AsFd, AsRawFd},
};

use crate::{
    maps::{check_kv_size, IterableMap, MapData, MapError, MapIter, MapKeys},
    sys::{bpf_map_lookup_elem, PidFd, SyscallError},
    Pod,
};

/// A storage for tasks.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.12.
#[doc(alias = "BPF_MAP_TYPE_TASK_STORAGE")]
#[derive(Debug)]
pub struct TaskStorage<T, V> {
    pub(crate) inner: T,
    _v: PhantomData<V>,
}

impl<T: Borrow<MapData>, V: Pod> TaskStorage<T, V> {
    pub(crate) fn new(map: T) -> Result<Self, MapError> {
        let data = map.borrow();
        check_kv_size::<c_int, V>(data)?;

        Ok(Self {
            inner: map,
            _v: PhantomData,
        })
    }

    /// Returns the value stored for the given `pid`.
    pub fn get(&self, pid: &u32, flags: u64) -> Result<V, MapError> {
        let pidfd = PidFd::open(*pid, 0).map_err(|(_, io_error)| SyscallError {
            call: "pidfd_open",
            io_error,
        })?;
        let map_fd = self.inner.borrow().fd().as_fd();
        let value =
            bpf_map_lookup_elem(map_fd, &pidfd.as_raw_fd(), flags).map_err(|(_, io_error)| {
                SyscallError {
                    call: "bpf_map_lookup_elem",
                    io_error,
                }
            })?;
        value.ok_or(MapError::KeyNotFound)
    }

    /// An iterator visiting all key-value pairs in arbitrary order. The
    /// iterator item type is `Result<(K, V), MapError>`.
    pub fn iter(&self) -> MapIter<'_, u32, V, Self> {
        MapIter::new(self)
    }

    /// An iterator visiting all keys in arbitrary order. The iterator ele
    pub fn keys(&self) -> MapKeys<'_, u32> {
        MapKeys::new(self.inner.borrow())
    }
}

impl<T: Borrow<MapData>, V: Pod> IterableMap<u32, V> for TaskStorage<T, V> {
    fn map(&self) -> &MapData {
        self.inner.borrow()
    }

    fn get(&self, key: &u32) -> Result<V, MapError> {
        Self::get(self, key, 0)
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use assert_matches::assert_matches;
    use libc::EFAULT;

    use super::*;
    use crate::{
        generated::{bpf_cmd, bpf_map_type::BPF_MAP_TYPE_TASK_STORAGE},
        maps::{
            test_utils::{self, new_map},
            Map,
        },
        obj,
        sys::{override_syscall, SysResult, Syscall},
    };

    fn new_obj_map() -> obj::Map {
        test_utils::new_obj_map::<u32>(BPF_MAP_TYPE_TASK_STORAGE)
    }

    fn sys_error(value: i32) -> SysResult<i64> {
        Err((-1, io::Error::from_raw_os_error(value)))
    }

    #[test]
    fn test_wrong_value_size() {
        let map = new_map(new_obj_map());
        let map = Map::TaskStorage(map);
        assert_matches!(
            TaskStorage::<_, u16>::try_from(&map),
            Err(MapError::InvalidValueSize {
                size: 1,
                expected: 2
            })
        );
    }

    #[test]
    fn test_try_from_wrong_map() {
        let map = new_map(new_obj_map());
        let map = Map::TaskStorage(map);
        assert_matches!(
            TaskStorage::<_, u32>::try_from(&map),
            Err(MapError::InvalidMapType { .. })
        );
    }

    #[test]
    fn test_new_ok() {
        let map = new_map(new_obj_map());
        assert!(TaskStorage::<_, u32>::new(&map).is_ok());
    }

    #[test]
    fn test_try_from_ok() {
        let map = new_map(new_obj_map());
        let map = Map::TaskStorage(map);
        assert!(TaskStorage::<_, u32>::try_from(&map).is_ok());
    }
}
