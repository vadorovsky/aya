//! Hash of maps.
use std::marker::PhantomData;

use crate::{
    sys::{bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_update_elem},
    Pod,
};

use super::{check_kv_size, MapData, MapError};

/// A hash map which stores other maps.
#[doc(alias = "BPF_MAP_TYPE_HASH_OF_MAPS")]
pub struct HashOfMaps<T, K, V> {
    inner: T,
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

impl<T: AsRef<MapData>, K: Pod, V: Pod> HashOfMaps<T, K, V> {
    pub(crate) fn new(map: T) -> Result<HashOfMaps<T, K, V>, MapError> {
        let data = map.as_ref();
        check_kv_size::<K, V>(data)?;
        let _ = data.fd_or_err()?;

        Ok(HashOfMaps {
            inner: map,
            _k: PhantomData,
            _v: PhantomData,
        })
    }

    /// Returns a copy of the map associated with the key.
    pub fn get(&self, key: &K, flags: u64) -> Result<V, MapError> {
        let fd = self.inner.as_ref().fd_or_err()?;
        let value = bpf_map_lookup_elem(fd, key, flags).map_err(|(_, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_lookup_elem".to_owned(),
                io_error,
            }
        })?;
        value.ok_or(MapError::KeyNotFound)
    }
}

impl<T: AsMut<MapData>, K: Pod, V: Pod> HashOfMaps<T, K, V> {
    /// Inserts a map into the hash of maps.
    pub fn insert(&mut self, key: &K, value: &V, flags: u64) -> Result<(), MapError> {
        let fd = self.inner.as_mut().fd_or_err()?;
        bpf_map_update_elem(fd, Some(key), value, flags).map_err(|(_, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_lookup_elem".to_owned(),
                io_error,
            }
        })?;

        Ok(())
    }

    /// Removes a key from the hash of maps.
    pub fn remove(&mut self, key: &K) -> Result<(), MapError> {
        let fd = self.inner.as_mut().fd_or_err()?;
        bpf_map_delete_elem(fd, key)
            .map(|_| ())
            .map_err(|(_, io_error)| MapError::SyscallError {
                call: "bpf_map_delete_elem".to_owned(),
                io_error,
            })
    }
}
