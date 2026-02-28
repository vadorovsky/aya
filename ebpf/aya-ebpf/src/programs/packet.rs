use core::slice;

/// Trait implemented by program context types which support the direct packet
/// access.
pub trait DirectPacketAccess {
    /// Returns the raw address of data.
    fn data(&self) -> usize;

    /// Returns the raw address immediately after the metadata.
    fn data_end(&self) -> usize;

    /// Returns the raw address of data and its length.
    #[inline]
    fn data_with_len(&self) -> (usize, usize) {
        let data = self.data();
        let len = self.data_end() - data;
        (data, len)
    }

    /// Returns the data as a slice of bytes.
    #[inline]
    fn data_bytes(&self) -> &[u8] {
        let (data, len) = self.data_with_len();
        // SAFETY: We know the exact address and length of the data.
        unsafe { slice::from_raw_parts(data, len) }
    }

    /// Returns the data as a mutable slice of bytes.
    #[inline]
    fn data_bytes_mut(&mut self) -> &mut [u8] {
        let (data, len) = self.data_with_len();
        // SAFETY: We know the exact address and length of the data.
        unsafe { slice::from_raw_parts_mut(data, len) }
    }
}
