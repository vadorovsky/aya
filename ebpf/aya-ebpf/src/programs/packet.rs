/// Trait implemented by program context types which support the direct packet
/// access.
pub trait DirectPacketAccess {
    /// Returns the raw address of data.
    fn data(&self) -> usize;

    /// Returns the raw address immediately after the metadata.
    fn data_end(&self) -> usize;
}
