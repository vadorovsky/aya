use core::{cell::UnsafeCell, hint::unreachable_unchecked, mem};

use crate::{
    bindings::bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY, btf_maps::AyaBtfMapMarker, cty::c_long,
    helpers::bpf_tail_call, EbpfContext,
};

#[allow(dead_code)]
pub struct ProgramArrayDef<const M: usize, const F: usize = 0> {
    r#type: *const [i32; BPF_MAP_TYPE_PROG_ARRAY as usize],
    key_size: *const [i32; mem::size_of::<u32>()],
    value_size: *const [i32; mem::size_of::<u32>()],
    max_entries: *const [i32; M],
    map_flags: *const [i32; F],

    // Anonymize the struct.
    _anon: AyaBtfMapMarker,
}

#[repr(transparent)]
pub struct ProgramArray<const M: usize, const F: usize = 0>(UnsafeCell<ProgramArrayDef<M, F>>);

impl<const M: usize, const F: usize> ProgramArray<M, F> {
    // Implementing `Default` makes no sense in this case. Maps are always
    // global variables, so they need to be instantiated with a `const` method.
    // The `Default::default` method is not `const`.
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self(UnsafeCell::new(ProgramArrayDef {
            r#type: &[0i32; BPF_MAP_TYPE_PROG_ARRAY as usize] as *const _,
            key_size: &[0i32; mem::size_of::<u32>()] as *const _,
            value_size: &[0i32; mem::size_of::<u32>()] as *const _,
            max_entries: &[0i32; M] as *const _,
            map_flags: &[0i32; F] as *const _,
            _anon: AyaBtfMapMarker::new(),
        }))
    }

    /// Perform a tail call into a program indexed by this map.
    ///
    /// # Safety
    ///
    /// This function is inherently unsafe, since it causes control flow to jump into
    /// another eBPF program. This can have side effects, such as drop methods not being
    /// called. Note that tail calling into an eBPF program is not the same thing as
    /// a function call -- control flow never returns to the caller.
    ///
    /// # Return Value
    ///
    /// On success, this function **does not return** into the original program.
    /// On failure, a negative error is returned, wrapped in `Err()`.
    #[cfg(not(unstable))]
    pub unsafe fn tail_call<C: EbpfContext>(&self, ctx: &C, index: u32) -> Result<(), c_long> {
        let res = bpf_tail_call(ctx.as_ptr(), self.0.get() as *mut _, index);
        if res != 0 {
            Err(res)
        } else {
            unreachable_unchecked()
        }
    }

    /// Perform a tail call into a program indexed by this map.
    ///
    /// # Safety
    ///
    /// This function is inherently unsafe, since it causes control flow to jump into
    /// another eBPF program. This can have side effects, such as drop methods not being
    /// called. Note that tail calling into an eBPF program is not the same thing as
    /// a function call -- control flow never returns to the caller.
    ///
    /// # Return Value
    ///
    /// On success, this function **does not return** into the original program.
    /// On failure, a negative error is returned, wrapped in `Err()`.
    #[cfg(unstable)]
    pub unsafe fn tail_call<C: EbpfContext>(&self, ctx: &C, index: u32) -> Result<!, c_long> {
        let res = bpf_tail_call(ctx.as_ptr(), self.0.get() as *mut _, index);
        if res != 0 {
            Err(res)
        } else {
            unreachable_unchecked()
        }
    }
}