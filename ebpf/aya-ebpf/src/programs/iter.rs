use core::ffi::c_void;

use crate::{args::FromBtfArgument, bindings::seq_file, EbpfContext};

#[repr(transparent)]
pub struct SeqFile(*mut seq_file);

impl SeqFile {
    pub fn as_ptr(&self) -> *mut seq_file {
        self.0
    }
}

#[repr(C)]
pub union SeqFileUnion {
    pub seq: *mut seq_file,
}

#[repr(C)]
pub struct BpfIterMeta {
    seq: SeqFileUnion,
    pub session_id: u64,
    pub seq_num: u64,
}

pub struct IterContext {
    ctx: *mut BpfIterMeta,
}

impl IterContext {
    pub fn new(ctx: *mut c_void) -> IterContext {
        IterContext {
            ctx: ctx as *mut BpfIterMeta,
        }
    }

    /// Returns the `n`th argument passed to the iterator, starting from 0.
    pub unsafe fn arg<T: FromBtfArgument>(&self, n: usize) -> T {
        T::from_argument(self.ctx as *const _, n)
    }

    pub fn seq_file(&self) -> SeqFile {
        unsafe { SeqFile((*self.ctx).seq.seq) }
    }
}

impl EbpfContext for IterContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx as *mut c_void
    }
}
