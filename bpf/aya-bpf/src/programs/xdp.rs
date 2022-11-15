use core::ffi::c_void;

use crate::{bindings::xdp_md, BpfContext};

pub struct XdpContext {
    pub ctx: *mut xdp_md,
}

impl XdpContext {
    pub fn new(ctx: *mut xdp_md) -> XdpContext {
        XdpContext { ctx }
    }

    #[inline]
    pub fn data(&self) -> *mut u8 {
        unsafe { (*self.ctx).data as *mut u8 }
    }

    #[inline]
    pub fn data_end(&self) -> *mut u8 {
        unsafe { (*self.ctx).data_end as *mut u8 }
    }

    /// Return the raw address of the XdpContext metadata.
    #[inline(always)]
    pub fn metadata(&self) -> *mut u8 {
        unsafe { (*self.ctx).data_meta as *mut u8 }
    }

    /// Return the raw address immediately after the XdpContext's metadata.
    #[inline(always)]
    pub fn metadata_end(&self) -> *mut u8 {
        self.data()
    }
}

impl BpfContext for XdpContext {
    fn as_ptr(&self) -> *mut c_void {
        self.ctx as *mut _
    }
}
