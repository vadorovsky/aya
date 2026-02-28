use aya_ebpf_cty::{c_long, c_void};

use crate::{
    EbpfContext,
    bindings::{__sk_buff, bpf_flow_keys},
    programs::{packet::DirectPacketAccess, sk_buff::SkBuff},
};

pub struct FlowDissectorContext {
    skb: SkBuff,
}

impl FlowDissectorContext {
    pub const fn new(skb: *mut __sk_buff) -> Self {
        let skb = SkBuff { skb };
        Self { skb }
    }

    #[inline]
    pub fn flow_keys(&mut self) -> &mut bpf_flow_keys {
        unsafe { &mut *(*self.skb.skb).__bindgen_anon_1.flow_keys }
    }

    #[inline(always)]
    pub fn load_bytes(&self, offset: usize, dst: &mut [u8]) -> Result<usize, c_long> {
        self.skb.load_bytes(offset, dst)
    }
}

impl EbpfContext for FlowDissectorContext {
    fn as_ptr(&self) -> *mut c_void {
        self.skb.as_ptr()
    }
}

impl DirectPacketAccess for FlowDissectorContext {
    #[inline]
    fn data(&self) -> usize {
        self.skb.data()
    }

    #[inline]
    fn data_end(&self) -> usize {
        self.skb.data_end()
    }
}
