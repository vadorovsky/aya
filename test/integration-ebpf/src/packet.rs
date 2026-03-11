#![no_std]
#![no_main]
#![expect(unused_crate_dependencies, reason = "used in other bins")]

use aya_ebpf::programs::{DirectPacketAccess, XdpContext};
#[cfg(not(test))]
extern crate ebpf_panic;

fn parse_packet<P: DirectPacketAccess>(ctx: P) -> Result<(), ()> {
    Ok(())
}
