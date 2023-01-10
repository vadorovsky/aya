use std::mem;

use aya::{include_bytes_aligned, maps::AsyncRingBuf, programs::UProbe, Bpf};
use procfs::process::Process;

use super::tokio_integration_test;

#[no_mangle]
#[inline(never)]
pub extern "C" fn trigger_ebpf_program(_val: u64) {}

fn get_base_addr() -> Option<usize> {
    let maps = Process::myself().unwrap().maps().unwrap();

    for entry in maps {
        if entry.perms.contains("r-xp") {
            return Some((entry.address.0 - entry.offset) as usize);
        }
    }

    None
}

#[tokio_integration_test]
async fn test_ringbuf_primitives() {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/debug/ringbuf");
    let mut bpf = Bpf::load(bytes).unwrap();
    let prog: &mut UProbe = bpf.program_mut("test_ringbuf").unwrap().try_into().unwrap();
    prog.load().unwrap();

    let fn_addr = trigger_ebpf_program as *const () as usize;
    let offset = fn_addr - get_base_addr().unwrap();

    prog.attach(None, offset as u64, "/proc/self/exe", None)
        .unwrap();

    trigger_ebpf_program(4u64);
    trigger_ebpf_program(11u64);
    trigger_ebpf_program(5u64);

    let mut ring = AsyncRingBuf::try_from(bpf.map_mut("EVENTS").unwrap()).unwrap();

    let expected_vals = vec![4u64, 11u64, 5u64];

    let _ = ring.readable_mut().await.unwrap();

    for expected_val in expected_vals {
        loop {
            if let Some(item) = ring.next() {
                assert_eq!(
                    u64::from_ne_bytes((*item).try_into().unwrap()),
                    expected_val,
                );
                break;
            }
            // let mut guard = ring.readable_mut().await.unwrap();
            // if let Some(item) = ring.next() {
            //     assert_eq!(
            //         u64::from_ne_bytes((*item).try_into().unwrap()),
            //         expected_val,
            //     );
            //     break;
            // }
            // guard.clear_ready();
        }
    }
}
