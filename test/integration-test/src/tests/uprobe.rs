use std::ffi::CString;

use aya::{EbpfLoader, maps::RingBuf, programs::UProbe};

#[test_log::test]
fn uprobe_atoi() {
    let mut ebpf = EbpfLoader::new()
        .map_max_entries("RING_BUF", 1)
        .load(crate::UPROBE)
        .unwrap();
    let ring_buf = ebpf.take_map("RING_BUF").unwrap();
    let mut ring_buf = RingBuf::try_from(ring_buf).unwrap();
    let prog: &mut UProbe = ebpf.program_mut("uprobe_atoi").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach("atoi", "/lib/libc.so", None, None).unwrap();

    let s = CString::new("🔥").unwrap();
    unsafe { libc::atoi(s.as_ptr()) };

    // let bytes = ring_buf.next().unwrap();
    // let bytes: &[u8] = bytes.as_ref().try_into().unwrap();
    // assert_eq!(bytes, &[255_u8]);

    while let Some(bytes) = ring_buf.next() {
        let bytes: &[u8] = bytes.as_ref().try_into().unwrap();
        println!("bytes: {bytes:?}");
        assert_eq!(bytes, &[255_u8]);
        return;
    }
}
