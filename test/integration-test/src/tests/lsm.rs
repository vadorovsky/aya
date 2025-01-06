use aya::{programs::Lsm, Btf, Ebpf};

#[test]
fn test_lsm() {
    let mut ebpf = Ebpf::load(crate::LSM).unwrap();
    let btf = Btf::from_sys_fs().unwrap();
    let program: &mut Lsm = ebpf.program_mut("file_open").unwrap().try_into().unwrap();
    program.load("file_open", &btf).unwrap();
    program.attach().unwrap();
}
