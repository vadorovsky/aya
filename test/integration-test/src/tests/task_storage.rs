use aya::{programs::KProbe, Ebpf};
use test_log::test;

#[test]
fn test_task_storage() {
    let mut ebpf = Ebpf::load(crate::TASK_STORAGE).unwrap();

    let prog: &mut KProbe = ebpf.program_mut("task_alloc").unwrap().try_into().unwrap();
    prog.load().unwrap();
    prog.attach("task_alloc", 0).unwrap();
}
