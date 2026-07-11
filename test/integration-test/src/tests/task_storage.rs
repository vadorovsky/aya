use assert_matches::assert_matches;
use aya::{
    Btf, Ebpf,
    maps::{Array, MapError, MapType, TaskStorage},
    programs::{Lsm, LsmAttachType, ProgramError, ProgramType},
    sys::{SyscallError, is_map_supported, is_program_supported},
};
use integration_common::local_storage::SENTINEL;
use test_log::test;

#[test]
fn task_storage() {
    if !is_map_supported(MapType::TaskStorage).unwrap() {
        eprintln!("skipping test - task storage maps not supported");
        return;
    }

    let btf = Btf::from_sys_fs().unwrap();
    let mut bpf: Ebpf = Ebpf::load(crate::TASK_STORAGE).unwrap();
    {
        let mut target_tgid: Array<_, u32> =
            Array::try_from(bpf.map_mut("TARGET_TGID").unwrap()).unwrap();
        target_tgid.set(0, std::process::id(), 0).unwrap();
    }
    let link_id = {
        let lsm: &mut Lsm = bpf
            .program_mut("task_storage_test")
            .unwrap()
            .try_into()
            .unwrap();
        lsm.load("bprm_check", &btf).unwrap();
        let result = lsm.attach();
        if !is_program_supported(ProgramType::Lsm(LsmAttachType::Mac)).unwrap() {
            assert_matches!(result, Err(ProgramError::SyscallError(SyscallError { call, io_error })) => {
                assert_eq!(call, "bpf_raw_tracepoint_open");
                assert_eq!(io_error.raw_os_error(), Some(524));
            });
            eprintln!("skipping test - LSM programs not supported");
            return;
        }
        result.unwrap()
    };

    // The BPF LSM module is only active on kernels booted with `lsm=bpf`.
    // Attach succeeds either way (`is_program_supported` only requires
    // `CONFIG_BPF_LSM=y`), but the hook only fires when the module is live.
    if !std::fs::read_to_string("/sys/kernel/security/lsm")
        .unwrap()
        .contains("bpf")
    {
        eprintln!("skipping runtime assertions - BPF LSM not active");
        return;
    }

    // Executing a binary fires `bprm_check` for the current task.
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg("true")
        .output()
        .unwrap();
    assert!(output.status.success());

    let mut storage =
        TaskStorage::<_, u64>::try_from(bpf.map_mut("TASK_STORAGE").unwrap()).unwrap();
    assert_matches!(storage.get(std::process::id() as i32, 0), Ok(value) => {
        assert_eq!(value, SENTINEL);
    });
    storage.remove(std::process::id() as i32).unwrap();
    assert_matches!(
        storage.get(std::process::id() as i32, 0),
        Err(MapError::KeyNotFound)
    );

    let lsm: &mut Lsm = bpf
        .program_mut("task_storage_test")
        .unwrap()
        .try_into()
        .unwrap();
    lsm.detach(link_id).unwrap();
}
