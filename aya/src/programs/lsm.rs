//! LSM probes.
use crate::{
    generated::{bpf_attach_type::BPF_LSM_MAC, bpf_prog_type::BPF_PROG_TYPE_LSM},
    obj::btf::{Btf, BtfKind},
    programs::{load_program, FdLink, LinkRef, ProgramData, ProgramError},
    sys::bpf_raw_tracepoint_open,
};
use std::os::unix::io::RawFd;

/// A program that attaches to Linux LSM hooks. Used to implement security policy and
/// audit logging.
///
/// LSM probes can be attached to the kernel's [security hooks][1] to implement mandatory
/// access control policy and security auditing.
///
/// LSM probes require a kernel compiled with `CONFIG_BPF_LSM=y` and `CONFIG_DEBUG_INFO_BTF=y`.
/// In order for the probes to fire, you also need the BPF LSM to be enabled through your
/// kernel's boot paramters (like `lsm=lockdown,yama,bpf`).
///
/// # Examples
///
/// ```no_run
/// # let mut bpf = Bpf::load_file("ebpf_programs.o")?;
/// use aya::{Bpf, programs::Lsm};
/// use std::convert::TryInto;
///
/// let program: &mut Lsm = bpf.program_mut("security_bprm_exec")?.try_into()?;
/// program.load()?;
/// program.attach()?;
/// # Ok::<(), aya::BpfError>(())
/// ```
///
/// [1]: https://elixir.bootlin.com/linux/latest/source/include/linux/lsm_hook_defs.h
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_LSM")]
pub struct Lsm {
    pub(crate) data: ProgramData,
}

impl Lsm {
    /// Loads the program inside the kernel.
    ///
    /// See also [`Program::load`](crate::programs::Program::load).
    pub fn load(&mut self) -> Result<(), ProgramError> {
        let btf = Btf::from_sys_fs().unwrap();
        self.data.expected_attach_type = Some(BPF_LSM_MAC);
        self.data.attach_btf_obj_fd = Some(0);
        let type_name = format!("bpf_lsm_{}", self.data.name);
        self.data.attach_btf_id = Some(
            btf.id_by_type_name_kind(type_name.as_str(), BtfKind::Func)
                .unwrap(),
        );
        load_program(BPF_PROG_TYPE_LSM, &mut self.data)
    }

    /// Returns the name of the program.
    pub fn name(&self) -> String {
        self.data.name.to_string()
    }

    /// Attaches the program.
    pub fn attach(&mut self) -> Result<LinkRef, ProgramError> {
        attach_btf_id(&mut self.data)
    }
}

/// Common logic for all BPF program types that attach to a BTF id.
pub(crate) fn attach_btf_id(program_data: &mut ProgramData) -> Result<LinkRef, ProgramError> {
    let prog_fd = program_data.fd_or_err()?;

    let pfd = bpf_raw_tracepoint_open(0, prog_fd).map_err(|(_code, io_error)| {
        ProgramError::SyscallError {
            call: "bpf".to_owned(),
            io_error,
        }
    })? as RawFd;

    Ok(program_data.link(FdLink { fd: Some(pfd) }))
}
