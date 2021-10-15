//! Raw tracepoints.
use std::{ffi::CString, os::unix::io::RawFd};

use crate::{
    generated::bpf_prog_type::BPF_PROG_TYPE_RAW_TRACEPOINT,
    programs::{load_program, FdLink, LinkRef, ProgramData, ProgramError},
    sys::bpf_raw_tracepoint_open,
};

/// A raw tracepoint probe.
///
/// These are attached directly to Linux tracepoints without any special argument
/// handling. TODO: Come back and document this better
///
/// # Examples
///
/// ```no_run
/// # let mut bpf = Bpf::load_file("ebpf_programs.o")?;
/// use aya::{Bpf, programs::RawTracePoint};
/// use std::convert::TryInto;
///
/// let program: &mut RawTracePoint = bpf.program_mut("sys_enter")?.try_into()?;
/// program.load()?;
/// program.attach("sys_enter")?;
/// # Ok::<(), aya::BpfError>(())
/// ```
#[derive(Debug)]
#[doc(alias = "BPF_PROG_TYPE_RAW_TRACEPOINT")]
pub struct RawTracePoint {
    pub(crate) data: ProgramData,
}

impl RawTracePoint {
    /// Loads the program inside the kernel.
    ///
    /// See also [`Program::load`](crate::programs::Program::load).
    pub fn load(&mut self) -> Result<(), ProgramError> {
        load_program(BPF_PROG_TYPE_RAW_TRACEPOINT, &mut self.data)
    }

    /// Returns the name of the program.
    pub fn name(&self) -> String {
        self.data.name.to_string()
    }

    /// Attaches the program to the given tracepoint.
    pub fn attach(&mut self, tp_name: &str) -> Result<LinkRef, ProgramError> {
        let prog_fd = self.data.fd_or_err()?;
        let name = CString::new(tp_name).unwrap();
        let name_ptr = name.as_ptr() as u64;

        let pfd = bpf_raw_tracepoint_open(name_ptr, prog_fd).map_err(|(_code, io_error)| {
            ProgramError::SyscallError {
                call: "bpf".to_owned(),
                io_error,
            }
        })? as RawFd;

        Ok(self.data.link(FdLink { fd: Some(pfd) }))
    }
}
