//! Iterators.
use std::{
    io,
    os::fd::{AsFd, BorrowedFd},
};

use crate::{
    generated::{bpf_attach_type::BPF_TRACE_ITER, bpf_prog_type},
    obj::{
        btf::{Btf, BtfKind},
        generated::bpf_link_type,
    },
    programs::{
        define_link_wrapper, load_program, FdLink, LinkError, PerfLinkIdInner, PerfLinkInner,
        ProgramData, ProgramError,
    },
    sys::{bpf_create_iter, bpf_link_create, bpf_link_get_info_by_fd, LinkTarget, SyscallError},
};

/// An eBPF iterator which allows to dump into user space.
///
/// It can be seen as an alternative to `/proc` filesystem, which offers more
/// flexibility about what information should be retrieved and how it should be
/// formatted.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.8.
///
/// ```no_run
/// use aya::{programs::Iter, BtfError, Btf, Ebpf};
///
/// let program: &mut Iter = bpf.program_mut("iter_prog").unwrap().try_into()?;
/// program.load()?;
/// program.attach()?;
/// # Ok::<(), LsmError>(())
/// ```
#[derive(Debug)]
pub struct Iter {
    pub(crate) data: ProgramData<IterLink>,
}

impl Iter {
    /// Loads the program inside the kernel.
    pub fn load(&mut self, iter_type: &str, btf: &Btf) -> Result<(), ProgramError> {
        self.data.expected_attach_type = Some(BPF_TRACE_ITER);
        let type_name = format!("bpf_iter_{iter_type}");
        self.data.attach_btf_id =
            Some(btf.id_by_type_name_kind(type_name.as_str(), BtfKind::Func)?);
        load_program(bpf_prog_type::BPF_PROG_TYPE_TRACING, &mut self.data)
    }

    /// Attaches the program.
    ///
    /// The returned value can be used to detach, see [Iter::detach].
    pub fn attach(&mut self) -> Result<IterLinkId, ProgramError> {
        let prog_fd = self.fd()?;
        let prog_fd = prog_fd.as_fd();
        let link_fd = bpf_link_create(prog_fd, LinkTarget::BtfId, BPF_TRACE_ITER, None, 0, None)
            .map_err(|(_, io_error)| SyscallError {
                call: "bpf_link_create",
                io_error,
            })?;

        self.data
            .links
            .insert(IterLink::new(PerfLinkInner::FdLink(FdLink::new(link_fd))))
    }

    /// Detaches the program.
    ///
    /// See [Iter::attach].
    pub fn detach(&mut self, link_id: IterLinkId) -> Result<(), ProgramError> {
        self.data.links.remove(link_id)
    }

    /// Takes ownership of the link referenced by the provided link_id.
    ///
    /// The link will be detached on `Drop` and the caller is now responsible
    /// for managing its lifetime.
    pub fn take_link(&mut self, link_id: IterLinkId) -> Result<IterLink, ProgramError> {
        self.data.take_link(link_id)
    }
}

/// An iterator descriptor.
#[derive(Debug)]
pub struct IterFd {
    fd: crate::MockableFd,
}

impl IterFd {
    fn from_fd(fd: crate::MockableFd) -> Self {
        Self { fd }
    }
}

impl AsFd for IterFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        let Self { fd } = self;
        fd.as_fd()
    }
}

impl TryFrom<IterLink> for FdLink {
    type Error = LinkError;

    fn try_from(value: IterLink) -> Result<Self, Self::Error> {
        if let PerfLinkInner::FdLink(fd) = value.into_inner() {
            Ok(fd)
        } else {
            Err(LinkError::InvalidLink)
        }
    }
}

impl TryFrom<FdLink> for IterLink {
    type Error = LinkError;

    fn try_from(fd_link: FdLink) -> Result<Self, Self::Error> {
        let info = bpf_link_get_info_by_fd(fd_link.fd.as_fd())?;
        if info.type_ == (bpf_link_type::BPF_LINK_TYPE_ITER as u32) {
            return Ok(Self::new(PerfLinkInner::FdLink(fd_link)));
        }
        Err(LinkError::InvalidLink)
    }
}

define_link_wrapper!(
    /// The link used by [Iter] programs.
    IterLink,
    /// The type returned by [Iter::attach]. Can be passed to [Iter::detach].
    IterLinkId,
    PerfLinkInner,
    PerfLinkIdInner
);

impl IterLink {
    /// Creates an iterator.
    pub fn create_iter(self) -> Result<IterFd, LinkError> {
        if let PerfLinkInner::FdLink(fd) = self.into_inner() {
            let fd = bpf_create_iter(fd.fd.as_fd()).map_err(|(_, error)| {
                LinkError::SyscallError(SyscallError {
                    call: "bpf_iter_create",
                    io_error: error,
                })
            })?;
            Ok(IterFd::from_fd(fd))
        } else {
            Err(LinkError::InvalidLink)
        }
    }
}
