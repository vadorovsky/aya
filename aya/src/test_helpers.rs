//! Utilities to run tests

use std::{
    borrow::Cow,
    fs,
    io::{self, Write as _},
    os::fd::{AsFd, BorrowedFd},
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use libc::if_nametoindex;

use crate::{netlink_set_link_up, sys::NetlinkError};

/// The root cgroup mount point on cgroup v2 systems.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The name of the file used to assign PIDs to a cgroup.
const CGROUP_PROCS: &str = "cgroup.procs";

/// An error type for test helpers.
///
/// This enum covers all failures that can occur during cgroup setup,
/// network namespace creation, and link manipulation in integration tests.
#[derive(Debug, thiserror::Error)]
pub enum AyaTestError {
    /// Failed to create a child cgroup directory under the root cgroup mount.
    #[error("failed to create a child cgroup directory: {path}: {source}")]
    CreateChildDir {
        /// The path of the directory that could not be created.
        path: PathBuf,
        /// Source error.
        #[source]
        source: io::Error,
    },
    /// Failed to write a PID to a cgroup's `cgroup.procs` file.
    #[error("failed to write PID {pid} to {cgroup_procs}: {source}")]
    WritePid {
        /// The PID that was being assigned to the cgroup.
        pid: u32,
        /// The path of the `cgroup.procs` file that was written to.
        cgroup_procs: PathBuf,
        /// Source error.
        #[source]
        source: io::Error,
    },
    /// Failed to open a file descriptor for a child cgroup directory.
    #[error("failed to open a child cgroup {path}: {source}")]
    OpenChild {
        /// The path of the cgroup directory that could not be opened.
        path: PathBuf,
        /// Source error.
        #[source]
        source: io::Error,
    },
    /// Failed to open a network namespace file descriptor.
    #[error("failed to open a network namespace {path}: {source}")]
    OpenNetns {
        /// The path of the namespace file (e.g. `/var/run/netns/<name>`).
        path: &'static str,
        /// Source error.
        #[source]
        source: io::Error,
    },
    /// Failed to create the directory used for persistent network namespaces.
    #[error("failed to create a directory for persistent network namespaces {path}: {source}")]
    CreatePersistNetnsDir {
        /// The path of the directory that could not be created.
        path: &'static str,
        /// Source error.
        #[source]
        source: io::Error,
    },
    /// Failed to create a new network namespace at the given path.
    #[error("failed to create a network namespace {ns_path}: {source}")]
    CreateNetns {
        /// The path where the namespace was created (e.g. `/var/run/netns/<name>`).
        ns_path: PathBuf,
        /// Source error.
        #[source]
        source: io::Error,
    },
    /// Failed to enter a network namespace via `setns`.
    #[error("failed to enter a network namespace: {source}")]
    EnterNetns {
        /// Source error.
        #[source]
        source: nix::errno::Errno,
    },
    /// Failed to bind mount a network namespace file.
    #[error("failed to bind mount a network namespace {source_path} to {target_path}: {source}")]
    BindMountNetns {
        /// The source path of the bind mount (typically `/proc/self/ns/net`).
        source_path: &'static str,
        /// The target path where the namespace was mounted.
        target_path: PathBuf,
        /// Source error.
        #[source]
        source: nix::errno::Errno,
    },
    /// Failed to set up a veth link by bringing it up.
    #[error("failed to set up the link {idx}: {source}")]
    SetupLink {
        /// The index of the link that could not be set up.
        idx: u32,
        /// Source error.
        #[source]
        source: NetlinkError,
    },
}

/// A result type for test helpers.
pub type AyaTestResult<T> = Result<T, AyaTestError>;

/// Returns `true` if the system is using cgroup v2, as determined by the
/// presence of `cgroup.controllers` at the root of the cgroup mount.
pub fn is_cgroup2() -> bool {
    // `cgroup.controllers` exists only at the root of a cgroup2 mount.
    Path::new(CGROUP_ROOT).join("cgroup.controllers").exists()
}

/// A handle to a child cgroup created under a [`Cgroup`].
///
/// On drop, the PIDs in this cgroup's `cgroup.procs` are moved back to the
/// parent cgroup and the directory is removed.
pub struct ChildCgroup<'a> {
    /// The parent cgroup under which this child was created.
    parent: &'a Cgroup<'a>,
    /// The filesystem path of this cgroup directory.
    path: Cow<'a, Path>,
}

/// A handle representing either the root cgroup or a child cgroup.
///
/// This enum is used to avoid unnecessary reference counting when the root
/// cgroup is the only handle needed.
pub enum Cgroup<'a> {
    /// The root cgroup (`/sys/fs/cgroup`).
    Root,
    /// A child cgroup created via [`Cgroup::create_child`].
    Child(ChildCgroup<'a>),
}

impl Cgroup<'static> {
    /// Returns a handle to the root cgroup.
    pub fn root() -> Self {
        Self::Root
    }
}

impl<'a> Cgroup<'a> {
    /// Returns the filesystem path for this cgroup.
    fn path(&self) -> &Path {
        match self {
            Self::Root => Path::new(CGROUP_ROOT),
            Self::Child(ChildCgroup { parent: _, path }) => path,
        }
    }

    /// Creates a child cgroup with the given name under this cgroup and returns
    /// a [`ChildCgroup`] handle to it.
    pub fn create_child(&'a self, name: &str) -> AyaTestResult<ChildCgroup<'a>> {
        let path = self.path().join(name);
        fs::create_dir(&path).map_err(|source| AyaTestError::CreateChildDir {
            path: path.clone(),
            source,
        })?;

        Ok(ChildCgroup {
            parent: self,
            path: path.into(),
        })
    }

    /// Writes the given PID to this cgroup's `cgroup.procs` file, thereby
    /// moving that process into this cgroup.
    pub fn write_pid(&self, pid: u32) -> AyaTestResult<()> {
        let cgroup_procs = self.path().join(CGROUP_PROCS);
        fs::write(&cgroup_procs, format!("{pid}\n")).map_err(move |source| AyaTestError::WritePid {
            pid,
            cgroup_procs,
            source,
        })
    }
}

impl<'a> ChildCgroup<'a> {
    /// Returns a reference to a lazily opened file descriptor for this cgroup
    /// directory.
    ///
    /// The file is opened for reading on first call and cached for subsequent
    /// calls.
    pub fn fd(&self) -> AyaTestResult<fs::File> {
        let Self { parent: _, path } = self;
        fs::OpenOptions::new()
            .read(true)
            .open(path.as_ref())
            .map_err(|source| AyaTestError::OpenChild {
                path: path.to_path_buf(),
                source,
            })
    }

    /// Consumes `self` and returns a [`Cgroup::Child`] variant.
    pub fn into_cgroup(self) -> Cgroup<'a> {
        Cgroup::Child(self)
    }
}

impl Drop for ChildCgroup<'_> {
    /// Moves all PIDs from this child cgroup back to the parent cgroup's
    /// `cgroup.procs`, then removes this cgroup's directory.
    ///
    /// If this cgroup is empty, the directory is simply removed. Errors are
    /// logged or cause a panic (depending on whether the runtime is already
    /// unwinding) rather than propagating, to avoid double-panic.
    #[expect(
        clippy::print_stderr,
        reason = "drop handlers avoid panic-in-panic by logging errors"
    )]
    #[expect(
        clippy::use_debug,
        reason = "debug formatting preserves error context in drop"
    )]
    fn drop(&mut self) {
        use anyhow::{Context as _, Result};

        let Self { parent, path } = self;

        match (|| -> Result<()> {
            let dst = parent.path().join(CGROUP_PROCS);
            let mut dst = fs::OpenOptions::new()
                .append(true)
                .open(&dst)
                .with_context(|| {
                    format!(
                        "fs::OpenOptions::new().append(true).open(\"{}\")",
                        dst.display()
                    )
                })?;
            let pids = path.as_ref().join(CGROUP_PROCS);
            let pids = fs::read_to_string(&pids)
                .with_context(|| format!("fs::read_to_string(\"{}\")", pids.display()))?;
            for pid in pids.split_inclusive('\n') {
                dst.write_all(pid.as_bytes())
                    .with_context(|| format!("dst.write_all(\"{pid}\")"))?;
            }

            fs::remove_dir(&path)
                .with_context(|| format!("fs::remove_dir(\"{}\")", path.display()))?;
            Ok(())
        })() {
            Ok(()) => (),
            Err(err) => {
                // Avoid panic in panic.
                if std::thread::panicking() {
                    eprintln!("{err:?}");
                } else {
                    panic!("{err:?}");
                }
            }
        }
    }
}

/// A guard that creates and enters a new network namespace, restoring the
/// previous namespace on drop.
///
/// The guard also brings up the `lo` (loopback) interface in the new
/// namespace by default, since it is down in freshly created namespaces.
pub struct NetNsGuard {
    /// The name of the persisted network namespace.
    name: String,
    /// File handle to the original network namespace, used for restoration on drop.
    old_ns: fs::File,
    /// File handle to the newly created network namespace.
    new_ns: fs::File,
}

impl NetNsGuard {
    /// The directory where network namespaces are persisted for user-space access.
    const PERSIST_DIR: &str = "/var/run/netns/";

    /// The path to the calling thread's network namespace file.
    const THREAD_NETNS: &str = "/proc/thread-self/ns/net";

    /// Creates a new network namespace guard.
    ///
    /// This creates a new network namespace, persists it under `/var/run/netns/`,
    /// enters it, and brings up the `lo` interface. On drop, the guard restores
    /// the previous namespace and cleans up the persisted namespace entry.
    #[expect(
        clippy::print_stdout,
        reason = "integration tests print namespace transitions for diagnostics"
    )]
    pub fn new() -> AyaTestResult<Self> {
        // `/proc/thread-self/ns/net` resolves to the calling thread's netns
        // (`/proc/self/ns/net` would always pin to the main thread's).
        let old_ns =
            fs::File::open(Self::THREAD_NETNS).map_err(|source| AyaTestError::OpenNetns {
                path: Self::THREAD_NETNS,
                source,
            })?;

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let pid = process::id();
        let name = format!("aya-test-{pid}-{}", COUNTER.fetch_add(1, Ordering::Relaxed));

        fs::create_dir_all(Self::PERSIST_DIR).map_err(|source| {
            AyaTestError::CreatePersistNetnsDir {
                path: Self::PERSIST_DIR,
                source,
            }
        })?;
        let ns_path = Path::new(Self::PERSIST_DIR).join(&name);
        let _unused: fs::File =
            fs::File::create(&ns_path).map_err(|source| AyaTestError::CreateNetns {
                ns_path: ns_path.clone(),
                source,
            })?;
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)
            .map_err(|source| AyaTestError::EnterNetns { source })?;

        // Re-open after unshare to capture the freshly entered namespace.
        let new_ns =
            fs::File::open(Self::THREAD_NETNS).map_err(|source| AyaTestError::OpenNetns {
                path: Self::THREAD_NETNS,
                source,
            })?;

        nix::mount::mount(
            Some(Self::THREAD_NETNS),
            &ns_path,
            Some("none"),
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(move |source| AyaTestError::BindMountNetns {
            source_path: Self::THREAD_NETNS,
            target_path: ns_path,
            source,
        })?;

        println!("entered network namespace {name}");

        let ns = Self {
            name,
            old_ns,
            new_ns,
        };

        // By default, the loopback in a new netns is down. Set it up.
        let lo = c"lo";
        unsafe {
            let idx = if_nametoindex(lo.as_ptr());
            assert!(
                idx != 0,
                "interface `lo` not found in netns {}: {}",
                ns.name,
                io::Error::last_os_error()
            );
            netlink_set_link_up(idx as i32)
                .map_err(|source| AyaTestError::SetupLink { idx, source })?;
        }

        Ok(ns)
    }
}

impl AsFd for NetNsGuard {
    /// Returns a borrowed file descriptor for the new network namespace.
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.new_ns.as_fd()
    }
}

impl Drop for NetNsGuard {
    /// Restores the original network namespace and cleans up the persisted
    /// namespace entry under `/var/run/netns/`.
    ///
    /// Errors are logged or cause a panic (depending on whether the runtime is
    /// already unwinding) rather than propagating, to avoid double-panic.
    #[expect(
        clippy::print_stderr,
        reason = "drop handlers avoid panic-in-panic by logging errors"
    )]
    #[expect(
        clippy::use_debug,
        reason = "debug formatting preserves error context in drop"
    )]
    fn drop(&mut self) {
        use anyhow::{Context as _, Result};

        let Self {
            old_ns,
            name,
            new_ns: _,
        } = self;
        match (|| -> Result<()> {
            nix::sched::setns(old_ns, nix::sched::CloneFlags::CLONE_NEWNET)
                .context("nix::sched::setns(_, CLONE_NEWNET)")?;
            let ns_path = Path::new(Self::PERSIST_DIR).join(&name);
            nix::mount::umount2(&ns_path, nix::mount::MntFlags::MNT_DETACH).with_context(|| {
                format!("nix::mount::umount2(\"{}\", MNT_DETACH)", ns_path.display())
            })?;
            fs::remove_file(&ns_path)
                .with_context(|| format!("fs::remove_file(\"{}\")", ns_path.display()))?;
            Ok(())
        })() {
            Ok(()) => (),
            Err(err) => {
                // Avoid panic in panic.
                if std::thread::panicking() {
                    eprintln!("{err:?}");
                } else {
                    panic!("{err:?}");
                }
            }
        }
    }
}

/// Asserts a condition based on the running kernel version.
///
/// If `KernelVersion::current >= $version`, evaluates to `assert!($cond)`.
/// Otherwise, evaluates to `assert!(!$cond)`.
///
/// This is useful for tests that behave differently across kernel versions.
#[macro_export]
macro_rules! kernel_assert {
    ($cond:expr, $version:expr $(,)?) => {
        let current = aya::util::KernelVersion::current().unwrap();
        let required: aya::util::KernelVersion = $version;
        if current >= required {
            assert!($cond, "{current} >= {required}");
        } else {
            assert!(!$cond, "{current} < {required}");
        }
    };
}

/// Asserts equality based on the running kernel version.
///
/// If `KernelVersion::current >= $version`, evaluates to `assert_eq!($left, $right)`.
/// Otherwise, evaluates to `assert_ne!($left, $right)`.
///
/// This is useful for tests that check for behavioral changes introduced in
/// specific kernel versions.
#[macro_export]
macro_rules! kernel_assert_eq {
    ($left:expr, $right:expr, $version:expr $(,)?) => {
        let current = aya::util::KernelVersion::current().unwrap();
        let required: aya::util::KernelVersion = $version;
        if current >= required {
            assert_eq!($left, $right, "{current} >= {required}");
        } else {
            assert_ne!($left, $right, "{current} < {required}");
        }
    };
}
