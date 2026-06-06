//! Test support utilities for Aya integration tests.

use std::{
    borrow::Cow,
    cell::OnceCell,
    ffi::CString,
    fs,
    io::{self, Write as _},
    os::fd::{AsFd, BorrowedFd},
    path::Path,
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use aya::netlink_set_link_up;
use libc::if_nametoindex;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CGROUP_PROCS: &str = "cgroup.procs";

#[derive(Debug, thiserror::Error)]
pub enum AyaTestError<'a> {
    #[error("failed to create a child cgroup directory: {}: {source}")]
    CreateChildDir {
        path: &'a Path,
        #[source]
        source: io::Error,
    },
    #[error("failed to write PID {pid} to {path}: {source}")]
    WritePid {
        pid: u32,
        cgroup_procs: &'a Path,
        #[source]
        source: io::Error,
    },
    #[error("failed to open a child cgroup {path}: {source}")]
    OpenChild {
        path: &'a Path,
        #[source]
        source: io::Error,
    },
    #[error("failed to open a network namespace {path}: {source}")]
    OpenNetns {
        path: &'a str,
        #[source]
        source: io::Error,
    },
    #[error("failed to create a directory for persistent network namespaces {path}: {source}")]
    CreatePersistNetnsDir {
        path: &'a str,
        #[source]
        source: io::Error,
    },
    #[error("failed to create a network namespace {path}: {source}")]
    CreateNetns {
        path: &'a Path,
        #[source]
        source: io::Error,
    },
    #[error("failed to enter a network namespace: {0}")]
    EnterNetns(#[source] io::Error),
    #[error("failed to bind mount a network namespace {path}: {source}")]
    BindMountNetns {
        source_path: &'a str,
        target_path: &'a Path,
        #[source]
        source: io::Error,
    },
    #[error("failed to set up the link {idx}: {source}")]
    SetupLink {
        idx: u32,
        #[source]
        source: NetlinkError,
    },
}

pub type Result<T> = Result<T, AyaTestError<'_>>;

/// Returns whether `/sys/fs/cgroup` is the root of a cgroup v2 mount.
pub fn is_cgroup2() -> bool {
    // `cgroup.controllers` exists only at the root of a cgroup2 mount.
    Path::new(CGROUP_ROOT).join("cgroup.controllers").exists()
}

pub struct ChildCgroup<'a> {
    parent: &'a Cgroup<'a>,
    path: Cow<'a, Path>,
    fd: OnceCell<fs::File>,
}

pub enum Cgroup<'a> {
    Root,
    Child(ChildCgroup<'a>),
}

impl Cgroup<'static> {
    pub const fn root() -> Self {
        Self::Root
    }
}

impl<'a> Cgroup<'a> {
    fn path(&self) -> &Path {
        match self {
            Self::Root => Path::new(CGROUP_ROOT),
            Self::Child(ChildCgroup {
                parent: _,
                path,
                fd: _,
            }) => path,
        }
    }

    pub fn create_child(&'a self, name: &str) -> Result<ChildCgroup<'a>> {
        let path = self.path().join(name);
        fs::create_dir(&path)?;

        let fd = fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|source| AyaTestError::CreateChildDir { path, source })?;

        Ok(ChildCgroup {
            parent: self,
            path: path.into(),
            fd: OnceCell::from(fd),
        })
    }

    pub fn write_pid(&self, pid: u32) -> Result<()> {
        let cgroup_procs = self.path().join(CGROUP_PROCS);
        fs::write(cgroup_procs, format!("{pid}\n")).map_err(|source| AyaTestError::WritePid {
            pid,
            cgroup_procs,
            source,
        })
    }
}

impl<'a> ChildCgroup<'a> {
    pub fn fd(&self) -> Result<&'a fs::File> {
        let Self {
            parent: _,
            path,
            fd,
        } = self;
        fd.get_or_init(|| {
            fs::OpenOptions::new()
                .read(true)
                .open(path.as_ref())
                .map_err(|source| AyaTestError::OpenChild { path, source })
        })
    }

    pub fn into_cgroup(self) -> Cgroup<'a> {
        Cgroup::Child(self)
    }
}

impl Drop for ChildCgroup<'_> {
    #[expect(
        clippy::print_stderr,
        reason = "drop handlers avoid panic-in-panic by logging errors"
    )]
    #[expect(
        clippy::use_debug,
        reason = "debug formatting preserves error context in drop"
    )]
    fn drop(&mut self) {
        let Self {
            parent,
            path,
            fd: _,
        } = self;

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

            fs::remove_dir(path.as_ref())
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

pub struct NetNsGuard {
    name: String,
    old_ns: fs::File,
    new_ns: fs::File,
}

impl NetNsGuard {
    const PERSIST_DIR: &str = "/var/run/netns/";
    const THREAD_NETNS: &str = "/proc/thread-self/ns/net";

    #[expect(
        clippy::print_stdout,
        reason = "integration tests print namespace transitions for diagnostics"
    )]
    pub fn new() -> Result<Self> {
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

        fs::create_dir_all(Self::PERSIST_DIR)
            .map_err(|source| AyaTestError::CreatePersistNetnsDir {
                path: Self::PERSIST_DIR,
                source,
            })
            .with_context(|| format!("fs::create_dir_all(\"{}\")", Self::PERSIST_DIR))?;
        let ns_path = Path::new(Self::PERSIST_DIR).join(&name);
        let _unused: fs::File =
            fs::File::create(&ns_path).map_err(|source| AyaTestError::CreateNetns {
                path: ns_path,
                source,
            })?;
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)
            .map_err(|source| AyaTestError::EnterNetns(source))?;

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
        .map_err(|source| AyaTestError::BindMountNetns {
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

impl Default for NetNsGuard {
    fn default() -> Self {
        Self::new().expect("NetNsGuard::new")
    }
}

impl AsFd for NetNsGuard {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.new_ns.as_fd()
    }
}

impl Drop for NetNsGuard {
    #[expect(
        clippy::print_stderr,
        reason = "drop handlers avoid panic-in-panic by logging errors"
    )]
    #[expect(
        clippy::use_debug,
        reason = "debug formatting preserves error context in drop"
    )]
    fn drop(&mut self) {
        let Self {
            old_ns,
            name,
            new_ns: _,
        } = self;
        match (|| -> Result<()> {
            nix::sched::setns(old_ns, nix::sched::CloneFlags::CLONE_NEWNET)
                .context("nix::sched::setns(_, CLONE_NEWNET)")?;
            let ns_path = Path::new(Self::PERSIST_DIR).join(name);
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

/// If the current kernel version is at least `$version`, assert `$cond`; otherwise assert
/// `!$cond`.
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

/// If the current kernel version is at least `$version`, assert equality; otherwise assert
/// inequality.
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
