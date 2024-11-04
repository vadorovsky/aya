use std::{
    fs::File,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
};

use aya::{
    programs::{links::FdLink, Iter, Link},
    Btf, Ebpf,
};
use test_log::test;
use tokio::io::unix::AsyncFd;

#[test]
fn iter_tcp4() {
    let mut ebpf = Ebpf::load(crate::ITER).unwrap();
    let btf = Btf::from_sys_fs().unwrap();
    let prog: &mut Iter = ebpf.program_mut("iter_tcp4").unwrap().try_into().unwrap();
    prog.load("tcp", &btf).unwrap();
}

#[test]
fn iter_task() {
    let mut ebpf = Ebpf::load(crate::ITER_TASK).unwrap();
    let btf = Btf::from_sys_fs().unwrap();
    let prog: &mut Iter = ebpf.program_mut("iter_task").unwrap().try_into().unwrap();
    prog.load("task", &btf).unwrap();

    let link_id = prog.attach().unwrap();
    println!("link_id: {link_id:?}");

    let link = prog.take_link(link_id).unwrap();
    println!("link: {link:?}");

    let fd_iter = link.create_iter().unwrap();
    println!("fd_iter: {fd_iter:?}");

    // let mut file = unsafe { File::from_raw_fd(fd_iter.as_raw_fd()) };
}

#[test(tokio::test)]
async fn iter_async_task() {
    let mut ebpf = Ebpf::load(crate::ITER_TASK).unwrap();
    let btf = Btf::from_sys_fs().unwrap();
    let prog: &mut Iter = ebpf.program_mut("iter_task").unwrap().try_into().unwrap();
    prog.load("task", &btf).unwrap();

    let link_id = prog.attach().unwrap();
    println!("link_id: {link_id:?}");

    let link = prog.take_link(link_id).unwrap();
    println!("link: {link:?}");

    let fd_iter = link.create_iter().unwrap();
    println!("fd_iter: {fd_iter:?}");

    let mut async_fd = AsyncFd::new(fd_iter.as_fd()).unwrap();

    let mut guard = async_fd.readable().await.unwrap();
    if guard.ready().is_readable() {
        guard.get_inner().read();
    }
}
