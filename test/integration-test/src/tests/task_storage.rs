use std::{
    process,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::{self, sleep},
    time::Duration,
};

use aya::{maps::TaskStorage, programs::FExit, Btf, Ebpf};
use test_log::test;

#[test]
fn test_task_storage_get() {
    let mut ebpf = Ebpf::load(crate::TASK_STORAGE).unwrap();

    let prog: &mut FExit = ebpf
        .program_mut("sched_post_fork")
        .unwrap()
        .try_into()
        .unwrap();
    let btf = Btf::from_sys_fs().unwrap();
    prog.load("sched_post_fork", &btf).unwrap();
    prog.attach().unwrap();

    let task_storage: TaskStorage<_, u32> =
        TaskStorage::try_from(ebpf.map_mut("task_storage").unwrap()).unwrap();

    let pair = Arc::new((Mutex::new(None), Condvar::new()));
    let stop = Arc::new(AtomicBool::new(false));

    let child = thread::spawn({
        let pair = Arc::clone(&pair);
        let stop = Arc::clone(&stop);
        move || {
            // `task_struct.pid`[0] in the kernel doesn't differentiate between
            // PID and TID
            let pid = unsafe { libc::getpid() } as u32;
            let tid = unsafe { libc::gettid() } as u32;
            println!("pid: {pid}, tid: {tid}");

            let (lock, cvar) = &*pair;
            *lock.lock().unwrap() = Some(tid);
            cvar.notify_one();

            while !stop.load(Ordering::Relaxed) {
                sleep(Duration::from_millis(100));
            }
        }
    });

    let (lock, cvar) = &*pair;
    let mut tid = lock.lock().unwrap();
    while tid.is_none() {
        tid = cvar.wait(tid).unwrap();
    }
    let tid = tid.unwrap();

    sleep(Duration::from_millis(100));

    let value = task_storage.get(&tid, 0).unwrap();
    assert_eq!(value, 1);

    stop.store(true, Ordering::Relaxed);
    child.join().unwrap();
}
