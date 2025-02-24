// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
// clang-format on

char _license[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, __u32);
} task_storage SEC(".maps");

void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter, struct pt_regs *regs, long id) {
  __u32 value = 1;
  struct task_struct *task = bpf_get_current_task_btf();
  // This test is triggered by a Rust test, running in a thread. A current task
  // (the one returned by `bpf_get_current_task()`) represents that thread. If
  // we create a task storage entry for that task, our user-space test will not
  // be able to retrieve it as pidfd.
  // To make retrieval of the map element by pidfd possible, we need to use the
  // `group_leader` (a `struct task_struct*` instance representing the process)
  // as the key.
  bpf_rcu_read_lock();
  struct task_struct *group_leader = BPF_CORE_READ(task, group_leader);
  bpf_task_storage_get(&task_storage, group_leader, &value,
                       BPF_LOCAL_STORAGE_GET_F_CREATE);
  bpf_rcu_read_unlock();

  return 0;
}
