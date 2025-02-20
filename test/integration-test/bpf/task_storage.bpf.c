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

SEC("fexit/sched_post_fork")
int BPF_PROG(sched_post_fork, struct task_struct *task) {
  __u32 value = 1;
  bpf_task_storage_get(&task_storage, task, &value,
                       BPF_LOCAL_STORAGE_GET_F_CREATE);
  pid_t pid = BPF_CORE_READ(task, pid);
  bpf_printk("sched_post_fork: pid: %d\n", pid);

  // struct task_struct *parent = bpf_get_current_task_btf();
  struct task_struct *parent = BPF_CORE_READ(task, real_parent);
  bpf_task_storage_get(&task_storage, parent, &value,
                       BPF_LOCAL_STORAGE_GET_F_CREATE);
  pid_t ppid = BPF_CORE_READ(parent, pid);
  bpf_printk("sched_post_fork: ppid: %d\n", ppid);

  return 0;
}

SEC("raw_tracepoint/sched_process_fork")
int BPF_PROG(sched_process_fork, struct task_struct *parent,
             struct task_struct *child)
{
  bpf_task_storage_get(&task_storage, parent, &value,
                       BPF_LOCAL_STORAGE_GET_F_CREATE);
  pid_t pid = BPF_CORE_READ(parent, pid);
  bpf_printk("sched_process_ork: pid: %d\n", pid);

  return 0;
}

SEC("fexit/security_file_open")
int BPF_PROG(security_file_open) {
  struct task_struct *task = bpf_get_current_task_btf();
  __u32 value = 1;
  bpf_task_storage_get(&task_storage, task, &value,
                       BPF_LOCAL_STORAGE_GET_F_CREATE);
  pid_t pid = BPF_CORE_READ(task, pid);
  bpf_printk("security_file_open: pid: %d\n", pid);

  return 0;
}
