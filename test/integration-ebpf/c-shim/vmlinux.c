#include "vmlinux.h"
#include <bpf/bpf_core_read.h>

int task_struct_tgid(struct task_struct *task) {
  return BPF_CORE_READ(task, tgid);
}
