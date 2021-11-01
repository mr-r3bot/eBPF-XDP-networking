#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/bpf.h>
#include <stdio.h>
#include "prototype-kernel/kernel/samples/bpf/bpf_helpers.h"
#include "trace_common.h"

// struct bpf_map_def SEC("maps") my_map = {
//     .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
//     .key_size = sizeof(int),
//     .value_size = sizeof(__u32),
//     .max_entries = 2
// };

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog1(void *ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    char msg[sizeof(comm)];
    bpf_probe_read(msg, sizeof(msg), comm);
    bpf_trace_printk(msg, sizeof(msg));
    return 0;
}

char _license[] SEC("license") = "GPL";
