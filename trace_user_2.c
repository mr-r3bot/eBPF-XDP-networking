#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/hw_breakpoint.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include "prototype-kernel/kernel/samples/bpf/tools/lib/bpf/bpf.h"
#include "prototype-kernel/kernel/samples/bpf/tools/lib/bpf/libbpf.h"


int main(int argc, char **argv) {
    char verifier_log_outputp[0x200000] = {0};
    union bpf_attr prog_attr = {

    };
}