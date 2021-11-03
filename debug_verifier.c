#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <linux/version.h>
#include <linux/hw_breakpoint.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include "prototype-kernel/kernel/samples/bpf/tools/lib/bpf/bpf.h"
#include "prototype-kernel/kernel/samples/bpf/tools/lib/bpf/libbpf.h"


int main(int argc, char **argv) {
    char verifier_log_output[0x200000] = {0};
    unsigned char buf[1024] = {};
    int bfd;
    int n;
    struct bpf_insn *insn;

    bfd = open("bin/trace_kern.o", O_RDONLY);
    if (bfd < 0)
    {
        fprintf(stderr, "Unable to open BPF object file\n");
        exit(1);
    }

    n = read(bfd, buf, sizeof(buf));
    close(bfd);
    insn = (struct bpf_insn*)buf;
    union bpf_attr prog_attr = {
        .prog_type = BPF_PROG_TYPE_TRACEPOINT,
        .insns = (uint64_t)insn,
        .insn_cnt = n / sizeof(struct bpf_insn),
        .license = (uint64_t)"",
        .log_level = 2,
        .log_size = sizeof(verifier_log_output),
        .log_buf = (uint64_t)verifier_log_output
    };

    int pdf = syscall(SYS_bpf, BPF_PROG_LOAD, &prog_attr, sizeof(prog_attr));
    if (pdf < 0 ) {
        fprintf(stderr, "Unable to load program:\n");
        printf("Log buf:\n%s\n", verifier_log_output);
        exit(-1);
    }
}