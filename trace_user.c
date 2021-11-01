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

void read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	while (1) {
		static char buf[4096];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
};

int main(int argc, char **argv) {
    struct bpf_object *obj;
    int prog_fd;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    // struct perf_event_attr pattr = {};
    struct bpf_prog_load_attr prog_attr = {
        .log_level = 2,
        .prog_type = BPF_PROG_TYPE_TRACEPOINT
    };

    prog_attr.file = "trace_kern.o";
    //Load program
    if (bpf_prog_load_xattr(&prog_attr, &obj, &prog_fd)) {
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "bpf_prog1");
    if (libbpf_get_error(prog)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        goto cleanup;
    }

    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: bpf_prog__attach failed\n");
        goto cleanup;
    }
    read_trace_pipe();
    

cleanup:
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}