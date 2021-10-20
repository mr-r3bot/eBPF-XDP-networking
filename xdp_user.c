#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/resource.h>
#include <net/if.h>

#include "prototype-kernel/kernel/samples/bpf/bpf_util.h"
#include "prototype-kernel/kernel/samples/bpf/bpf.h"
#include "prototype-kernel/kernel/samples/bpf/libbpf.h"

static void usage(void *prog) {
    fprintf(stderr,
		"usage: %s [OPTS] IFACE\n\n"
		"OPTS:\n"
		"    -S    use skb-mode\n"
		"    -N    enforce native mode\n"
		"    -F    force loading prog\n",
		prog);
}

int main(int argc, char **argv) {
    // Load XDP type program from Kernel
    struct bpf_prog_load_attr pro_load_attr = {
        .prog_type = BPF_PROG_TYPE_XDP
    }
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
}