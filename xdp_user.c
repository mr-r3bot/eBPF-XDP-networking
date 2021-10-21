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
#include "prototype-kernel/kernel/samples/bpf/tools/lib/bpf/libbpf.h"

static int ifindex;
static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static __u32 prog_id;

static void int_exit(int sig) {
    __u32 current_prog_id = 0;
    if (bpf_get_link_xdp_id(ifindex, &current_prog_id, xdp_flags)) {
		printf("bpf_get_link_xdp_id failed\n");
		exit(1);
	}
	if (prog_id == current_prog_id)
		bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
	else if (!current_prog_id)
		printf("couldn't find a prog id on a given interface\n");
	else
		printf("program on interface changed, not removing\n");
	exit(0);
}

static void usage(void *prog) {
    fprintf(stderr,
		"usage: %s [OPTS] IFACE\n\n"
		"OPTS:\n"
		"    -S    use skb-mode\n"
		"    -N    enforce native mode\n"
		"    -F    force loading prog\n",
		prog);
}

static void poll_stats(int map_fd, int interval) {
    
}

int main(int argc, char **argv) {
    // Load XDP type program from Kernel
    struct bpf_prog_load_attr pro_load_attr = {
        .prog_type = BPF_PROG_TYPE_XDP
    };
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    const char *optstr = "FSN";
    int prog_fd, map_fd, opt;

    struct bpf_object *obj;
    struct bpf_map *map;
    char filename[256];
    int err;

    while ((opt = getopt(argc, argv, optstr)) != -1) {
        switch (opt) {
        case 'S':
            // OR bitwise
            xdp_flags |= XDP_FLAGS_SKB_MODE;
            break;
        case 'N':
            //default
            break;
        case 'F':
            // AND and NOT bitwise operator
            xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
            break;
        default:
            usage(basename(argv[0]));
            return 1;
        }
    }

    if (!(xdp_flags & XDP_FLAGS_SKB_MODE)) {
        xdp_flags |= XDP_FLAGS_DRV_MODE;
    }

    if (optind == argc) {
		usage(basename(argv[0]));
		return 1;
	}

	ifindex = if_nametoindex(argv[optind]);
	if (!ifindex) {
		perror("if_nametoindex");
		return 1;
	}

    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
    pro_load_attr.file = filename;
    // Loading eBPF program to kernel
    // obj: contains detailed information of code loaded in kernel
    // prog_fd: file descriptor of program
    if (bpf_prog_load_xattr(&pro_load_attr, &obj, &prog_fd)) {
        return 1;
    }
    // obtain map
    // Return an iteratorfor list of maps declared in prog
    map = bpf_map__next(NULL, obj);
    if (!map) {
        printf("failed to obtain map in obj file\n");
        return 1;
    }

    // Obtain file descriptor of the map
    // Since in this case, there is only one map so we can pass *map directly to the function
    map_fd = bpf_map__fd(map);
    if (!prog_fd) {
		printf("bpf_prog_load_xattr: %s\n", strerror(errno));
		return 1;
	}

    // Attached eBPF program to interface
    if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
        printf("link set xdp fd failed\n");
        return 1;
    }

    err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		printf("can't get prog info - %s\n", strerror(errno));
		return err;
	}
	prog_id = info.id;
	poll_stats(map_fd, 2);
	return 0;
}