#include <stdio.h>
#include <assert.h>
#include <linux/bpf.h>
#include "prototype-kernel/kernel/samples/bpf/tools/lib/bpf/bpf.h"
#include "prototype-kernel/kernel/samples/bpf/tools/lib/bpf/libbpf.h"
#include <stdlib.h>
#include <linux/unistd.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <asm-generic/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <arpa/inet.h>

static int open_rawsock(const char *name) {
    struct sockaddr_ll sll;
    int sock_fd;

    sock_fd = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        printf("cannot create raw socket\n");
        return -1;
    }
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = if_nametoindex(name);
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        printf("bind to %s: %s\n", name, strerror(errno));
		close(sock_fd);
		return -1;
    }
    return sock_fd;
};

int main (int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_prog_load_attr prog_attr;
    int map_fd, prog_fd;
    char filename[256];

    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
    prog_attr.file = filename;
    prog_attr.log_level = 2;
    prog_attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    //Load program
    if (bpf_prog_load_xattr(&prog_attr, &obj, &prog_fd)) {
        return 1;
    }
    map_fd = bpf_object__find_map_fd_by_name(obj, "my_map");

    int sock_fd = open_rawsock("lo");
    assert(setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
			  sizeof(prog_fd)) == 0);
    
    FILE *f = popen("ping -4 -c5 localhost", "r");
    (void) f;

    for (int i=0; i < 5; i++) {
        long long tcp_cnt, udp_cnt, icmp_cnt;
		int key;

		key = IPPROTO_TCP;
		assert(bpf_map_lookup_elem(map_fd, &key, &tcp_cnt) == 0);

		key = IPPROTO_UDP;
		assert(bpf_map_lookup_elem(map_fd, &key, &udp_cnt) == 0);

		key = IPPROTO_ICMP;
		assert(bpf_map_lookup_elem(map_fd, &key, &icmp_cnt) == 0);

		printf("TCP %lld UDP %lld ICMP %lld bytes\n",
		       tcp_cnt, udp_cnt, icmp_cnt);
		sleep(1);
    }
    return 0;
}