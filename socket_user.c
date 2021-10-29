#include <stdio.h>
#include <assert.h>
#include <linux/bpf.h>
#include "prototype-kernel/kernel/samples/bpf/tools/lib/bpf/bpf.h"
#include "prototype-kernel/kernel/samples/bpf/tools/lib/bpf/libbpf.h"
#include <unistd.h>
#include <arpa/inet.h>

int main (int argc, char **argv) {
    struct bpf_object *obj;
    int map_fd, prog_fd;
    char filename[256];
    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
}