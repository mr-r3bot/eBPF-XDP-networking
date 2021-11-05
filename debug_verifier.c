#include <linux/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include "prototype-kernel/kernel/samples/bpf/tools/lib/bpf/bpf.h"
#include "prototype-kernel/kernel/samples/bpf/tools/lib/bpf/libbpf.h"
#include "bpf_insn.h"


int main(int argc, char **argv) {
    char verifier_log_output[0x200000] = {0};
    int sock = -1, map_fd, prog_fd, key;
    long long value = 0, tcp_cnt, udp_cnt, imcp_cnt;
    map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value), 256, 0);
    if (map_fd < 0) {
        fprintf(stderr, "Unable to create map\n");
        exit(-1);
    }
    struct bpf_insn prog[] = {
        // program context (input) is stored at r1 register, we move it to r6 as backup because 
        // r1 will be used as arguments for function call during program execution
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
        // Loads a byte (BPF_B) into r0 from an offsetin the context buffer ( which is the network packet buffer in this case)
        // we supply the offset of the protocol byte from an iphdr structure to be loaded into r0.
        BPF_LD_ABS(BPF_B, ETH_HLEN + offsetof(struct iphdr, protocol)),
        // Push the word (BPF_W) containing the previously read protocol on the stack (pointed by r10 starting with offset -4 bytes).
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        //Load the local in-process file descriptor referencing the map containing protocol packet counts into r1
        BPF_LD_MAP_FD(BPF_REG_1, map_fd),
        //Execute the map lookup call with the protocol value from the stack, pointed at by r2, as key. 
        // The result is stored in r0: a pointer address to the value indexed by the key.
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        // If the map_lookup_elem is not succeed ( value stored at r0 = 0 ). Jump ( skip 2 instructions)
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
        // if r0 != 0
        BPF_MOV64_IMM(BPF_REG_1, 1),
        // xadd: r0 = ro + r1
        // Increment the map value at the address pointed to by r0
        BPF_RAW_INSN(BPF_STX | BPF_XADD | BPF_DW, BPF_REG_0, BPF_REG_1, 0, 0),
        // Move result of the program execution to r0 (eBPF program return 0 and then exit)
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN()
    };

    size_t insn_cnt = sizeof(prog) / sizeof(struct bpf_insn);

    union bpf_attr prog_attr = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insns = (uint64_t)prog,
        .insn_cnt = insn_cnt,
        .license = (uint64_t)"",
        .log_level = 2,
        .log_size = sizeof(verifier_log_output),
        .log_buf = (uint64_t)verifier_log_output
    };

    int pdf = syscall(SYS_bpf, BPF_PROG_LOAD, &prog_attr, sizeof(prog_attr));
    if (pdf < 0 ) {
        fprintf(stderr, "Unable to load program\n");
        printf("Log buf:\n%s\n", verifier_log_output);
        exit(-1);
    }
}