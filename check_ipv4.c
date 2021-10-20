
#include <linux/bpf.h> 
#include <linux/if_ether.h>
#include <linux/ip.h> 
#include <linux/tcp.h> 
#include <linux/in.h> 
#include "prototype-kernel/kernel/samples/bpf/bpf_helpers.h"
#include "prototype-kernel/kernel/samples/bpf/bpf_endian.h"

SEC("xdp_ipv4")
int is_ipv4(struct xdp_md *ctx) {
    char msg[] = "Got a packet\n";
    bpf_trace_printk(msg,sizeof(msg));
    void *data_end = (void *)(long)ctx->data_end;
    void *data_begin = (void *)(long)ctx->data;
    struct ethhdr *eth = data_begin;

    // Check bound 1
    if (eth + 1 > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ipv4 = (struct iphdr *)(((void *)eth) + ETH_HLEN);
        //Check bound 2
        if (ipv4 + 1 > data_end) {
            return XDP_PASS;
        }
    
        if (ipv4->protocol == IPPROTO_TCP)
            return XDP_PASS;
    }
    // If not check boundary, program will be rejected by eBPF verifier
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
