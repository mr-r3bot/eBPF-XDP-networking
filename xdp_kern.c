#include <linux/bpf.h> 
#include <linux/in.h> 
#include <linux/if_ether.h> 
#include <linux/if_packet.h> 
#include <linux/if_vlan.h> 
#include <linux/ip.h> 
#include <linux/ipv6.h>
#include "prototype-kernel/kernel/samples/bpf/bpf_helpers.h"
#include "prototype-kernel/kernel/samples/bpf/bpf_endian.h"

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct bpf_map_def SEC("maps") rxcnt = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(long),
    .max_entries = 256
};

static int parse_ipv4(void *data_begin, __u64 eth_off, void *data_end) {
    struct iphdr *ipv4 = data_begin + eth_off;
    if (ipv4 + 1 > data_end) 
        return 0;

    return ipv4->protocol;
}

static int parse_ipv6(void *data_begin, __u64 eth_off, void *data_end) {
    struct ipv6hdr *ipv6 = data_begin + eth_off;
    if (ipv6 + 1 > data_end) {
        return 0;
    }
    return ipv6->nexthdr;
}

SEC("xdp1")
int xdp_prog1(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data_begin = (void *)(long)ctx->data;

    struct ethhdr *eth = data_begin;
    __u64 eth_off = sizeof(*eth);
    __u32 ipproto;
    
    //Check boundary for eBPF verifier
    if (data_begin + 1 > data_end) {
        return XDP_DROP;
    }

    __u16 h_proto = eth->h_proto;

    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr = data_begin + eth_off;
        eth_off += sizeof(struct vlan_hdr);
        if (data_begin + eth_off > data_end) {
            return XDP_DROP;
        }
        h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    if (h_proto == bpf_htons(ETH_P_IP)) {
        ipproto = parse_ipv4(data_begin, eth_off, data_end);
    } 
    else if (h_proto == bpf_htons(ETH_P_IPV6)){
        ipproto = parse_ipv6(data_begin, eth_off, data_end);
    }
    else
        ipproto = 0;

    // This function returns a pointer to the current value stored in the map if it exists, or NULL otherwise.
    // This address can be used to change the stored data directly, without the need for a map update operation.
    long *value;
    value = bpf_map_lookup_elem(&rxcnt, &ipproto);
    if (value)
        *value +=1;
    
    return XDP_DROP;
}


char _license[] SEC("license") = "GPL";
