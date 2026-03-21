//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_PEERS 1024

// Define the expected map types correctly
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // Use IP address as key for simplicity in C
    __type(value, __u32); // Policy flags (e.g., 1=allow, 0=block)
    __uint(max_entries, MAX_PEERS);
} allowed_peers SEC(".maps");

struct token_bucket {
    __u64 tokens;
    __u64 last_update;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32); // src_ip
    __type(value, struct token_bucket);
    __uint(max_entries, 10000);
} rate_limiter SEC(".maps");

struct flow_tuple {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct conn_state {
    __u32 state;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_tuple);
    __type(value, struct conn_state);
    __uint(max_entries, 65535);
} conn_track SEC(".maps");

SEC("xdp")
int xdp_ingress_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    __u32 *policy = bpf_map_lookup_elem(&allowed_peers, &src_ip);
    if (policy) {
        if (*policy == 1) {
            return XDP_PASS; // Authorized
        }
    }

    // Default deny if not in allowed_peers or policy is 0
    return XDP_DROP;
}

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb) {
    // TC ingress logic, similar lookup but via skb
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __u32 src_ip = ip->saddr;

    __u32 *policy = bpf_map_lookup_elem(&allowed_peers, &src_ip);
    if (policy && *policy == 1) {
        return TC_ACT_OK;
    }

    return TC_ACT_SHOT; // Drop packet
}

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __u32 dst_ip = ip->daddr;

    __u32 *policy = bpf_map_lookup_elem(&allowed_peers, &dst_ip);
    if (policy && *policy == 1) {
        return TC_ACT_OK;
    }

    // Default deny for egress to unauthorized peers
    return TC_ACT_SHOT;
}

char __license[] SEC("license") = "Dual MIT/GPL";