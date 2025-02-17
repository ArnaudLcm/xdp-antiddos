#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#define BASE_THRESHOLD 500            // Initial allowed packets per second
#define SYN_THRESHOLD 100             // Initial allowed SYN packets per second
#define TIME_WINDOW_NS 1000000000     // 1 second in nanoseconds
#define DECAY_FACTOR 0.9              // Reduce threshold if abuse detected
#define RECOVERY_FACTOR 1.1           // Recover if normal traffic
#define MAP_MAX_ENTRIES 4096

struct rate_limit {
    __u64 last_time;
    __u64 packet_count;
    __u64 threshold;
};

struct syn_rate_limit {
    __u64 last_time;
    __u64 syn_count;
    __u64 syn_threshold;
};

struct key_t {
    __u32 ip;
    __u16 port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAP_MAX_ENTRIES);
    __type(key, struct key_t);
    __type(value, struct rate_limit);
} rate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAP_MAX_ENTRIES);
    __type(key, __u32);  // Only need IP for SYN flood detection
    __type(value, struct syn_rate_limit);
} syn_rate_map SEC(".maps");

static __always_inline int packet_checker(struct xdp_md *ctx, struct iphdr *ip, void *l4_header, __u8 protocol) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if ((void *)(ip + 1) > data_end) return 0;  // Invalid IP header

    if (ip->ihl < 5 || ip->version != 4) return 0;

    __u32 ip_hlen = ip->ihl * 4;
    if ((void *)ip + ip_hlen > data_end) return 0;  // Invalid header length

    void *l4_start = (void *)ip + ip_hlen;
    if (l4_start > data_end || l4_header < data || l4_header >= data_end) return 0;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_header;
        if ((void *)(tcp + 1) > data_end) return 0;
        if (tcp->doff < 5) return 0;
        if ((void *)tcp + (tcp->doff * 4) > data_end) return 0;

    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4_header;
        if ((void *)(udp + 1) > data_end) return 0;
        __u16 udp_len = bpf_ntohs(udp->len);
        if (udp_len < sizeof(struct udphdr) || (void *)udp + udp_len > data_end) return 0;
    }

    return 1;
}

static __always_inline __u16 extract_port(void *l4_header, __u8 protocol) {
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_header;
        return bpf_ntohs(tcp->source);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4_header;
        return bpf_ntohs(udp->source);
    }
    return 0;
}

static __always_inline int rate_limiter(struct xdp_md *ctx, struct iphdr *ip, __u16 port) {
    struct key_t key = { .ip = ip->saddr, .port = port };
    __u64 now = bpf_ktime_get_ns();  // Get time in nanoseconds
    struct rate_limit *entry = bpf_map_lookup_elem(&rate_map, &key);

    if (!entry) {
        // Initialize new rate limit entry
        struct rate_limit new_entry = {
            .last_time = now,
            .packet_count = 1,
            .threshold = BASE_THRESHOLD
        };
        bpf_map_update_elem(&rate_map, &key, &new_entry, BPF_ANY);
        return XDP_PASS;
    }

    __u64 elapsed = now - entry->last_time;

    if (elapsed > TIME_WINDOW_NS) {
        // Adjust threshold dynamically based on previous traffic
        if (entry->packet_count > entry->threshold) {
            entry->threshold *= DECAY_FACTOR;  // Reduce if abuse detected
        } else {
            entry->threshold *= RECOVERY_FACTOR;  // Recover if normal
        }
        entry->threshold = entry->threshold < 50 ? 50 : entry->threshold;  // Min limit
        entry->packet_count = 1;
        entry->last_time = now;
    } else {
        // Count packet
        entry->packet_count++;
        if (entry->packet_count > entry->threshold) {
            return XDP_DROP;  // Drop if rate exceeded
        }
    }

    bpf_map_update_elem(&rate_map, &key, entry, BPF_ANY);
    return XDP_PASS;
}

static __always_inline int syn_flood_detector(struct xdp_md *ctx, struct iphdr *ip, struct tcphdr *tcp) {
    __u32 ip_key = ip->saddr;
    __u64 now = bpf_ktime_get_ns();
    struct syn_rate_limit *syn_entry = bpf_map_lookup_elem(&syn_rate_map, &ip_key);

    if (!syn_entry) {
        // Initialize new SYN rate limit entry
        struct syn_rate_limit new_syn_entry = {
            .last_time = now,
            .syn_count = 1,
            .syn_threshold = SYN_THRESHOLD
        };
        bpf_map_update_elem(&syn_rate_map, &ip_key, &new_syn_entry, BPF_ANY);
        return XDP_PASS;
    }

    __u64 elapsed = now - syn_entry->last_time;

    if (elapsed > TIME_WINDOW_NS) {
        // Adjust SYN threshold dynamically based on previous traffic
        if (syn_entry->syn_count > syn_entry->syn_threshold) {
            syn_entry->syn_threshold *= DECAY_FACTOR;  // Reduce if abuse detected
        } else {
            syn_entry->syn_threshold *= RECOVERY_FACTOR;  // Recover if normal
        }
        syn_entry->syn_threshold = syn_entry->syn_threshold < 10 ? 10 : syn_entry->syn_threshold;  // Min limit
        syn_entry->syn_count = 1;
        syn_entry->last_time = now;
    } else {
        // Count SYN packet
        syn_entry->syn_count++;
        if (syn_entry->syn_count > syn_entry->syn_threshold) {
            return XDP_DROP;  // Drop if SYN rate exceeded
        }
    }

    bpf_map_update_elem(&syn_rate_map, &ip_key, syn_entry, BPF_ANY);
    return XDP_PASS;
}

SEC("xdp") int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    __u16 eth_type = bpf_ntohs(eth->h_proto);
    if (eth_type != ETH_P_IP) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_DROP;

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) return XDP_PASS;

    void *l4_header = (void *)ip + ip->ihl * 4;
    if (l4_header > data_end) return XDP_PASS;

    if (!packet_checker(ctx, ip, l4_header, ip->protocol)) return XDP_DROP;  // Drop bad packets

    __u16 port = extract_port(l4_header, ip->protocol);
    if (port == 0) return XDP_PASS;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_header;
        if (tcp->syn && !tcp->ack) {
            // Check for SYN Flood
            int syn_result = syn_flood_detector(ctx, ip, tcp);
            if (syn_result == XDP_DROP) {
                return XDP_DROP;
            }
        }
    }

    return rate_limiter(ctx, ip, port);
}

char _license[] SEC("license") = "GPL";