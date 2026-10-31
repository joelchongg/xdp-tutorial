/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#define VLAN_MAX_DEPTH 4

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	char *pos;
};

/* vlan tag header */
struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
        return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
                  h_proto == bpf_htons(ETH_P_8021AD));
}

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in network byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = (struct ethhdr *) nh->pos;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (eth + 1 > data_end) {
		return -1;
	}

	nh->pos += hdrsize;
	*ethhdr = eth;

	int next_proto = eth->h_proto;
	struct vlan_hdr *vlan;

	#pragma unroll
	for (int i = 0; i < VLAN_MAX_DEPTH; ++i) {
		if (!proto_is_vlan(next_proto)) {
			break;
		}

		vlan = (struct vlan_hdr *) nh->pos;
		int vlan_hdrsize = sizeof(*vlan);

		if (vlan + 1 > data_end) {
			return -1;
		}

		nh->pos += vlan_hdrsize;
		next_proto = vlan->h_vlan_encapsulated_proto;
	}

	return next_proto; /* network-byte-order */
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr) {
	struct ipv6hdr *ipv6 = (struct ipv6hdr *) nh->pos;
	int hdrsize = sizeof(*ipv6);

	if (ipv6 + 1 > data_end) {
		return -1;
	}

	nh->pos += hdrsize;
	*ip6hdr = ipv6;

	return ipv6->nexthdr;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr) {
	struct icmp6hdr *icmpv6 = (struct icmp6hdr *) nh->pos;
	int hdrsize = sizeof(*icmpv6);

	if (icmpv6 + 1 > data_end) {
		return -1;
	}

	nh->pos += hdrsize;
	*icmp6hdr = icmpv6;

	return icmpv6->icmp6_type;
}

static __always_inline int parse_ipv4hdr(struct hdr_cursor *nh, void *data_end, struct iphdr** ipv4hdr) {
	struct iphdr *ipv4 = (struct iphdr *) nh->pos;
	if (ipv4 + 1 > data_end) {
		return -1;
	}
	
	int hdrsize = ipv4->ihl * 4;
	if (hdrsize < sizeof(*ipv4) || nh->pos + hdrsize > data_end) {
		return -1;
	}

	nh->pos += hdrsize;
	*ipv4hdr = ipv4;

	return ipv4->protocol;
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh, void *data_end, struct icmphdr** icmphdr) {
	struct icmphdr *icmp = (struct icmphdr *) nh->pos;
	if (icmp + 1 > data_end) {
		return -1;
	}

	nh->pos += sizeof(*icmp);
	*icmphdr = icmp;

	return icmp->type;
}

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = (char *) data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *ipv4;
		nh_type = parse_ipv4hdr(&nh, data_end, &ipv4);
		if (nh_type != IPPROTO_ICMP) {
			goto out;
		}

		struct icmphdr *icmpv4 = NULL;
		nh_type = parse_icmphdr(&nh, data_end, &icmpv4);
		if (!icmpv4 || icmpv4 + 1 > data_end) {
			goto out;
		}

		__u16 seq = bpf_ntohs(icmpv4->un.echo.sequence);

		/* only drop even sequence number ICMP packets */
		if (!(seq & 1)) {
			action = XDP_DROP;
		}
	} else if (nh_type == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6;
		nh_type = parse_ip6hdr(&nh, data_end, &ip6);
		if (nh_type != IPPROTO_ICMPV6) {
			goto out;
		}

		struct icmp6hdr *icmp6 = NULL;
		nh_type = parse_icmp6hdr(&nh, data_end, &icmp6);
		if (!icmp6 || icmp6 + 1 > data_end) {
			goto out;
		}

		__u16 seq = bpf_ntohs(icmp6->icmp6_sequence);

		/* only drop even sequence number ICMP packets */
		if (!(seq & 1)) {
			action = XDP_DROP;
		}
	}
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
