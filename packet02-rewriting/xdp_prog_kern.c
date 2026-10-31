/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Pops the outermost VLAN tag off the packet. Returns the popped VLAN ID on
 * success or -1 on failure.
 */
static __always_inline int vlan_tag_pop(struct xdp_md *ctx, struct ethhdr *eth)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr eth_cpy;
	struct vlan_hdr *vlh;
	__be16 h_proto;
	int vlid = -1;

	/* Check if there is a vlan tag to pop */
	if (!proto_is_vlan(eth->h_proto)) {
		return -1;
	}

	/* Still need to do bounds checking */
	if (eth + 1 > data_end) {
		return -1;
	}

	/* Save vlan ID for returning, h_proto for updating Ethernet header */
	vlh = (struct vlan_hdr *)(eth + 1);
	if (vlh + 1 > data_end) {
		return -1;
	}
	vlid = bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK;
	h_proto = vlh->h_vlan_encapsulated_proto;


	/* Make a copy of the outer Ethernet header before we cut it off */
	__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

	/* Actually adjust the head pointer */
	if (bpf_xdp_adjust_head(ctx, (int)sizeof(*vlh))) {
		return -1;
	}

	/* Need to re-evaluate data *and* data_end and do new bounds checking
	 * after adjusting head
	 */
	void *data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	struct ethhdr *new_eth_hdr = (struct ethhdr *)data;
	if (new_eth_hdr + 1 > data_end) {
		return -1;
	}

	/* Copy back the old Ethernet header and update the proto type */
	__builtin_memcpy(new_eth_hdr, &eth_cpy, sizeof(eth_cpy));
	new_eth_hdr->h_proto = h_proto;

	return vlid;
}

/* Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
 * -1 on failure.
 */
static __always_inline int vlan_tag_push(struct xdp_md *ctx,
					 struct ethhdr *eth, int vlid) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr eth_cpy;

	if (eth + 1 > data_end) {
		return -1;
	}
	__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

	if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct vlan_hdr))) {
		return -1;
	}

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	struct ethhdr *new_eth_hdr = (struct ethhdr *)data;
	if (new_eth_hdr + 1 > data_end) {
		return -1;
	}
	__builtin_memcpy(new_eth_hdr, &eth_cpy, sizeof(eth_cpy));

	struct vlan_hdr *new_vlan_hdr = (struct vlan_hdr *)(new_eth_hdr + 1);
	if (new_vlan_hdr + 1 > data_end) {
		return -1;
	}
	new_vlan_hdr->h_vlan_TCI = bpf_htons(vlid);
	new_vlan_hdr->h_vlan_encapsulated_proto = eth_cpy.h_proto;
	new_eth_hdr->h_proto = bpf_htons(ETH_P_8021Q);
	
	return 0;
}

/* Implement assignment 1 in this section */
SEC("xdp")
int xdp_port_rewrite_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0) {
		return XDP_PASS;
	}
	nh_type = bpf_ntohs(nh_type);

	if (nh_type == ETH_P_IP) {
		struct iphdr *ip;
		nh_type = parse_iphdr(&nh, data_end, &ip);
	} else if (nh_type == ETH_P_IPV6) {
		struct ipv6hdr *ipv6;
		nh_type = parse_ip6hdr(&nh, data_end, &ipv6);
	} else {
		return XDP_PASS;
	}

	if (nh_type == IPPROTO_TCP) {
		struct tcphdr *tcp;
		nh_type = parse_tcphdr(&nh, data_end, &tcp);
		if (tcp + 1 > data_end) {
			return XDP_PASS;
		}
		tcp->dest = bpf_htons(bpf_ntohs(tcp->dest) - 1);
	} else if (nh_type == IPPROTO_UDP) {
		struct udphdr *udp;
		nh_type = parse_udphdr(&nh, data_end, &udp);
		if (udp + 1 > data_end) {
			return XDP_PASS;
		}
		udp->dest = bpf_htons(bpf_ntohs(udp->dest) - 1);
	}
	return XDP_PASS;
}

/* VLAN swapper; will pop outermost VLAN tag if it exists, otherwise push a new
 * one with ID 1. Use this for assignments 2 and 3.
 */
SEC("xdp")
int xdp_vlan_swap_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		return XDP_PASS;

	/* Assignment 2 and 3 will implement these. For now they do nothing */
	if (proto_is_vlan(eth->h_proto))
		vlan_tag_pop(ctx, eth);
	else
		vlan_tag_push(ctx, eth, 1);

	return XDP_PASS;
}

/* Solution to the parsing exercise in lesson packet01. Handles VLANs and legacy
 * IP (via the helpers in parsing_helpers.h).
 */
SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;
		struct icmp6hdr *icmp6h;

		nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
		if (nh_type != IPPROTO_ICMPV6)
			goto out;

		nh_type = parse_icmp6hdr(&nh, data_end, &icmp6h);
		if (nh_type != ICMPV6_ECHO_REQUEST)
			goto out;

		if (bpf_ntohs(icmp6h->icmp6_sequence) % 2 == 0)
			action = XDP_DROP;

	} else if (nh_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph;
		struct icmphdr *icmph;

		nh_type = parse_iphdr(&nh, data_end, &iph);
		if (nh_type != IPPROTO_ICMP)
			goto out;

		nh_type = parse_icmphdr(&nh, data_end, &icmph);
		if (nh_type != ICMP_ECHO)
			goto out;

		if (bpf_ntohs(icmph->un.echo.sequence) % 2 == 0)
			action = XDP_DROP;
	}
 out:
	return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
