// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_MASQUERADE_IPV4 1

#define TUNNEL_PROTOCOL		TUNNEL_PROTOCOL_VXLAN
#define ENCAP_IFINDEX		42
#define TUNNEL_MODE

#define CLIENT_IP		v4_pod_one
#define CLIENT_PORT		__bpf_htons(111)
#define CLIENT_SEC_IDENTITY	112233
#define CLIENT_NODE_IP		v4_node_one

#define FRONTEND_IP		v4_svc_one
#define FRONTEND_PORT		tcp_svc_one

#define LB_IP			v4_node_two
#define IPV4_DIRECT_ROUTING	LB_IP

#define BACKEND_IP		v4_pod_three
#define BACKEND_PORT		__bpf_htons(8080)
#define BACKEND_SEC_IDENTITY	223344
#define BACKEND_NODE_IP		v4_node_three

static volatile const __u8 *zero_mac = mac_zero;

struct mock_settings {
	__be16 nat_source_port;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct mock_settings));
	__uint(max_entries, 1);
} settings_map __section_maps_btf;

#include "node_config.h"

#define ctx_redirect mock_ctx_redirect
static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __ctx_buff *ctx __maybe_unused, int ifindex __maybe_unused,
		  __u32 flags __maybe_unused)
{
	/* in this scenario, all traffic should flow through the overlay interface */
	if (ifindex != ENCAP_IFINDEX)
		return CTX_ACT_DROP;

	return CTX_ACT_REDIRECT;
}

#define skb_get_tunnel_key mock_skb_get_tunnel_key
int mock_skb_get_tunnel_key(__maybe_unused struct __sk_buff *skb,
			    __maybe_unused struct bpf_tunnel_key *key,
			    __maybe_unused __u32 size,
			    __maybe_unused __u32 flags)
{
	/* hacky, this is actually only correct for the reply path. But
	 * at least for now the datapath doesn't care about the
	 * transported identity in the forward path.
	 */
	key->tunnel_id = BACKEND_SEC_IDENTITY;

	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bpf_tunnel_key));
	__uint(max_entries, 1);
} tunnel_key_map __section_maps_btf;

#define skb_set_tunnel_key mock_skb_set_tunnel_key
int mock_skb_set_tunnel_key(__maybe_unused struct __sk_buff *skb,
			    __maybe_unused const struct bpf_tunnel_key *key,
			    __maybe_unused __u32 size,
			    __maybe_unused __u32 flags)
{
	__u32 map_key = 0;
	struct bpf_tunnel_key *mock_key = map_lookup_elem(&tunnel_key_map, &map_key);

	if (mock_key)
		memcpy(mock_key, key, sizeof(*key));

	return 0;
}

#include "lib/bpf_overlay.h"

#include "lib/ipcache.h"
#include "lib/lb.h"

/* Test that a SVC request to an intermediate LB node gets DNATed and SNATed,
 * and flows back out on the overlay interface to a remote backend
 * (with WORLD_ID security identity).
 */
PKTGEN("tc", "nodeport_overlay_nat_1_fwd")
int nodeport_overlay_nat_1_fwd_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)zero_mac, (__u8 *)zero_mac,
					  CLIENT_IP, FRONTEND_IP,
					  CLIENT_PORT, FRONTEND_PORT);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "nodeport_overlay_nat_1_fwd")
int nodeport_overlay_nat_1_fwd_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service(FRONTEND_IP, FRONTEND_PORT, IPPROTO_UDP, 1, revnat_id);
	lb_v4_add_backend(FRONTEND_IP, FRONTEND_PORT, 1, 124,
			  BACKEND_IP, BACKEND_PORT, IPPROTO_UDP, 0);

	ipcache_v4_add_entry(BACKEND_IP, 0, BACKEND_SEC_IDENTITY,
			     BACKEND_NODE_IP, 0);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "nodeport_overlay_nat_1_fwd")
int nodeport_overlay_nat_1_fwd_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	__u32 key = 0;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l3->saddr != IPV4_GATEWAY)
		test_fatal("src IP hasn't been SNATed to gateway IP");

	if (l3->daddr != BACKEND_IP)
		test_fatal("dst IP hasn't been DNATed to backend IP");

	if (l4->dest != BACKEND_PORT)
		test_fatal("dst port hasn't been DNATed to backend port");

	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (settings)
		settings->nat_source_port = l4->source;

	struct bpf_tunnel_key *tunnel_key = map_lookup_elem(&tunnel_key_map, &key);

	if (!tunnel_key)
		test_fatal("no tunnel key set");

	assert(tunnel_key->tunnel_id == WORLD_ID);

	test_finish();
}

/* Test that a reply for the SVC request is RevDNATed & RevSNATed,
 * and flows back out on the overlay interface to the client
 * (preserving the backend's security identity).
 */
PKTGEN("tc", "nodeport_overlay_nat_2_reply")
int nodeport_overlay_nat_2_reply_pktgen(struct __ctx_buff *ctx)
{
	__be16 nat_source_port = 0;
	struct pktgen builder;
	struct udphdr *l4;
	void *data;

	__u32 key = 0;
	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (settings)
		nat_source_port = settings->nat_source_port;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	l4 = pktgen__push_ipv4_udp_packet(&builder,
					  (__u8 *)zero_mac, (__u8 *)zero_mac,
					  BACKEND_IP, IPV4_GATEWAY,
					  BACKEND_PORT, nat_source_port);
	if (!l4)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "nodeport_overlay_nat_2_reply")
int nodeport_overlay_nat_2_reply_setup(struct __ctx_buff *ctx)
{
	ipcache_v4_add_entry(CLIENT_IP, 0, CLIENT_SEC_IDENTITY,
			     CLIENT_NODE_IP, 0);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "nodeport_overlay_nat_2_reply")
int nodeport_overlay_nat_2_reply_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	__u32 key = 0;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == CTX_ACT_REDIRECT);

	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);
	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	if (l3->saddr != FRONTEND_IP)
		test_fatal("src IP hasn't been RevDNATed to frontend IP");

	if (l3->daddr != CLIENT_IP)
		test_fatal("dst IP is not the client");

	if (l4->source != FRONTEND_PORT)
		test_fatal("src port hasn't been RevDNATed to frontend port");

	if (l4->dest != CLIENT_PORT)
		test_fatal("dst port is not the client");

	struct bpf_tunnel_key *tunnel_key = map_lookup_elem(&tunnel_key_map, &key);

	if (!tunnel_key)
		test_fatal("no tunnel key set");

	assert(identity_is_remote_node(tunnel_key->tunnel_id));

	test_finish();
}

/* Reproduce the production SIP path where service pinning tunnels a reply to
 * the original LB node and the packet enters through cil_from_overlay. The
 * service fallback intentionally points at LB4; the pre-service SIP reverse
 * NAT lookup must restore LB3 instead.
 */
#define SIP_LB3_IP              IPV4(10, 244, 6, 114)
#define SIP_LB3_PORT            __bpf_htons(6000)
#define SIP_LB4_IP              IPV4(10, 244, 5, 210)
#define SIP_PEER_IP             IPV4(95, 216, 211, 90)
#define SIP_PEER_PORT           __bpf_htons(63644)
#define SIP_VIP_IP              IPV4(23, 29, 18, 180)
#define SIP_PORT                __bpf_htons(5060)
#define SIP_CALL_ID_HASH        0xfaf06e38
#define SIP_CALL_ID             "devdev01-JmwcpDSf5oPQJQOZRa0fKLH35oNP1iR3"
#define SIP_RESPONSE                                                    \
	"SIP/2.0 100 Trying\r\n"                                            \
	"Call-ID: " SIP_CALL_ID "\r\n"                                   \
	"X: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\r\n"

PKTGEN("tc", "nodeport_overlay_sip_reply")
int nodeport_overlay_sip_reply_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *udp;
	void *data;

	pktgen__init(&builder, ctx);
	udp = pktgen__push_ipv4_udp_packet(&builder,
					   (__u8 *)zero_mac, (__u8 *)zero_mac,
					   SIP_PEER_IP, SIP_VIP_IP,
					   SIP_PEER_PORT, SIP_PORT);
	if (!udp)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, SIP_RESPONSE,
				 sizeof(SIP_RESPONSE) - 1);
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "nodeport_overlay_sip_reply")
int nodeport_overlay_sip_reply_setup(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple reverse = {
		.saddr = SIP_PEER_IP,
		.daddr = SIP_VIP_IP,
		.sport = SIP_PEER_PORT,
		.dport = SIP_PORT,
		.nexthdr = IPPROTO_UDP,
		.flags = TUPLE_F_IN,
		.sip_call_id_hash = SIP_CALL_ID_HASH,
	};
	struct ipv4_nat_entry state = {
		.to_daddr = SIP_LB3_IP,
		.to_dport = SIP_LB3_PORT,
	};
	__u16 revnat_id = 99;

	map_update_elem(&cilium_snat_v4_external, &reverse, &state, BPF_ANY);
	lb_v4_add_service_sip(SIP_VIP_IP, SIP_PORT, IPPROTO_UDP, 1, revnat_id);
	lb_v4_add_backend(SIP_VIP_IP, SIP_PORT, 1, 124, SIP_LB4_IP,
			  SIP_LB3_PORT, IPPROTO_UDP, 0);

	/* Both destinations are routable so the final address reveals which
	 * branch was selected even if the test's mock redirect terminates it.
	 */
	ipcache_v4_add_entry(SIP_LB3_IP, 0, CLIENT_SEC_IDENTITY, 0, 0);
	ipcache_v4_add_entry(SIP_LB4_IP, 0, BACKEND_SEC_IDENTITY, 0, 0);

	return overlay_receive_packet(ctx);
}

CHECK("tc", "nodeport_overlay_sip_reply")
int nodeport_overlay_sip_reply_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct udphdr *udp;

	test_init();
	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct iphdr) +
	    sizeof(struct udphdr) > data_end)
		test_fatal("SIP overlay reply packet out of bounds");

	ip4 = data + sizeof(__u32) + sizeof(struct ethhdr);
	udp = (void *)ip4 + sizeof(*ip4);
	if (ip4->daddr != SIP_LB3_IP)
		test_fatal("SIP overlay reply selected LB4 service backend");
	if (udp->dest != SIP_LB3_PORT)
		test_fatal("SIP overlay reply did not restore LB3 port");

	test_finish();
}
