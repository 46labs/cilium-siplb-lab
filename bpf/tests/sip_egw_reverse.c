// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4                    1
#define ENABLE_NODEPORT                1
#define ENABLE_EGRESS_GATEWAY          1
#define ENABLE_MASQUERADE_IPV4         1
#define ENABLE_HOST_FIREWALL            1

#define ENCAP_IFINDEX                  42

#define LB3_IP                         IPV4(10, 244, 6, 114)
#define LB3_PORT                       __bpf_htons(6000)
#define LB4_IP                         IPV4(10, 244, 5, 210)
#define PEER_IP                        IPV4(95, 216, 211, 90)
#define PEER_PORT                      __bpf_htons(63644)
#define PEER_LOCAL_PORT                __bpf_htons(63645)
#define PEER_NON_SIP_PORT              __bpf_htons(63646)
#define VIP_IP                         IPV4(23, 29, 18, 180)
#define SIP_PORT                       __bpf_htons(5060)
#define GATEWAY_NODE_IP                IPV4(10, 90, 57, 8)
#define IPV4_DIRECT_ROUTING            GATEWAY_NODE_IP
#define LB3_IDENTITY                   123456

#define SIP_CALL_ID                    "devdev01-JmwcpDSf5oPQJQOZRa0fKLH35oNP1iR3"
#define SIP_CALL_ID_HASH               0xfaf06e38
#define SIP_EXTERNAL_CALL_ID           "devdev01-external-request-reply"
#define SIP_EXTERNAL_CALL_ID_HASH      0x588d17dd
#define SIP_LOCAL_CALL_ID              "devdev01-local-gateway-reply-test"
#define SIP_LOCAL_CALL_ID_HASH         0x3d068747

#define SIP_INVITE                                                     \
	"INVITE sip:x SIP/2.0\r\n"                                        \
	"Call-ID: " SIP_CALL_ID "\r\n"                                  \
	"X: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\r\n"

#define SIP_RESPONSE                                                   \
	"SIP/2.0 100 Trying\r\n"                                           \
	"Call-ID: " SIP_CALL_ID "\r\n"                                  \
	"X: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\r\n"

#define SIP_EXTERNAL_RESPONSE                                          \
	"SIP/2.0 100 Trying\r\n"                                           \
	"Call-ID: " SIP_EXTERNAL_CALL_ID "\r\n"                         \
	"X: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\r\n"

#define SIP_LOCAL_RESPONSE                                             \
	"SIP/2.0 100 Trying\r\n"                                           \
	"Call-ID: " SIP_LOCAL_CALL_ID "\r\n"                            \
	"X: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\r\n"

static volatile const __u8 *lb3_mac = mac_one;
static volatile const __u8 *peer_mac = mac_two;
static volatile const __u8 *node_mac = mac_three;

#define ctx_redirect mock_ctx_redirect
static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	return CTX_ACT_REDIRECT;
}

#define redirect_neigh mock_redirect_neigh
static __always_inline __maybe_unused int
mock_redirect_neigh(int ifindex __maybe_unused,
		    struct bpf_redir_neigh *params __maybe_unused,
		    int plen __maybe_unused, __u32 flags __maybe_unused)
{
	return CTX_ACT_REDIRECT;
}

#define fib_lookup mock_fib_lookup
static __always_inline __maybe_unused long
mock_fib_lookup(void *ctx __maybe_unused, struct bpf_fib_lookup *params,
		int plen __maybe_unused, __u32 flags __maybe_unused)
{
	return params ? BPF_FIB_LKUP_RET_SUCCESS : BPF_FIB_LKUP_RET_BLACKHOLE;
}

#include "lib/bpf_host.h"

#include "lib/endpoint.h"
#include "lib/egressgw_policy.h"
#include "lib/ipcache.h"
#include "lib/lb.h"

static __always_inline void add_egress_policy_for(__be32 source_ip,
					  bool sip_inspect)
{
	struct egress_gw_policy_key key = {
		.lpm_key = { EGRESS_PREFIX_LEN_V4(32), {} },
		.saddr = source_ip,
		.daddr = PEER_IP,
	};
	struct egress_gw_policy_entry value = {
		.egress_ip = VIP_IP,
		.gateway_ip = GATEWAY_NODE_IP,
		.sip_inspect = sip_inspect,
		.sip_port = 5060,
	};

	map_update_elem(&cilium_egress_gw_policy_v4, &key, &value, BPF_ANY);
}

static __always_inline void add_sip_egress_policy(void)
{
	add_egress_policy_for(LB3_IP, true);
}

static __always_inline int build_sip_packet(struct __ctx_buff *ctx, bool reply)
{
	struct pktgen builder;
	struct udphdr *udp;
	void *data;

	pktgen__init(&builder, ctx);
	udp = pktgen__push_ipv4_udp_packet(
		&builder,
		reply ? (__u8 *)peer_mac : (__u8 *)lb3_mac,
		reply ? (__u8 *)node_mac : (__u8 *)peer_mac,
		reply ? PEER_IP : LB3_IP,
		reply ? VIP_IP : PEER_IP,
		reply ? PEER_PORT : LB3_PORT,
		reply ? SIP_PORT : PEER_PORT);
	if (!udp)
		return TEST_ERROR;

	if (reply)
		data = pktgen__push_data(&builder, SIP_RESPONSE,
					 sizeof(SIP_RESPONSE) - 1);
	else
		data = pktgen__push_data(&builder, SIP_INVITE,
					 sizeof(SIP_INVITE) - 1);
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

PKTGEN("tc", "sip_egw_1_request")
int sip_egw_request_pktgen(struct __ctx_buff *ctx)
{
	return build_sip_packet(ctx, false);
}

SETUP("tc", "sip_egw_1_request")
int sip_egw_request_setup(struct __ctx_buff *ctx)
{
	const struct egress_gw_policy_entry *policy;

	add_sip_egress_policy();
	policy = lookup_ip4_egress_gw_policy(LB3_IP, PEER_IP, 0);
	if (!policy || policy->egress_ip != VIP_IP || !policy->sip_inspect ||
	    policy->sip_port != 5060)
		return TEST_ERROR;
	ipcache_v4_add_entry(VIP_IP, 0, HOST_ID, 0, 0);
	set_identity_mark(ctx, LB3_IDENTITY, MARK_MAGIC_EGW_DONE);
	return netdev_send_packet(ctx);
}

CHECK("tc", "sip_egw_1_request")
int sip_egw_request_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct udphdr *udp;
	struct ipv4_ct_tuple reverse = {
		.saddr = PEER_IP,
		.daddr = VIP_IP,
		.sport = PEER_PORT,
		.dport = SIP_PORT,
		.nexthdr = IPPROTO_UDP,
		.flags = TUPLE_F_IN,
		.sip_call_id_hash = SIP_CALL_ID_HASH,
	};
	struct ipv4_nat_entry *state;

	test_init();
	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct iphdr) +
	    sizeof(struct udphdr) > data_end)
		test_fatal("request packet out of bounds");

	if (*(__u32 *)data != CTX_ACT_OK &&
	    *(__u32 *)data != CTX_ACT_REDIRECT)
		test_fatal("unexpected request verdict: %u", *(__u32 *)data);
	ip4 = data + sizeof(__u32) + sizeof(struct ethhdr);
	udp = (void *)ip4 + sizeof(*ip4);
	if (ip4->saddr != VIP_IP)
		test_error("request source IP was not SNATed to VIP: actual=%x expected=%x",
			   bpf_ntohl(ip4->saddr), bpf_ntohl(VIP_IP));
	if (udp->source != SIP_PORT)
		test_error("request source port was not SNATed to SIP port: actual=%u expected=%u",
			   bpf_ntohs(udp->source), bpf_ntohs(SIP_PORT));

	state = snat_v4_lookup(&reverse);
	if (!state)
		test_error("reverse SIP NAT entry was not created");
	if (state && (state->to_daddr != LB3_IP || state->to_dport != LB3_PORT))
		test_fatal("reverse SIP NAT entry points to wrong LB");

	test_finish();
}

PKTGEN("tc", "sip_egw_2_reply")
int sip_egw_reply_pktgen(struct __ctx_buff *ctx)
{
	return build_sip_packet(ctx, true);
}

SETUP("tc", "sip_egw_2_reply")
int sip_egw_reply_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	lb_v4_add_service_sip(VIP_IP, SIP_PORT, IPPROTO_UDP, 1, revnat_id);
	lb_v4_add_backend(VIP_IP, SIP_PORT, 1, 124, LB4_IP, LB3_PORT,
			  IPPROTO_UDP, 0);
	ipcache_v4_add_entry(LB3_IP, 0, LB3_IDENTITY, 0, 0);
	ipcache_v4_add_entry(LB4_IP, 0, LB3_IDENTITY + 1, 0, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "sip_egw_2_reply")
int sip_egw_reply_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct udphdr *udp;

	test_init();
	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct iphdr) +
	    sizeof(struct udphdr) > data_end)
		test_fatal("reply packet out of bounds");

	if (*(__u32 *)data != CTX_ACT_OK &&
	    *(__u32 *)data != CTX_ACT_REDIRECT)
		test_fatal("unexpected reply verdict: %u", *(__u32 *)data);
	ip4 = data + sizeof(__u32) + sizeof(struct ethhdr);
	udp = (void *)ip4 + sizeof(*ip4);
	if (ip4->daddr != LB3_IP)
		test_fatal("reply selected service backend instead of reverse SIP NAT");
	if (udp->dest != LB3_PORT)
		test_fatal("reply destination port was not restored");

	test_finish();
}

static __always_inline int build_external_request_reply(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *udp;
	void *data;

	pktgen__init(&builder, ctx);
	udp = pktgen__push_ipv4_udp_packet(&builder,
					   (__u8 *)lb3_mac, (__u8 *)peer_mac,
					   LB4_IP, PEER_IP,
					   LB3_PORT, PEER_PORT);
	if (!udp)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, SIP_EXTERNAL_RESPONSE,
				 sizeof(SIP_EXTERNAL_RESPONSE) - 1);
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline int add_external_request_reply_ct(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {};
	struct iphdr *ip4;
	void *data, *data_end;
	fraginfo_t fraginfo;
	int l4_off;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return TEST_ERROR;
	fraginfo = ipfrag_encode_ipv4(ip4);
	snat_v4_init_tuple(ip4, NAT_DIR_EGRESS, &tuple);
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
	if (ct_extract_ports4(ctx, ip4, fraginfo, l4_off, CT_EGRESS, &tuple))
		return TEST_ERROR;
	tuple.flags = TUPLE_F_IN;
	if (ct_create4(get_ct_map4(&tuple), NULL, &tuple, ctx,
		       CT_INGRESS, NULL, NULL))
		return TEST_ERROR;

	/* Production has both the ordinary UDP CT entry above and Call-ID CT
	 * entries for the same 5-tuple. The egress-gateway reply lookup uses the
	 * ordinary entry because it does not parse a Call-ID at this stage.
	 */
	tuple.sip_call_id_hash = SIP_EXTERNAL_CALL_ID_HASH;
	return ct_create4(get_ct_map4(&tuple), NULL, &tuple, ctx,
			  CT_INGRESS, NULL, NULL);
}

static __always_inline int add_unhashed_nodeport_reply_ct(struct __ctx_buff *ctx,
							   __u16 rev_nat_index)
{
	struct ipv4_ct_tuple tuple = {};
	struct ct_state state = {
		.node_port = true,
		.rev_nat_index = rev_nat_index,
	};
	struct iphdr *ip4;
	void *data, *data_end;
	fraginfo_t fraginfo;
	int l4_off;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return TEST_ERROR;
	fraginfo = ipfrag_encode_ipv4(ip4);
	snat_v4_init_tuple(ip4, NAT_DIR_EGRESS, &tuple);
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
	if (ct_extract_ports4(ctx, ip4, fraginfo, l4_off, CT_EGRESS, &tuple))
		return TEST_ERROR;

	/* Simulate an older SIP dialog which shares the UDP 5-tuple. */
	return ct_create4(get_ct_map4(&tuple), NULL, &tuple, ctx,
			  CT_EGRESS, &state, NULL);
}

PKTGEN("tc", "sip_egw_3_external_request_reply_redirect")
int sip_egw_external_request_reply_redirect_pktgen(struct __ctx_buff *ctx)
{
	return build_external_request_reply(ctx);
}

SETUP("tc", "sip_egw_3_external_request_reply_redirect")
int sip_egw_external_request_reply_redirect_setup(struct __ctx_buff *ctx)
{
	const struct egress_gw_policy_entry *policy;
	struct trace_ctx trace = {};

	add_egress_policy_for(LB4_IP, true);
	policy = lookup_ip4_egress_gw_policy(LB4_IP, PEER_IP, 0);
	if (!policy || !policy->sip_inspect || policy->gateway_ip != GATEWAY_NODE_IP)
		return TEST_ERROR;
	endpoint_v4_add_entry(LB4_IP, 0, 0, 0, LB3_IDENTITY + 1, 0,
			      (__u8 *)lb3_mac, (__u8 *)node_mac);
	ipcache_v4_add_entry(VIP_IP, 0, HOST_ID, 0, 0);

	if (add_external_request_reply_ct(ctx))
		return TEST_ERROR;

	return egress_gw_handle_request(ctx, bpf_htons(ETH_P_IP),
					LB3_IDENTITY + 1, WORLD_ID, &trace);
}

CHECK("tc", "sip_egw_3_external_request_reply_redirect")
int sip_egw_external_request_reply_redirect_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;

	test_init();
	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(__u32) > data_end)
		test_fatal("external-request reply status out of bounds");
	if (*(__u32 *)data != CTX_ACT_REDIRECT)
		test_error("external-request SIP reply was not redirected to its egress gateway: verdict=%u",
			   *(__u32 *)data);

	test_finish();
}

PKTGEN("tc", "sip_egw_6_non_sip_policy_reply")
int sip_egw_non_sip_policy_reply_pktgen(struct __ctx_buff *ctx)
{
	return build_external_request_reply(ctx);
}

SETUP("tc", "sip_egw_6_non_sip_policy_reply")
int sip_egw_non_sip_policy_reply_setup(struct __ctx_buff *ctx)
{
	struct trace_ctx trace = {};

	add_egress_policy_for(LB4_IP, false);
	endpoint_v4_add_entry(LB4_IP, 0, 0, 0, LB3_IDENTITY + 1, 0,
			      (__u8 *)lb3_mac, (__u8 *)node_mac);
	if (add_external_request_reply_ct(ctx))
		return TEST_ERROR;

	return egress_gw_handle_request(ctx, bpf_htons(ETH_P_IP),
					LB3_IDENTITY + 1, WORLD_ID, &trace);
}

CHECK("tc", "sip_egw_6_non_sip_policy_reply")
int sip_egw_non_sip_policy_reply_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;

	test_init();
	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(__u32) > data_end)
		test_fatal("non-SIP policy reply status out of bounds");
	if (*(__u32 *)data != CTX_ACT_OK)
		test_error("non-SIP policy reply behavior changed: verdict=%u",
			   *(__u32 *)data);

	test_finish();
}

PKTGEN("tc", "sip_egw_4_external_request_reply_gateway")
int sip_egw_external_request_reply_gateway_pktgen(struct __ctx_buff *ctx)
{
	return build_external_request_reply(ctx);
}

SETUP("tc", "sip_egw_4_external_request_reply_gateway")
int sip_egw_external_request_reply_gateway_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	/* On the egress-gateway node LB4 is a remote endpoint. */
	add_egress_policy_for(LB4_IP, true);
	endpoint_v4_del_entry(LB4_IP);
	lb_v4_add_service_sip(VIP_IP, SIP_PORT, IPPROTO_UDP, 0, revnat_id);
	if (add_unhashed_nodeport_reply_ct(ctx, revnat_id))
		return TEST_ERROR;
	set_identity_mark(ctx, LB3_IDENTITY + 1, MARK_MAGIC_EGW_DONE);
	return netdev_send_packet(ctx);
}

CHECK("tc", "sip_egw_4_external_request_reply_gateway")
int sip_egw_external_request_reply_gateway_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct udphdr *udp;
	struct ipv4_ct_tuple reverse = {
		.saddr = PEER_IP,
		.daddr = VIP_IP,
		.sport = PEER_PORT,
		.dport = SIP_PORT,
		.nexthdr = IPPROTO_UDP,
		.flags = TUPLE_F_IN,
		.sip_call_id_hash = SIP_EXTERNAL_CALL_ID_HASH,
	};
	struct ipv4_nat_entry *state;

	test_init();
	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct iphdr) +
	    sizeof(struct udphdr) > data_end)
		test_fatal("external-request reply packet out of bounds");

	if (*(__u32 *)data != CTX_ACT_OK &&
	    *(__u32 *)data != CTX_ACT_REDIRECT)
		test_fatal("unexpected external-request reply verdict: %u",
			   *(__u32 *)data);
	ip4 = data + sizeof(__u32) + sizeof(struct ethhdr);
	udp = (void *)ip4 + sizeof(*ip4);
	if (ip4->saddr != VIP_IP)
		test_error("external-request reply was not SNATed to VIP: actual=%x expected=%x",
			   bpf_ntohl(ip4->saddr), bpf_ntohl(VIP_IP));
	if (udp->source != SIP_PORT)
		test_error("external-request reply was not SNATed to SIP port: actual=%u expected=%u",
			   bpf_ntohs(udp->source), bpf_ntohs(SIP_PORT));

	state = snat_v4_lookup(&reverse);
	if (!state)
		test_error("external-request reply did not create reverse SIP NAT entry");
	if (state && (state->to_daddr != LB4_IP || state->to_dport != LB3_PORT))
		test_fatal("external-request reverse SIP NAT entry points to wrong LB");

	test_finish();
}

PKTGEN("tc", "sip_egw_5_external_request_followup")
int sip_egw_external_request_followup_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct udphdr *udp;
	void *data;

	pktgen__init(&builder, ctx);
	udp = pktgen__push_ipv4_udp_packet(&builder,
					   (__u8 *)peer_mac, (__u8 *)node_mac,
					   PEER_IP, VIP_IP,
					   PEER_PORT, SIP_PORT);
	if (!udp)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, SIP_EXTERNAL_RESPONSE,
				 sizeof(SIP_EXTERNAL_RESPONSE) - 1);
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "sip_egw_5_external_request_followup")
int sip_egw_external_request_followup_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	/* Without the Call-ID reverse entry this service would pick LB3. */
	lb_v4_add_service_sip(VIP_IP, SIP_PORT, IPPROTO_UDP, 1, revnat_id);
	lb_v4_add_backend(VIP_IP, SIP_PORT, 1, 124, LB3_IP, LB3_PORT,
			  IPPROTO_UDP, 0);
	ipcache_v4_add_entry(LB3_IP, 0, LB3_IDENTITY, 0, 0);
	ipcache_v4_add_entry(LB4_IP, 0, LB3_IDENTITY + 1, 0, 0);

	return netdev_receive_packet(ctx);
}

CHECK("tc", "sip_egw_5_external_request_followup")
int sip_egw_external_request_followup_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct udphdr *udp;

	test_init();
	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct iphdr) +
	    sizeof(struct udphdr) > data_end)
		test_fatal("external-request follow-up packet out of bounds");

	if (*(__u32 *)data != CTX_ACT_OK &&
	    *(__u32 *)data != CTX_ACT_REDIRECT)
		test_fatal("unexpected external-request follow-up verdict: %u",
			   *(__u32 *)data);
	ip4 = data + sizeof(__u32) + sizeof(struct ethhdr);
	udp = (void *)ip4 + sizeof(*ip4);
	if (ip4->daddr != LB4_IP)
		test_fatal("external-request follow-up moved to another LB");
	if (udp->dest != LB3_PORT)
		test_fatal("external-request follow-up destination port was not restored");

	test_finish();
}

static __always_inline int build_local_gateway_reply(struct __ctx_buff *ctx,
					       __be16 peer_port)
{
	struct pktgen builder;
	struct udphdr *udp;
	void *data;

	pktgen__init(&builder, ctx);
	udp = pktgen__push_ipv4_udp_packet(&builder,
					   (__u8 *)lb3_mac, (__u8 *)peer_mac,
					   LB3_IP, PEER_IP,
					   LB3_PORT, peer_port);
	if (!udp)
		return TEST_ERROR;

	data = pktgen__push_data(&builder, SIP_LOCAL_RESPONSE,
				 sizeof(SIP_LOCAL_RESPONSE) - 1);
	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

static __always_inline int add_local_gateway_reply_ct(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {};
	struct iphdr *ip4;
	void *data, *data_end;
	fraginfo_t fraginfo;
	int l4_off;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return TEST_ERROR;
	fraginfo = ipfrag_encode_ipv4(ip4);
	snat_v4_init_tuple(ip4, NAT_DIR_EGRESS, &tuple);
	l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
	if (ct_extract_ports4(ctx, ip4, fraginfo, l4_off, CT_EGRESS, &tuple))
		return TEST_ERROR;
	tuple.flags = TUPLE_F_IN;
	return ct_create4(get_ct_map4(&tuple), NULL, &tuple, ctx,
			  CT_INGRESS, NULL, NULL);
}

PKTGEN("tc", "sip_egw_7_local_gateway_reply")
int sip_egw_local_gateway_reply_pktgen(struct __ctx_buff *ctx)
{
	return build_local_gateway_reply(ctx, PEER_LOCAL_PORT);
}

SETUP("tc", "sip_egw_7_local_gateway_reply")
int sip_egw_local_gateway_reply_setup(struct __ctx_buff *ctx)
{
	add_egress_policy_for(LB3_IP, true);
	endpoint_v4_add_entry(LB3_IP, 0, 0, 0, LB3_IDENTITY, 0,
			      (__u8 *)lb3_mac, (__u8 *)node_mac);
	endpoint_v4_add_entry(GATEWAY_NODE_IP, 0, 0, ENDPOINT_F_HOST,
			      HOST_ID, 0, NULL, NULL);
	ipcache_v4_add_entry(VIP_IP, 0, HOST_ID, 0, 0);

	if (sip_inspect(ctx) != SIP_LOCAL_CALL_ID_HASH)
		return TEST_ERROR;
	if (add_local_gateway_reply_ct(ctx))
		return TEST_ERROR;

	set_identity_mark(ctx, LB3_IDENTITY, MARK_MAGIC_IDENTITY);
	return netdev_send_packet(ctx);
}

CHECK("tc", "sip_egw_7_local_gateway_reply")
int sip_egw_local_gateway_reply_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct udphdr *udp;
	struct ipv4_ct_tuple reverse = {
		.saddr = PEER_IP,
		.daddr = VIP_IP,
		.sport = PEER_LOCAL_PORT,
		.dport = SIP_PORT,
		.nexthdr = IPPROTO_UDP,
		.flags = TUPLE_F_IN,
		.sip_call_id_hash = SIP_LOCAL_CALL_ID_HASH,
	};
	struct ipv4_nat_entry *state;

	test_init();
	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct iphdr) +
	    sizeof(struct udphdr) > data_end)
		test_fatal("local-gateway reply packet out of bounds");

	ip4 = data + sizeof(__u32) + sizeof(struct ethhdr);
	udp = (void *)ip4 + sizeof(*ip4);
	if (ip4->saddr != VIP_IP)
		test_error("local-gateway reply source IP was not SNATed: actual=%x expected=%x",
			   bpf_ntohl(ip4->saddr), bpf_ntohl(VIP_IP));
	if (udp->source != SIP_PORT)
		test_error("local-gateway reply source port was not SNATed: actual=%u expected=%u",
			   bpf_ntohs(udp->source), bpf_ntohs(SIP_PORT));

	state = snat_v4_lookup(&reverse);
	if (!state)
		test_error("local-gateway reply did not create reverse SIP NAT entry");
	if (state && (state->to_daddr != LB3_IP || state->to_dport != LB3_PORT))
		test_fatal("local-gateway reverse SIP NAT entry points to wrong LB");

	test_finish();
}

PKTGEN("tc", "sip_egw_8_local_gateway_non_sip_reply")
int sip_egw_local_gateway_non_sip_reply_pktgen(struct __ctx_buff *ctx)
{
	return build_local_gateway_reply(ctx, PEER_NON_SIP_PORT);
}

SETUP("tc", "sip_egw_8_local_gateway_non_sip_reply")
int sip_egw_local_gateway_non_sip_reply_setup(struct __ctx_buff *ctx)
{
	add_egress_policy_for(LB3_IP, false);
	endpoint_v4_add_entry(LB3_IP, 0, 0, 0, LB3_IDENTITY, 0,
			      (__u8 *)lb3_mac, (__u8 *)node_mac);
	endpoint_v4_add_entry(GATEWAY_NODE_IP, 0, 0, ENDPOINT_F_HOST,
			      HOST_ID, 0, NULL, NULL);

	if (add_local_gateway_reply_ct(ctx))
		return TEST_ERROR;

	set_identity_mark(ctx, LB3_IDENTITY, MARK_MAGIC_IDENTITY);
	return netdev_send_packet(ctx);
}

CHECK("tc", "sip_egw_8_local_gateway_non_sip_reply")
int sip_egw_local_gateway_non_sip_reply_check(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct udphdr *udp;

	test_init();
	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(__u32) + sizeof(struct ethhdr) + sizeof(struct iphdr) +
	    sizeof(struct udphdr) > data_end)
		test_fatal("local-gateway non-SIP reply packet out of bounds");

	ip4 = data + sizeof(__u32) + sizeof(struct ethhdr);
	udp = (void *)ip4 + sizeof(*ip4);
	if (ip4->saddr != LB3_IP)
		test_error("local-gateway non-SIP reply was unexpectedly SNATed");
	if (udp->source != LB3_PORT)
		test_error("local-gateway non-SIP reply source port changed");

	test_finish();
}
