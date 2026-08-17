/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright 46labs LLC */

#pragma once

#include <linux/udp.h>

#define NOT_FOUND 0

/* sip_inspect() uses direct packet access. TC skbs received after tunnel
 * decapsulation may keep the SIP payload outside the linear head, even though
 * skb_load_bytes() can still read the SIP method. Pull only the parser window
 * that can actually be inspected: 1000 bytes while looking for Call-ID, the
 * 9-byte header itself and the 68-byte Call-ID bounds window.
 */
#define SIP_L3_HEADERS_LEN (sizeof(struct ethhdr) + sizeof(struct iphdr))
#define SIP_PAYLOAD_OFFSET (SIP_L3_HEADERS_LEN + sizeof(struct udphdr))
#define SIP_METHOD_LEN 10
#define SIP_PARSE_WINDOW (SIP_PAYLOAD_OFFSET + 1000 + 9 + 68)

/* Temporary canary diagnostics. Removed after the failing path is isolated. */
struct sip_debug_key {
	__be32 saddr;
	__be32 daddr;
	__u32 hash;
	__u8 stage;
	__u8 pad[3];
};

struct sip_debug_value {
	__u32 full_len;
	__u32 linear_len;
	__s32 result;
	__u32 aux;
	__be16 ip_id;
	__be16 sport;
	__be16 dport;
	__u16 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct sip_debug_key);
	__type(value, struct sip_debug_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 8192);
} cilium_sip_dbg __section_maps_btf;

static __noinline __maybe_unused void
sip_debug_record(struct __ctx_buff *ctx, __u8 stage, __s32 result,
		 __u32 hash, __u32 aux)
{
	struct sip_debug_value value = {
		.full_len = (__u32)ctx_full_len(ctx),
		.result = result,
		.aux = aux,
	};
	struct sip_debug_key key = {
		.hash = hash,
		.stage = stage,
	};
	struct iphdr iph = {};
	struct udphdr udp = {};
	void *data = ctx_data(ctx);
	void *data_end = ctx_data_end(ctx);

	value.linear_len = (__u32)(data_end - data);
	if (ctx_load_bytes(ctx, sizeof(struct ethhdr), &iph, sizeof(iph)) < 0 ||
	    iph.protocol != IPPROTO_UDP ||
	    ctx_load_bytes(ctx, SIP_L3_HEADERS_LEN, &udp, sizeof(udp)) < 0)
		return;

	/* Keep the temporary map focused on SIP signaling. */
	if (udp.source != bpf_htons(5060) && udp.source != bpf_htons(6000) &&
	    udp.dest != bpf_htons(5060) && udp.dest != bpf_htons(6000))
		return;

	key.saddr = iph.saddr;
	key.daddr = iph.daddr;
	value.ip_id = iph.id;
	value.sport = udp.source;
	value.dport = udp.dest;
	map_update_elem(&cilium_sip_dbg, &key, &value, BPF_ANY);
}

static inline __u8 is_sip(const char *cur, const char *data_end)
{
	static const __u64 resp = 0x20302e322f706973; // "sip/2.0 "

	// 8 bytes match
	static const __u64 reg = 0x7265747369676572;	    // "register"
	static const __u64 subscribe1 = 0x6269726373627573; // "subscrib"

	// 8 bytes with space
	static const __u64 options = 0x20736e6f6974706f; // "options "
	static const __u64 message = 0x206567617373656d; // "message "
	static const __u64 publish = 0x206873696c627570; // "publish "

	// 7 bytes with space
	static const __u64 invite = 0x0020657469766e69; // "invite "
	static const __u64 cancel = 0x00206c65636e6163; // "cancel "
	static const __u64 update = 0x0020657461647075; // "update "
	static const __u64 notify = 0x0020796669746f6e; // "notify "

	// 6 bytes match
	static const __u64 prack = 0x0000206b63617270; // "prack "
	static const __u64 refer = 0x0000207265666572; // "refer "

	// 5 bytes match
	static const __u64 info = 0x000000206f666e69; // "info "

	// 4 bytes match
	static const __u64 ack = 0x00000000206b6361; // "ack "
	static const __u64 bye = 0x0000000020657962; // "bye "

	// remainders
	static const __u16 subscribe2 = 0x2065; // "e "

	if (cur + sizeof(__u64) + sizeof(__u16) > data_end)
		return 0;

	__u64 v = *(__u64 *)cur;
	__u16 r = *(__u16 *)(cur + 8);

	if ((v | 0x202020) == resp)
		return 1;

	__u64 v_masked8 = v | 0x2020202020202020;
	__u16 r_masked1 = r | 0x0020;
	if (v_masked8 == reg)
		return 1;

	if (v_masked8 == subscribe1 && r_masked1 == subscribe2)
		return 1;

	__u64 v_masked7 = v | 0x0020202020202020;
	if (v_masked7 == options || v_masked7 == message || v_masked7 == publish)
		return 1;

	__u64 v_masked6 = (v | 0x0000202020202020) & 0x00FFFFFFFFFFFFFF;
	if (v_masked6 == invite || v_masked6 == cancel || v_masked6 == update ||
	    v_masked6 == notify)
		return 1;

	__u64 v_masked5 = (v | 0x0000002020202020) & 0x0000FFFFFFFFFFFF;
	if (v_masked5 == prack || v_masked5 == refer)
		return 1;

	__u64 v_masked4 = (v | 0x0000000020202020) & 0x000000FFFFFFFFFF;
	if (v_masked4 == info)
		return 1;

	__u64 v_masked3 = (v | 0x0000000000202020) & 0x00000000FFFFFFFF;
	if (v_masked3 == ack || v_masked3 == bye)
		return 1;

	return 0;
}

__noinline __weak __u32 sip_inspect(struct __ctx_buff *ctx)
{
	static const __u64 call_id1 = 0x3a64692d6c6c6163ULL; // "call-id:"
	static const __u8 call_id2 = ' ';
	static const __u16 crlf = 0x0a0d;

	void *data, *data_end;
	struct ethhdr *eth = NULL;
	struct iphdr *iph = NULL;
	__u32 hash = 0x811c9dc5;
	__u32 fnv_prime = 0x01000193;
	__u64 method[2] = {};
	__u32 pull_len;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + SIP_L3_HEADERS_LEN > data_end)
		return NOT_FOUND;

	eth = data;
	if ((void *)(eth + 1) > data_end)
		return NOT_FOUND;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return NOT_FOUND;

	iph = (void *)(eth + 1);

	if (iph->protocol != IPPROTO_UDP)
		return NOT_FOUND;

	if ((void *)(iph + 1) > data_end)
		return NOT_FOUND;

	void *cur = data + SIP_PAYLOAD_OFFSET;
	if (cur + SIP_METHOD_LEN > data_end) {
		/* skb_load_bytes() can read non-linear data without invalidating
		 * packet pointers. Only linearize the larger parser window after
		 * confirming that this is actually SIP.
		 */
		if (ctx_load_bytes(ctx, SIP_PAYLOAD_OFFSET, method,
				   SIP_METHOD_LEN) < 0 ||
		    !is_sip((char *)method, (char *)method + SIP_METHOD_LEN))
			return NOT_FOUND;
	} else if (!is_sip(cur, data_end)) {
		return NOT_FOUND;
	}

	/* The scan below uses direct access too. A decapsulated skb may have only
	 * its headers linear even though the complete SIP message is present.
	 */
	pull_len = (__u32)ctx_full_len(ctx);
	if (pull_len > SIP_PARSE_WINDOW)
		pull_len = SIP_PARSE_WINDOW;
	if (data + pull_len > data_end) {
		if (ctx_pull_data(ctx, pull_len) < 0)
			return NOT_FOUND;

		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;

		if (data + SIP_PAYLOAD_OFFSET + SIP_METHOD_LEN > data_end)
			return NOT_FOUND;

		cur = data + SIP_PAYLOAD_OFFSET;
	}

	int found = 0;

	for (int i = 0; i < 1000; i++) {
		if (cur + 9 > data_end)
			break;

		__u64 v = *(__u64 *)cur;
		__u8 c = *(__u8 *)(cur + 8);

		v |= 0x0020200020202020ULL;

		if (v == call_id1 && c == call_id2) {
			found = 1;
			break;
		}

		cur++;
	}

	if (!found)
		return NOT_FOUND;

	if (cur + 9 > data_end)
		return NOT_FOUND;

	cur += 9;

	found = 0;
	if (cur + 68 > data_end)
		return NOT_FOUND;

#pragma unroll
	for (int i = 0; i < 64; i++) {
		__u16 v = *(__u16 *)(cur + i);

		if (v == crlf) {
			found = 1;
			break;
		}

		hash ^= *(unsigned char *)(cur + i);
		hash *= fnv_prime;
	}

	if (!found)
		return NOT_FOUND;

	return hash;
}
