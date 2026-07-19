/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh access layer (MshPRT_v1.1 Section 3.7).
 *
 * The access layer sits directly on top of the upper transport
 * (mesh_transport.[ch], Section 3.6): an Access PDU is exactly what
 * mesh_upper_encrypt() carries as its plaintext "Access Payload" and what
 * mesh_upper_decrypt() recovers.  This module has no crypto of its own; it
 * is the cleartext opcode/parameter codec plus a small model-dispatch
 * registry.
 *
 * Access PDU layout (Section 3.7.3):
 *
 *   Opcode (1, 2 or 3 octets) | Parameters (0..N octets)
 *
 * Opcode length is self-describing from the most-significant bits of the
 * first octet (Section 3.7.3.1, Table 3.43):
 *
 *   0xxxxxxx                         1 octet  (0x00..0x7E; 0x7F is RFU)
 *   10xxxxxx xxxxxxxx                2 octet  (0x8000..0xBFFF)
 *   11xxxxxx cccccccc cccccccc       3 octet  vendor: 6-bit opcode plus a
 *                                             16-bit Company Identifier in
 *                                             LITTLE-endian order
 *
 * Canonical numeric opcode representation used throughout this module:
 *   1-octet : 0x00 .. 0x7E                    (== the octet)
 *   2-octet : 0x8000 .. 0xBFFF                (== octet0<<8 | octet1)
 *   3-octet : 0xC00000 .. 0xFFFFFF            (== octet0<<16 | company_id)
 * where for the 3-octet form octet0 is the 11xxxxxx byte and the low 16
 * bits hold the Company Identifier as an ordinary integer (the wire form is
 * little-endian, handled by the codec).  This is a total, unambiguous map:
 * the three ranges do not overlap and mesh_access_opcode_len() rejects any
 * value outside them (including the reserved one-octet 0x7F).
 *
 * The module is pure and hardware-free: big-endian on the wire for multi-
 * octet SIG opcodes, no I/O, no globals.  Every codec returns 0 on success
 * and -1 on failure with the output zeroed on failure.
 */

#ifndef _MESH_ACCESS_H_
#define _MESH_ACCESS_H_

#include <stddef.h>
#include <stdint.h>

/*
 * Access payload size bound.  Section 3.7.3: the Access Payload is at most
 * 380 octets (the largest Upper Transport Access PDU, 384, minus a 4-octet
 * TransMIC), which also equals mesh_transport.h MESH_ACCESS_MAX.  With the
 * smallest (1-octet) opcode the parameters are at most 379 octets.
 */
#define	MESH_ACCESS_PAYLOAD_MAX		380
#define	MESH_ACCESS_PARAMS_MAX		(MESH_ACCESS_PAYLOAD_MAX - 1)
#define	MESH_ACCESS_OPCODE_MAX_LEN	3

/* Label UUID length (virtual-address subscriptions).  MshPRT Section 3.4.2.3. */
#ifndef	MESH_LABEL_UUID_LEN
#define	MESH_LABEL_UUID_LEN		16
#endif

/*
 * Address classification (MshPRT_v1.1 Section 3.4.2).
 *
 *   0x0000            unassigned
 *   0x0001 .. 0x7FFF  unicast
 *   0x8000 .. 0xBFFF  virtual  (top two bits 10)
 *   0xC000 .. 0xFFFF  group    (top two bits 11)
 *
 * MESH_ADDR_ALL_NODES (0xFFFF) is the fixed all-nodes group; every element
 * is a member.  These predicates decide destination-address resolution in
 * the access layer.
 */
#define	MESH_ADDR_UNASSIGNED		0x0000u
#ifndef	MESH_ADDR_ALL_NODES
#define	MESH_ADDR_ALL_NODES		0xFFFFu
#endif

int	mesh_addr_is_unicast(uint16_t a);
int	mesh_addr_is_virtual(uint16_t a);
int	mesh_addr_is_group(uint16_t a);

/*
 * Virtual-address derivation (MshPRT_v1.1 Section 3.4.2.3).
 *
 * A virtual address is the 14-bit hash of a 16-octet Label UUID placed in a
 * 0x8000..0xBFFF address:  va = 0x8000 | (AES-CMAC(s1("vtad"), Label)[14..15]
 * & 0x3FFF).  Because the hash is only 14 bits, distinct Label UUIDs can
 * collide onto the same virtual address; the full 16-octet Label UUID (used
 * as upper-transport AAD) disambiguates them.  Returns 0 and *va on success,
 * -1 on a NULL argument or a crypto failure (*va left 0).
 */
int	mesh_virtual_addr(const uint8_t label[MESH_LABEL_UUID_LEN], uint16_t *va);

/*
 * Network message cache (MshPRT_v1.1 Section 3.4.6.5): the relay-loop dedup
 * store keyed by (SRC, SEQ).  mesh_msg_cache_check() returns 1 if the pair
 * was already recorded (a duplicate to be dropped) and otherwise records it
 * and returns 0.  This is the library home of the logic that previously
 * lived only inside the simulator, so real network consumers can dedup too.
 */
#define	MESH_MSG_CACHE_SIZE		64
struct mesh_msg_cache_slot {
	uint16_t	src;
	uint32_t	seq;
	int		valid;
};
struct mesh_msg_cache {
	struct mesh_msg_cache_slot	slots[MESH_MSG_CACHE_SIZE];
	size_t				next;
};
void	mesh_msg_cache_init(struct mesh_msg_cache *c);
int	mesh_msg_cache_check(struct mesh_msg_cache *c, uint16_t src,
	    uint32_t seq);

/*
 * Opcode length detection (Section 3.7.3.1).  Returns 1, 2 or 3 for a valid
 * canonical opcode, or -1 for a value that does not fall in any opcode range
 * (this includes the reserved one-octet opcode 0x7F).
 */
int	mesh_access_opcode_len(uint32_t opcode);

/*
 * Access PDU codec (Section 3.7.3).
 *
 * mesh_access_pdu_build() emits opcode || parameters.  The opcode is encoded
 * in 1/2/3 octets per its canonical value; a 3-octet vendor opcode places
 * the Company Identifier on the wire little-endian.  params may be NULL only
 * when params_len is 0.
 *
 * mesh_access_pdu_parse() splits a received Access PDU into its opcode and
 * parameters.  It rejects a truncated PDU (fewer octets than the opcode
 * length demands) and the reserved one-octet opcode 0x7F.  The parameters
 * are copied into out->params (not aliased into the input).
 */
struct mesh_access_pdu {
	uint32_t	opcode;		/* canonical numeric opcode */
	int		vendor;		/* 1 => 3-octet vendor opcode */
	uint16_t	company_id;	/* vendor Company Identifier (else 0) */
	uint8_t		opcode_len;	/* 1, 2 or 3 */
	uint8_t		params[MESH_ACCESS_PARAMS_MAX];
	size_t		params_len;
};

int	mesh_access_pdu_build(uint32_t opcode, const uint8_t *params,
	    size_t params_len, uint8_t *out, size_t *outlen);
int	mesh_access_pdu_parse(const uint8_t *in, size_t inlen,
	    struct mesh_access_pdu *out);

/*
 * Vendor-opcode helpers.  A 3-octet vendor opcode is (6-bit opcode, 16-bit
 * Company Identifier).  mesh_access_vendor_opcode() packs them into the
 * canonical numeric form; the accessors unpack it.
 */
uint32_t	mesh_access_vendor_opcode(uint8_t op6, uint16_t company_id);
uint16_t	mesh_access_opcode_company(uint32_t opcode);

/*
 * Model message dispatch (Section 3.7).
 *
 * A node exposes a set of elements (each with a unicast address); each
 * element holds a set of models; each model publishes an opcode table that
 * maps a received opcode to a handler.  This is the addressing/registry
 * shape that the Configuration and Health models plug into.
 *
 * mesh_model_find_op() looks up one opcode within one model's table.
 * mesh_access_dispatch() parses a received Access PDU, resolves the element
 * addressed by dst (unicast: element address equal to dst), searches that
 * element's models for a handler for the PDU's opcode, and invokes it.  It
 * returns 0 when a handler ran, or -1 on parse failure or when no model on
 * the addressed element handles the opcode (the caller can then treat the
 * message as unhandled).  Group/virtual destination resolution (subscription
 * lists) is layered above this by the model state and is not decided here.
 */
struct mesh_access_rx {
	uint16_t			src;		/* message source */
	uint16_t			dst;		/* message destination */
	uint16_t			elem_addr;	/* addressed element */
	const struct mesh_access_pdu	*pdu;		/* parsed access PDU */
	void				*model_user;	/* model's user pointer */
	void				*ctx;		/* caller context */
	uint64_t			now_ms;		/* monotonic receive time */
};

typedef int (*mesh_opcode_handler)(const struct mesh_access_rx *rx);
typedef void (*mesh_model_tick_fn)(void *, uint64_t);

struct mesh_opcode_entry {
	uint32_t		opcode;
	mesh_opcode_handler	handler;
};

#define	MESH_MODEL_MAX_APP_OPCODES	16

struct mesh_model {
	uint16_t			model_id;	/* SIG or vendor model id */
	uint16_t			company_id;	/* 0xFFFF => SIG model */
	const struct mesh_opcode_entry	*ops;
	size_t				n_ops;
	void				*user;
	mesh_model_tick_fn		tick;
	const uint16_t			*subs;
	const uint8_t			(*labels)[MESH_LABEL_UUID_LEN];
	const int			*sub_is_va;
	size_t				n_subs;
	int				subscriptions_configured;
	const uint16_t			*app_idx;
	size_t				n_app;
	int				bindings_configured;
	uint32_t			app_opcodes[MESH_MODEL_MAX_APP_OPCODES];
	size_t				n_app_opcodes;
};

struct mesh_element {
	uint16_t			addr;		/* element unicast address */
	const struct mesh_model		*models;
	size_t				n_models;
	/*
	 * Optional destination-resolution state (Sections 3.4.2 / 3.7).  A
	 * NULL list (with count 0) means "no group / no virtual subscription";
	 * elements with no subscriptions therefore receive unicast traffic only.
	 *   subs   : subscribed group addresses (0xC000..0xFFFF).
	 *   labels : subscribed virtual Label UUIDs (16 octets each); a message
	 *            to virtual DST matches when mesh_virtual_addr(label)==DST.
	 */
	const uint16_t			*subs;
	size_t				n_subs;
	const uint8_t			(*labels)[MESH_LABEL_UUID_LEN];
	size_t				n_labels;
};

#define	MESH_COMPANY_SIG	0xFFFFu

const struct mesh_opcode_entry *
	mesh_model_find_op(const struct mesh_model *m, uint32_t opcode);

/*
 * Generic model reply carrier (dispatch ctx).  A model receive handler reads
 * its server state from mesh_access_rx.model_user and, when a Status must be
 * returned, records it here through mesh_access_rx.ctx.  The dispatch caller
 * (e.g. mesh_sim) then transmits the recorded reply from src back to dst.
 *
 * This carrier is model-family agnostic: every family's handler fills the same
 * type so the sim reply loop is shared.  The parameter buffer is sized for the
 * largest model Status (Sensor / Lighting Status blocks far exceed the 7-octet
 * Generic maximum), not for any one family.
 */
#define	MESH_MODEL_REPLY_PARAMS_MAX	64

struct mesh_model_reply {
	int		have_reply;		/* a Status was produced */
	uint32_t	opcode;			/* reply opcode (STATUS) */
	uint8_t		params[MESH_MODEL_REPLY_PARAMS_MAX];
	size_t		params_len;
	uint16_t	src;			/* reply source (element addr) */
	uint16_t	dst;			/* reply destination (message src) */
};

/*
 * Destination-address resolution (MshPRT_v1.1 Sections 3.4.2 / 3.7).  Returns
 * 1 when the element is addressed by dst:
 *   - unicast dst : el->addr == dst;
 *   - all-nodes (0xFFFF) : always;
 *   - group   dst : dst appears in el->subs;
 *   - virtual dst : some el->labels entry hashes to dst.
 * Returns 0 otherwise (including the unassigned address).
 */
int	mesh_access_elem_addressed(const struct mesh_element *el, uint16_t dst);

int	mesh_access_dispatch(const struct mesh_element *elems, size_t n_elems,
	    uint16_t src, uint16_t dst, const uint8_t *pdu, size_t pdu_len,
		    void *ctx);
int	mesh_access_dispatch_at(const struct mesh_element *elems, size_t n_elems,
		    uint16_t src, uint16_t dst, const uint8_t *pdu, size_t pdu_len,
		    void *ctx, uint64_t now_ms);
int	mesh_access_dispatch_key_at(const struct mesh_element *elems,
	    size_t n_elems, uint16_t src, uint16_t dst, uint16_t app_idx,
	    const uint8_t *pdu, size_t pdu_len, void *ctx, uint64_t now_ms);
uint64_t mesh_access_now_ms(void);
void	mesh_access_tick(const struct mesh_element *, size_t, uint64_t);

struct mesh_transition_state {
	int active;
	int32_t initial;
	int32_t target;
	uint64_t start_ms;
	uint64_t end_ms;
};

int	mesh_transition_time_valid(uint8_t transition_time);
uint64_t mesh_transition_time_ms(uint8_t transition_time);
uint8_t mesh_transition_remaining(uint64_t remaining_ms);
void	mesh_transition_start(struct mesh_transition_state *, int32_t,
		    int32_t, uint8_t, uint8_t, uint64_t);
void	mesh_transition_start_ms(struct mesh_transition_state *, int32_t,
		    int32_t, uint64_t, uint8_t, uint64_t);
int32_t mesh_transition_sample(struct mesh_transition_state *, uint64_t);
uint16_t mesh_transition_sample_u16_circular(struct mesh_transition_state *,
	    uint64_t);
uint8_t mesh_transition_sample_binary(struct mesh_transition_state *,
		    uint64_t);

#endif /* _MESH_ACCESS_H_ */
