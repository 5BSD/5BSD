/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Directed Forwarding (MshPRT_v1.1 Section 3.6.6 and the
 * associated Directed Forwarding Configuration model, MshMDL_v1.1
 * Section 4.4.2).
 *
 * Directed Forwarding is the path-based routing subsystem layered on top of
 * managed flooding.  Where managed flooding (Section 3.4.6.3, mesh_net.[ch])
 * retransmits every relayable PDU on every interface, directed forwarding
 * establishes a path between a Path Origin and a Path Target and then forwards
 * a PDU only along that path's bearers, falling back to managed flooding when
 * no path applies.
 *
 * This module provides:
 *
 *   1. The Forwarding Table (Section 3.6.6.5): the discovered/fixed path
 *      entries a node keeps, with add / lookup / delete / expire.
 *   2. The path discovery transport-control PDUs (Section 3.6.6.5): Path
 *      Request (0x0B), Path Reply (0x0C), Path Confirmation (0x0D), Path Echo
 *      Request / Reply (0x0E / 0x0F), Dependent Node Update (0x10) and Path
 *      Request Solicitation (0x11) - big-endian build/parse codecs plus a
 *      unicast-address-range sub-codec.
 *   3. The path discovery state machine at the Path Origin: allocate a
 *      Forwarding Number, send a Path Request, accept a matching Path Reply,
 *      send a Path Confirmation, and establish the Forwarding Table entry;
 *      lane accounting and the 8-bit Forwarding Number wrap rules.
 *   4. The directed forwarding decision (Section 3.6.6.5): given a Network
 *      PDU, decide directed-forward vs managed-flooding fallback vs drop,
 *      gated by the directed-relay / directed-proxy / directed-friend feature
 *      states.  This plugs into the mesh_net relay decision point.
 *   5. The fixed-format Directed Forwarding Configuration model codecs
 *      (MshMDL_v1.1 Section 4.4.2): Directed Control, Path Metric, Wanted
 *      Lanes, Two Way Path, Path Echo Interval, Directed Network Transmit and
 *      Directed Relay Retransmit - Get / Set / Status.
 *
 * The module is pure and hardware-free: every codec operates on values in
 * network (big-endian) byte order for the transport-control PDUs and
 * little-endian for the model messages (per MshMDL), performs no I/O and keeps
 * no global state.  All timers are driven by a caller-supplied millisecond
 * clock (uint64_t now), exactly like mesh_iv / mesh_lpn, so tests advance a
 * mock clock rather than sleep.  Each function returns 0 on success and -1 on
 * failure with outputs zeroed on failure, unless documented as a predicate.
 */

#ifndef _MESH_DF_H_
#define _MESH_DF_H_

#include <stddef.h>
#include <stdint.h>

/* ================================================================
 * Path discovery transport-control opcodes (MshPRT_v1.1 Table 3.44).
 * These are 7-bit opcodes carried in an unsegmented Transport Control PDU
 * (CTL=1) as struct mesh_lower.opcode.
 * ================================================================ */
#define	MESH_DF_OP_PATH_REQUEST			0x0B
#define	MESH_DF_OP_PATH_REPLY			0x0C
#define	MESH_DF_OP_PATH_CONFIRMATION		0x0D
#define	MESH_DF_OP_PATH_ECHO_REQUEST		0x0E
#define	MESH_DF_OP_PATH_ECHO_REPLY		0x0F
#define	MESH_DF_OP_DEPENDENT_NODE_UPDATE	0x10
#define	MESH_DF_OP_PATH_REQUEST_SOLICITATION	0x11

/*
 * Path metric type (Section 3.6.6.5).  Only the node-count metric (0) is
 * defined by MshPRT_v1.1; the field is 3 bits wide.
 */
#define	MESH_DF_METRIC_NODE_COUNT		0x00

/*
 * Path lifetime selector (Section 3.6.6.5.1), a 2-bit field choosing the
 * Forwarding Table entry lifetime once a path is established.
 */
#define	MESH_DF_LIFETIME_12_MIN			0x00
#define	MESH_DF_LIFETIME_2_HOUR			0x01
#define	MESH_DF_LIFETIME_24_HOUR		0x02
#define	MESH_DF_LIFETIME_10_DAY			0x03

/* Path lifetime durations in milliseconds, indexed by the selector above. */
extern const uint64_t mesh_df_lifetime_ms[4];

/* Dependent Node Update type (Section 3.6.6.5.6). */
#define	MESH_DF_DEP_REMOVE			0x00
#define	MESH_DF_DEP_ADD				0x01

/* ================================================================
 * Unicast address range (Section 3.6.6.4).  A 2- or 3-octet range used to
 * carry a Path Origin / Path Target / Dependent address span.  Wire layout,
 * big-endian:
 *
 *   octets 0-1: (Range_Start << 1) | Length_Present
 *   octet 2   : Range_Length            -- present only when Length_Present
 *
 * Range_Start is a 15-bit unicast address (0x0001..0x7FFF).  When
 * Length_Present is 0 the range is the single address Range_Start (length 1);
 * otherwise Range_Length (>= 2) addresses starting at Range_Start.
 * ================================================================ */
struct mesh_df_addr_range {
	uint16_t	range_start;
	uint8_t		range_length;	/* number of addresses, >= 1 */
};
int	mesh_df_addr_range_build(const struct mesh_df_addr_range *in,
	    uint8_t *out, size_t *outlen);
int	mesh_df_addr_range_parse(const uint8_t *in, size_t inlen,
	    struct mesh_df_addr_range *out, size_t *used);

/* ================================================================
 * Path Request (0x0B).  Section 3.6.6.5.1.  Parameter wire layout:
 *
 *   o0: [7]=On_Behalf_Of_Dependent_Origin
 *       [4:6]=Path_Origin_Path_Metric_Type (3)
 *       [2:3]=Path_Origin_Path_Lifetime (2)
 *       [1]=Path_Discovery_Interval
 *       [0]=RFU
 *   o1: Path_Origin_Forwarding_Number (8)
 *   o2: [1:7]=Path_Metric (7)  [0]=RFU
 *   o3-o4: Destination (Path Target address, 16 big-endian)
 *   o5..:  Path_Origin unicast address range (2 or 3)
 *   [.. :  Dependent_Origin unicast address range (2 or 3), iff OBO=1]
 * ================================================================ */
struct mesh_df_path_request {
	uint8_t				on_behalf_of_dependent_origin;
	uint8_t				metric_type;	/* 3 bits */
	uint8_t				lifetime;	/* 2 bits, MESH_DF_LIFETIME_* */
	uint8_t				path_discovery_interval; /* 1 bit */
	uint8_t				forwarding_number;
	uint8_t				path_metric;	/* 7 bits */
	uint16_t			destination;	/* Path Target */
	struct mesh_df_addr_range	origin;		/* Path Origin range */
	struct mesh_df_addr_range	dependent_origin; /* iff OBO */
};
int	mesh_df_path_request_build(const struct mesh_df_path_request *in,
	    uint8_t *out, size_t *outlen);
int	mesh_df_path_request_parse(const uint8_t *in, size_t inlen,
	    struct mesh_df_path_request *out);

/* ================================================================
 * Path Reply (0x0C).  Section 3.6.6.5.2.  Parameter wire layout:
 *
 *   o0: [7]=On_Behalf_Of_Dependent_Target
 *       [6]=Confirmation_Request
 *       [0:5]=RFU
 *   o1: Forwarding_Number (8)  -- the Path Origin Forwarding Number replied to
 *   o2-o3: Path_Origin address (16 big-endian)
 *   o4..:  Path_Target unicast address range (2 or 3)
 *   [.. :  Dependent_Target unicast address range (2 or 3), iff OBO=1]
 * ================================================================ */
struct mesh_df_path_reply {
	uint8_t				on_behalf_of_dependent_target;
	uint8_t				confirmation_request;
	uint8_t				forwarding_number;
	uint16_t			path_origin;
	struct mesh_df_addr_range	target;		/* Path Target range */
	struct mesh_df_addr_range	dependent_target; /* iff OBO */
};
int	mesh_df_path_reply_build(const struct mesh_df_path_reply *in,
	    uint8_t *out, size_t *outlen);
int	mesh_df_path_reply_parse(const uint8_t *in, size_t inlen,
	    struct mesh_df_path_reply *out);

/* ================================================================
 * Path Confirmation (0x0D).  Section 3.6.6.5.3.  Four octets:
 *   o0-o1: Path_Origin (16 big-endian)
 *   o2-o3: Path_Target (16 big-endian)
 * ================================================================ */
struct mesh_df_path_confirmation {
	uint16_t	path_origin;
	uint16_t	path_target;
};
int	mesh_df_path_confirmation_build(const struct mesh_df_path_confirmation *in,
	    uint8_t *out, size_t *outlen);
int	mesh_df_path_confirmation_parse(const uint8_t *in, size_t inlen,
	    struct mesh_df_path_confirmation *out);

/* ================================================================
 * Path Echo Request (0x0E): no parameters.  Path Echo Reply (0x0F): a single
 * Destination unicast address (16 big-endian).  Section 3.6.6.5.4 / 3.6.6.5.5.
 * ================================================================ */
int	mesh_df_path_echo_request_build(uint8_t *out, size_t *outlen);
int	mesh_df_path_echo_reply_build(uint16_t destination, uint8_t *out,
	    size_t *outlen);
int	mesh_df_path_echo_reply_parse(const uint8_t *in, size_t inlen,
	    uint16_t *destination);

/* ================================================================
 * Dependent Node Update (0x10).  Section 3.6.6.5.6.  Wire layout:
 *   o0: [0]=Type (0 remove, 1 add)  [1:7]=RFU
 *   o1-o2: Path_Endpoint address (16 big-endian; a Path Origin or Path Target)
 *   o3..:  Dependent_Node unicast address range (2 or 3)
 * ================================================================ */
struct mesh_df_dependent_update {
	uint8_t				type;		/* MESH_DF_DEP_* */
	uint16_t			path_endpoint;
	struct mesh_df_addr_range	dependent;
};
int	mesh_df_dependent_update_build(const struct mesh_df_dependent_update *in,
	    uint8_t *out, size_t *outlen);
int	mesh_df_dependent_update_parse(const uint8_t *in, size_t inlen,
	    struct mesh_df_dependent_update *out);

/* ================================================================
 * Path Request Solicitation (0x11).  Section 3.6.6.5.7.  A list of Destination
 * unicast addresses (16 big-endian each), at least one.
 * ================================================================ */
#define	MESH_DF_SOLICITATION_MAX	8
int	mesh_df_path_solicitation_build(const uint16_t *dests, size_t n,
	    uint8_t *out, size_t *outlen);
int	mesh_df_path_solicitation_parse(const uint8_t *in, size_t inlen,
	    uint16_t *dests, size_t max, size_t *n);

/* ================================================================
 * Forwarding Number arithmetic (Section 3.6.6.5).  The Forwarding Number is an
 * 8-bit value incremented for each new path discovery originated by a node and
 * wraps modulo 256.  Freshness is decided by serial-number arithmetic: b is
 * newer than a when (b - a) mod 256 lies in 1..127.
 * ================================================================ */
uint8_t	mesh_df_fn_next(uint8_t fn);
int	mesh_df_fn_newer(uint8_t a, uint8_t b);

/* ================================================================
 * Forwarding Table (Section 3.6.6.5).
 *
 * Each entry records one established (or fixed) path.  A directed forward is
 * possible for a Network PDU whose SRC/DST are covered by an entry that is
 * still within its lifetime.  Lane counters track the number of established
 * lanes vs the wanted lanes for a path.
 * ================================================================ */
#define	MESH_DF_MAX_DEPENDENTS		4

struct mesh_df_fwd_entry {
	int		valid;
	int		fixed_path;	/* 1 = provisioned fixed path (no lifetime) */
	int		backward_validated; /* Path Confirmation seen (lane locked) */
	uint16_t	path_origin;
	uint16_t	path_target;	/* unicast, group or virtual */
	uint8_t		forwarding_number;
	uint8_t		bearer_toward_origin;
	uint8_t		bearer_toward_target;
	uint8_t		lane_counter;	/* established lanes */
	uint16_t	dep_origin[MESH_DF_MAX_DEPENDENTS];
	size_t		dep_origin_n;
	uint16_t	dep_target[MESH_DF_MAX_DEPENDENTS];
	size_t		dep_target_n;
	uint64_t	install_ms;	/* clock when (re)installed */
	uint64_t	last_used_ms;	/* clock at last forward along this path */
	uint64_t	lifetime_ms;	/* 0 for a fixed path */
};

/*
 * A path half is "installed" when its bearer is known.  The reverse half
 * (toward the Path Origin) is set from a Path Request; the forward half
 * (toward the Path Target) from a Path Reply.  These derive path state without
 * enlarging the entry, which is embedded per node in higher layers.
 */
#define	mesh_df_entry_reverse_valid(e)	\
	((e)->bearer_toward_origin != MESH_DF_BEARER_NONE)
#define	mesh_df_entry_forward_valid(e)	\
	((e)->bearer_toward_target != MESH_DF_BEARER_NONE)

#define	MESH_DF_MAX_ENTRIES		8

struct mesh_df_fwd_table {
	struct mesh_df_fwd_entry	entries[MESH_DF_MAX_ENTRIES];
	size_t				count;
};

void	mesh_df_table_init(struct mesh_df_fwd_table *t);

/*
 * Add (or refresh) a forwarding-table entry for (origin, target).  A matching
 * entry is updated in place (bearers, forwarding number, install time);
 * otherwise a free slot is claimed.  lifetime_ms is the entry lifetime (0 for a
 * fixed path).  Returns the entry on success or NULL when the table is full.
 */
struct mesh_df_fwd_entry *mesh_df_table_add(struct mesh_df_fwd_table *t,
	    uint16_t origin, uint16_t target, uint8_t forwarding_number,
	    uint8_t bearer_toward_origin, uint8_t bearer_toward_target,
	    uint64_t lifetime_ms, uint64_t now);

/*
 * Look up a non-expired entry whose path can carry a PDU to dst originated by
 * src.  A dst matching the entry's Path Target (or one of its dependent target
 * addresses) selects the entry toward the target; a dst matching the Path
 * Origin (or dependent origin) selects the entry toward the origin.  Returns
 * the entry or NULL.  Expired entries are ignored (but not removed; call
 * mesh_df_table_expire()).
 */
struct mesh_df_fwd_entry *mesh_df_table_lookup(struct mesh_df_fwd_table *t,
	    uint16_t src, uint16_t dst, uint64_t now);

/* Remove the entry for (origin, target).  Returns 0 if removed, -1 if absent. */
int	mesh_df_table_delete(struct mesh_df_fwd_table *t, uint16_t origin,
	    uint16_t target);

/* Add a dependent address to an entry's origin/target dependent list. */
int	mesh_df_entry_add_dependent(struct mesh_df_fwd_entry *e, int toward_target,
	    uint16_t addr);

/*
 * Remove a dependent address from an entry's origin/target dependent list.
 * Returns 0 whether or not the address was present, -1 on a bad argument.
 */
int	mesh_df_entry_del_dependent(struct mesh_df_fwd_entry *e, int toward_target,
	    uint16_t addr);

/*
 * Expire entries whose lifetime elapsed at now.  Fixed paths never expire.
 * Returns the number of entries removed.
 */
size_t	mesh_df_table_expire(struct mesh_df_fwd_table *t, uint64_t now);

/* ================================================================
 * Path discovery state machine (Path Origin role, Section 3.6.6.5).
 * ================================================================ */
enum mesh_df_disc_state {
	MESH_DF_DISC_IDLE = 0,
	MESH_DF_DISC_REQUEST_SENT,	/* Path Request sent, awaiting Reply */
	MESH_DF_DISC_REPLY_RECEIVED,	/* Reply accepted, Confirmation due */
	MESH_DF_DISC_ESTABLISHED,	/* path installed */
	MESH_DF_DISC_FAILED		/* discovery timed out */
};

struct mesh_df_discovery {
	enum mesh_df_disc_state	state;
	uint16_t		origin;		/* this node (Path Origin) */
	uint16_t		target;		/* Path Target sought */
	uint8_t			forwarding_number;
	uint8_t			metric_type;
	uint8_t			lifetime;	/* MESH_DF_LIFETIME_* */
	uint8_t			wanted_lanes;
	uint8_t			lane_counter;
	int			two_way_path;	/* request confirmation from target */
	uint64_t		started_ms;
	uint64_t		timeout_ms;	/* discovery timeout */
};

/*
 * Begin a path discovery from origin to target.  fn is the Forwarding Number to
 * use for this discovery (the caller advances it with mesh_df_fn_next()).  The
 * built Path Request parameters are written to *req.  On return the state is
 * MESH_DF_DISC_REQUEST_SENT.  timeout_ms is the discovery timeout (the origin
 * gives up and the state becomes MESH_DF_DISC_FAILED after it elapses).
 */
int	mesh_df_discovery_start(struct mesh_df_discovery *d, uint16_t origin,
	    uint16_t target, uint8_t fn, uint8_t metric_type, uint8_t lifetime,
	    uint8_t wanted_lanes, int two_way_path, uint64_t timeout_ms,
	    uint64_t now, struct mesh_df_path_request *req);

/*
 * Feed a received Path Reply into the state machine.  The reply is accepted
 * only when it matches the outstanding discovery (Path Origin == this node,
 * Forwarding Number == the request's, Path Target range covers the sought
 * target).  On acceptance the state becomes MESH_DF_DISC_REPLY_RECEIVED, the
 * lane counter is incremented, and *need_confirm reports whether a Path
 * Confirmation must be sent (from the reply's Confirmation_Request or the
 * configured two-way path).  Returns 1 when accepted, 0 when the reply does not
 * match this discovery, -1 on error.
 */
int	mesh_df_discovery_on_reply(struct mesh_df_discovery *d,
	    const struct mesh_df_path_reply *rep, int *need_confirm);

/*
 * Build the Path Confirmation for a discovery in the REPLY_RECEIVED state and
 * mark it ESTABLISHED.  Returns -1 if the discovery is not awaiting confirm.
 */
int	mesh_df_discovery_confirm(struct mesh_df_discovery *d,
	    struct mesh_df_path_confirmation *conf);

/* Report whether the discovery has timed out at now (advances to FAILED). */
int	mesh_df_discovery_timed_out(struct mesh_df_discovery *d, uint64_t now);

/* ================================================================
 * Directed forwarding decision (Section 3.6.6.5), the mesh_net relay hook.
 *
 * Feature-state gates a node applies when relaying: whether it may use directed
 * forwarding as a relay / proxy / friend, and whether managed flooding is
 * available as the fallback.
 * ================================================================ */
struct mesh_df_features {
	int	directed_relay;		/* Directed Relay enabled */
	int	directed_proxy;		/* Directed Proxy enabled */
	int	directed_friend;	/* Directed Friend enabled */
	int	managed_flood_relay;	/* base managed-flooding Relay enabled */
};

enum mesh_df_forward {
	MESH_DF_FORWARD_DROP = 0,	/* not forwarded */
	MESH_DF_FORWARD_FLOOD,		/* managed-flooding relay (mesh_net_relay) */
	MESH_DF_FORWARD_DIRECTED	/* forward along the matched path */
};

/*
 * Decide how to forward a received Network PDU.  When a valid forwarding-table
 * entry covers (src, dst) and any directed feature is enabled the verdict is
 * MESH_DF_FORWARD_DIRECTED; otherwise, when the base managed-flooding Relay is
 * enabled and the TTL permits (>= 2), the verdict is MESH_DF_FORWARD_FLOOD;
 * otherwise MESH_DF_FORWARD_DROP.  In the FLOOD and DIRECTED cases *new_ttl
 * receives the decremented TTL (ttl - 1).  Directed forwarding requires TTL
 * >= 2 as well (a two-hop path still spends one TTL per hop).  The matched
 * entry (DIRECTED case) is returned via *matched when non-NULL and its
 * last_used_ms is refreshed.
 */
enum mesh_df_forward mesh_df_forward_decide(struct mesh_df_fwd_table *t,
	    const struct mesh_df_features *feat, uint16_t src, uint16_t dst,
	    uint8_t ttl, uint8_t *new_ttl, uint64_t now,
	    struct mesh_df_fwd_entry **matched);

/* ================================================================
 * Non-origin path discovery roles (MshPRT_v1.1 Section 3.6.6.5).
 *
 * These drive the relay-side and target-side of directed forwarding: a node
 * that is not the Path Origin processes received transport-control PDUs to
 * build the reverse and forward halves of a path, replies as the Path Target,
 * locks lanes on Path Confirmation, tracks dependent nodes, and runs the Path
 * Echo keep-alive.  Everything is pure: no I/O, no real clock.  The transport
 * layer supplies the incoming network context (src/dst/ttl/bearer) and a mock
 * millisecond clock; each handler reports what to transmit next and where.
 * ================================================================ */

/*
 * Bearer identifier.  A caller-chosen non-zero interface index; 0 is reserved
 * to mean "no bearer" (an unknown half of a path) and, as an output bearer, a
 * managed-flood transmission on every interface except the incoming one.
 */
#define	MESH_DF_BEARER_NONE		0
#define	MESH_DF_BEARER_FLOOD		0

/*
 * A node's directed-forwarding identity and state.  addr..addr_last is this
 * node's element unicast-address range (addr_last == addr for a single-element
 * node).  lifetime selects the Forwarding Table entry lifetime for paths this
 * node installs (MESH_DF_LIFETIME_*).  two_way_path makes the Path Target set
 * Confirmation_Request in its Path Reply.
 */
struct mesh_df_node {
	uint16_t			addr;		/* primary element address */
	uint16_t			addr_last;	/* last element address */
	uint8_t				lifetime;	/* MESH_DF_LIFETIME_* */
	int				two_way_path;
	struct mesh_df_fwd_table	table;
	/*
	 * Path Echo state, indexed in lock-step with table.entries[].  Kept in
	 * the node (not the entry) so the shared Forwarding Table entry stays
	 * compact for the layers that embed it per node.
	 */
	int				echo_pending[MESH_DF_MAX_ENTRIES];
	uint64_t			echo_deadline_ms[MESH_DF_MAX_ENTRIES];
};

void	mesh_df_node_init(struct mesh_df_node *n, uint16_t addr,
	    uint16_t addr_last, uint8_t lifetime, int two_way_path);

/* Incoming network context for a received transport-control PDU. */
struct mesh_df_recv_ctx {
	uint16_t	src;		/* network SRC */
	uint16_t	dst;		/* network DST */
	uint8_t		ttl;		/* incoming TTL */
	uint8_t		bearer;		/* incoming bearer (non-zero) */
	uint64_t	now;		/* mock clock, ms */
};

/*
 * A transport-control PDU to emit as a result of processing.  opcode is the
 * 7-bit transport-control opcode; pdu/pdulen are the parameter octets (no
 * opcode byte, matching the codecs above).  bearer is the outgoing bearer
 * (MESH_DF_BEARER_FLOOD == managed flood).  src/dst/ttl are the network fields
 * to send it with.
 */
struct mesh_df_output {
	uint8_t		opcode;
	uint8_t		bearer;
	uint8_t		ttl;
	uint16_t	src;
	uint16_t	dst;
	uint8_t		pdu[32];
	size_t		pdulen;
};

/*
 * mesh_df_recv_control() result.  DROP: PDU rejected (truncated/invalid/no
 * matching state).  CONSUMED: processed, nothing to transmit.  FORWARD: *out
 * holds a PDU to transmit.  FOR_ORIGIN: a Path Reply reached this node acting
 * as the Path Origin (feed the origin state machine).  FOR_TARGET: a Path
 * Request/Echo reached this node as the Path Target and *out holds the reply.
 */
#define	MESH_DF_RECV_DROP		(-1)
#define	MESH_DF_RECV_CONSUMED		0
#define	MESH_DF_RECV_FORWARD		1
#define	MESH_DF_RECV_FOR_ORIGIN		2
#define	MESH_DF_RECV_FOR_TARGET		3

/*
 * Dispatch a received transport-control PDU by opcode (Section 3.6.6.5).  pdu/
 * pdulen are the parameter octets for the given opcode.  Every parse is
 * length-gated.  *out is filled only when the result is FORWARD or FOR_TARGET.
 */
int	mesh_df_recv_control(struct mesh_df_node *node,
	    const struct mesh_df_recv_ctx *ctx, uint8_t opcode,
	    const uint8_t *pdu, size_t pdulen, struct mesh_df_output *out);

/*
 * Send a Path Echo Request along the established path toward target (Section
 * 3.6.6.5.4).  Marks the matched entry echo-pending with a deadline at
 * now + timeout_ms.  *out receives the Echo Request to transmit toward the
 * target.  Returns 0 on success, -1 if no path toward target exists.
 */
int	mesh_df_echo_start(struct mesh_df_node *node, uint16_t target,
	    uint8_t ttl, uint64_t timeout_ms, uint64_t now,
	    struct mesh_df_output *out);

/*
 * Invalidate every path whose Path Echo Request went unanswered by its
 * deadline at now (Section 3.6.6.5.4).  Returns the number of paths removed.
 */
size_t	mesh_df_echo_expire(struct mesh_df_node *node, uint64_t now);

/* Predicate: is a Path Echo Request outstanding for the path toward target? */
int	mesh_df_echo_is_pending(const struct mesh_df_node *node, uint16_t target);

/* ================================================================
 * Directed Forwarding Configuration model (MshMDL_v1.1 Section 4.4.2).
 *
 * Opcodes are the 2-octet 0x807B.. block that follows the Section 4.3.4 block
 * implemented in mesh_cfg_v11.[ch].  Multi-octet fields are little-endian, as
 * for every other Configuration model message.
 * ================================================================ */
#define	MESH_CFG_OP_DIRECTED_CONTROL_GET		0x807B
#define	MESH_CFG_OP_DIRECTED_CONTROL_SET		0x807C
#define	MESH_CFG_OP_DIRECTED_CONTROL_STATUS		0x807D
#define	MESH_CFG_OP_PATH_METRIC_GET			0x807E
#define	MESH_CFG_OP_PATH_METRIC_SET			0x807F
#define	MESH_CFG_OP_PATH_METRIC_STATUS			0x8080
#define	MESH_CFG_OP_WANTED_LANES_GET			0x8090
#define	MESH_CFG_OP_WANTED_LANES_SET			0x8091
#define	MESH_CFG_OP_WANTED_LANES_STATUS			0x8092
#define	MESH_CFG_OP_TWO_WAY_PATH_GET			0x8093
#define	MESH_CFG_OP_TWO_WAY_PATH_SET			0x8094
#define	MESH_CFG_OP_TWO_WAY_PATH_STATUS			0x8095
#define	MESH_CFG_OP_PATH_ECHO_INTERVAL_GET		0x8096
#define	MESH_CFG_OP_PATH_ECHO_INTERVAL_SET		0x8097
#define	MESH_CFG_OP_PATH_ECHO_INTERVAL_STATUS		0x8098
#define	MESH_CFG_OP_DIRECTED_NET_TRANSMIT_GET		0x8099
#define	MESH_CFG_OP_DIRECTED_NET_TRANSMIT_SET		0x809A
#define	MESH_CFG_OP_DIRECTED_NET_TRANSMIT_STATUS	0x809B
#define	MESH_CFG_OP_DIRECTED_RELAY_RETRANSMIT_GET	0x809C
#define	MESH_CFG_OP_DIRECTED_RELAY_RETRANSMIT_SET	0x809D
#define	MESH_CFG_OP_DIRECTED_RELAY_RETRANSMIT_STATUS	0x809E

/* Config message status code shared by every Config model.  Section 4.3.9. */
#define	MESH_CFG_STATUS_SUCCESS				0x00

/*
 * Directed Control (Section 4.2.24).  The per-subnet directed feature state.
 * Directed Control Get: NetKeyIndex (2, LE).
 * Directed Control Set: NetKeyIndex (2) + five one-octet state fields.
 * Directed Control Status: Status (1) + NetKeyIndex (2) + five state fields.
 */
struct mesh_cfg_directed_control {
	uint16_t	net_idx;
	uint8_t		directed_forwarding;
	uint8_t		directed_relay;
	uint8_t		directed_proxy;
	uint8_t		directed_proxy_use_directed_default;
	uint8_t		directed_friend;
};
int	mesh_cfg_directed_control_get_build(uint16_t net_idx, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_directed_control_get_parse(const uint8_t *in, size_t inlen,
	    uint16_t *net_idx);
int	mesh_cfg_directed_control_set_build(const struct mesh_cfg_directed_control *in,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_directed_control_set_parse(const uint8_t *in, size_t inlen,
	    struct mesh_cfg_directed_control *out);
int	mesh_cfg_directed_control_status_build(uint8_t status,
	    const struct mesh_cfg_directed_control *in, uint8_t *out, size_t *outlen);
int	mesh_cfg_directed_control_status_parse(const uint8_t *in, size_t inlen,
	    uint8_t *status, struct mesh_cfg_directed_control *out);

/*
 * Path Metric (Section 4.2.25).  Get: NetKeyIndex (2).  Set: NetKeyIndex (2) +
 * one packed octet ([0:2]=Metric_Type(3), [3:4]=Lifetime(2), [5:7]=RFU).
 * Status: Status (1) + NetKeyIndex (2) + packed octet.
 */
struct mesh_cfg_path_metric {
	uint16_t	net_idx;
	uint8_t		metric_type;	/* 3 bits */
	uint8_t		lifetime;	/* 2 bits, MESH_DF_LIFETIME_* */
};
int	mesh_cfg_path_metric_get_build(uint16_t net_idx, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_path_metric_set_build(const struct mesh_cfg_path_metric *in,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_path_metric_set_parse(const uint8_t *in, size_t inlen,
	    struct mesh_cfg_path_metric *out);
int	mesh_cfg_path_metric_status_build(uint8_t status,
	    const struct mesh_cfg_path_metric *in, uint8_t *out, size_t *outlen);
int	mesh_cfg_path_metric_status_parse(const uint8_t *in, size_t inlen,
	    uint8_t *status, struct mesh_cfg_path_metric *out);

/*
 * Wanted Lanes (Section 4.2.27).  NetKeyIndex (2) + Wanted_Lanes (1).  Get has
 * only NetKeyIndex; Set/Status add the octet; Status also prefixes a Status.
 */
struct mesh_cfg_wanted_lanes {
	uint16_t	net_idx;
	uint8_t		wanted_lanes;
};
int	mesh_cfg_wanted_lanes_get_build(uint16_t net_idx, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_wanted_lanes_set_build(const struct mesh_cfg_wanted_lanes *in,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_wanted_lanes_set_parse(const uint8_t *in, size_t inlen,
	    struct mesh_cfg_wanted_lanes *out);
int	mesh_cfg_wanted_lanes_status_build(uint8_t status,
	    const struct mesh_cfg_wanted_lanes *in, uint8_t *out, size_t *outlen);
int	mesh_cfg_wanted_lanes_status_parse(const uint8_t *in, size_t inlen,
	    uint8_t *status, struct mesh_cfg_wanted_lanes *out);

/*
 * Two Way Path (Section 4.2.26).  NetKeyIndex (2) + one octet whose bit 0 is
 * the Two_Way_Path flag (Set/Status); Get carries only NetKeyIndex.  Status
 * prefixes a Status octet.
 */
struct mesh_cfg_two_way_path {
	uint16_t	net_idx;
	uint8_t		two_way_path;	/* 1 bit */
};
int	mesh_cfg_two_way_path_get_build(uint16_t net_idx, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_two_way_path_set_build(const struct mesh_cfg_two_way_path *in,
	    uint8_t *out, size_t *outlen);
int	mesh_cfg_two_way_path_set_parse(const uint8_t *in, size_t inlen,
	    struct mesh_cfg_two_way_path *out);
int	mesh_cfg_two_way_path_status_build(uint8_t status,
	    const struct mesh_cfg_two_way_path *in, uint8_t *out, size_t *outlen);
int	mesh_cfg_two_way_path_status_parse(const uint8_t *in, size_t inlen,
	    uint8_t *status, struct mesh_cfg_two_way_path *out);

/*
 * Path Echo Interval (Section 4.2.28).  NetKeyIndex (2) + Unicast_Echo_Interval
 * (1) + Multicast_Echo_Interval (1).  Get carries only NetKeyIndex; Status
 * prefixes a Status octet.
 */
struct mesh_cfg_path_echo_interval {
	uint16_t	net_idx;
	uint8_t		unicast_echo_interval;
	uint8_t		multicast_echo_interval;
};
int	mesh_cfg_path_echo_interval_get_build(uint16_t net_idx, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_path_echo_interval_set_build(
	    const struct mesh_cfg_path_echo_interval *in, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_path_echo_interval_set_parse(const uint8_t *in, size_t inlen,
	    struct mesh_cfg_path_echo_interval *out);
int	mesh_cfg_path_echo_interval_status_build(uint8_t status,
	    const struct mesh_cfg_path_echo_interval *in, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_path_echo_interval_status_parse(const uint8_t *in, size_t inlen,
	    uint8_t *status, struct mesh_cfg_path_echo_interval *out);

/*
 * Directed Network Transmit (Section 4.2.31) and Directed Relay Retransmit
 * (Section 4.2.32) share the one-octet Transmit format used by the classic
 * Network / Relay transmit states: [0:2]=Count (3), [3:7]=Interval_Steps (5).
 * Get: no parameters.  Set/Status: the one octet.
 */
struct mesh_cfg_transmit {
	uint8_t		count;		/* 3 bits: transmissions = count + 1 */
	uint8_t		interval_steps;	/* 5 bits: interval = (steps + 1) * 10 ms */
};
int	mesh_cfg_directed_transmit_get_build(uint32_t opcode, uint8_t *out,
	    size_t *outlen);
int	mesh_cfg_directed_transmit_build(uint32_t opcode,
	    const struct mesh_cfg_transmit *in, uint8_t *out, size_t *outlen);
int	mesh_cfg_directed_transmit_parse(const uint8_t *in, size_t inlen,
	    uint32_t *opcode, struct mesh_cfg_transmit *out);

#endif /* _MESH_DF_H_ */
