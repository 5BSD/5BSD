/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh Generic models (Mesh Model 1.1, MshMDL_v1.1 Section 3.2),
 * built on the cleartext access-layer codec of mesh_access.[ch]
 * (MshPRT_v1.1 Section 3.7).  This module is the canonical application-model
 * layer that the multi-node simulator (mesh_sim.[ch]) composes end to end.
 *
 * Two model pairs are implemented:
 *
 *   - Generic OnOff Server (0x1000) / Client (0x1001)   MshMDL Section 3.2.1
 *       Opcodes (Section 7.1): Get 0x8201, Set 0x8202,
 *       Set Unacknowledged 0x8203, Status 0x8204.
 *   - Generic Level Server (0x1002) / Client (0x1003)   MshMDL Section 3.2.2
 *       Opcodes (Section 7.1): Get 0x8205, Set 0x8206,
 *       Set Unacknowledged 0x8207, Status 0x8208, Delta Set 0x8209,
 *       Delta Set Unacknowledged 0x820A, Move Set 0x820B,
 *       Move Set Unacknowledged 0x820C.
 *
 * BYTE ORDER.  Unlike the network layer, access-layer model message fields
 * are LITTLE-endian (MshPRT_v1.1 Section 3.7.2): the Level, Delta Level and
 * Move Delta multi-octet fields are packed low octet first.  The message
 * codecs below emit and consume only the opcode PARAMETERS; the enclosing
 * opcode is added by mesh_access_pdu_build() (the client send helpers do this
 * for the caller and return a complete Access PDU).
 *
 * STATE MODEL.  Timed state changes use an injected millisecond clock.  The
 * servers retain present and target values, honor Delay and Transition Time,
 * sample transitions when receiving or querying state, and encode the
 * optional Target/Remaining Time fields while a transition is active.  No
 * wall clock, hardware I/O, or background scheduler is hidden in this module.
 *
 * Pure and hardware-free: no I/O, no globals, no dynamic allocation.  The
 * *_encode/_decode codecs return 0 on success and -1 on failure with the
 * output zeroed; predicates/receivers return their documented result.
 */

#ifndef _MESH_GENERIC_H_
#define _MESH_GENERIC_H_

#include <stddef.h>
#include <stdint.h>

#include "mesh_access.h"

/* SIG model identifiers (MshMDL_v1.1 Section 7.3). */
#define	MESH_MODEL_GEN_ONOFF_SRV	0x1000
#define	MESH_MODEL_GEN_ONOFF_CLI	0x1001
#define	MESH_MODEL_GEN_LEVEL_SRV	0x1002
#define	MESH_MODEL_GEN_LEVEL_CLI	0x1003
#define	MESH_MODEL_GEN_DTT_SRV		0x1004
#define	MESH_MODEL_GEN_DTT_CLI		0x1005
#define	MESH_MODEL_GEN_POWER_ONOFF_SRV	0x1006
#define	MESH_MODEL_GEN_POWER_ONOFF_SETUP_SRV 0x1007
#define	MESH_MODEL_GEN_POWER_ONOFF_CLI	0x1008
#define	MESH_MODEL_GEN_POWER_LEVEL_SRV	0x1009
#define	MESH_MODEL_GEN_POWER_LEVEL_SETUP_SRV 0x100a
#define	MESH_MODEL_GEN_POWER_LEVEL_CLI	0x100b
#define	MESH_MODEL_GEN_BATTERY_SRV	0x100c
#define	MESH_MODEL_GEN_BATTERY_CLI	0x100d
#define	MESH_MODEL_GEN_LOCATION_SRV	0x100e
#define	MESH_MODEL_GEN_LOCATION_SETUP_SRV 0x100f
#define	MESH_MODEL_GEN_LOCATION_CLI	0x1010

/* Generic OnOff opcodes (MshMDL_v1.1 Section 7.1). */
#define	MESH_OP_GEN_ONOFF_GET		0x8201u
#define	MESH_OP_GEN_ONOFF_SET		0x8202u
#define	MESH_OP_GEN_ONOFF_SET_UNACK	0x8203u
#define	MESH_OP_GEN_ONOFF_STATUS	0x8204u

/* Generic Level opcodes (MshMDL_v1.1 Section 7.1). */
#define	MESH_OP_GEN_LEVEL_GET		0x8205u
#define	MESH_OP_GEN_LEVEL_SET		0x8206u
#define	MESH_OP_GEN_LEVEL_SET_UNACK	0x8207u
#define	MESH_OP_GEN_LEVEL_STATUS	0x8208u
#define	MESH_OP_GEN_DELTA_SET		0x8209u
#define	MESH_OP_GEN_DELTA_SET_UNACK	0x820Au
#define	MESH_OP_GEN_MOVE_SET		0x820Bu
#define	MESH_OP_GEN_MOVE_SET_UNACK	0x820Cu
#define	MESH_OP_GEN_DTT_GET		0x820Du
#define	MESH_OP_GEN_DTT_SET		0x820Eu
#define	MESH_OP_GEN_DTT_SET_UNACK	0x820Fu
#define	MESH_OP_GEN_DTT_STATUS		0x8210u
#define	MESH_OP_GEN_ONPOWERUP_GET	0x8211u
#define	MESH_OP_GEN_ONPOWERUP_STATUS	0x8212u
#define	MESH_OP_GEN_ONPOWERUP_SET	0x8213u
#define	MESH_OP_GEN_ONPOWERUP_SET_UNACK 0x8214u
#define	MESH_OP_GEN_POWER_LEVEL_GET	0x8215u
#define	MESH_OP_GEN_POWER_LEVEL_SET	0x8216u
#define	MESH_OP_GEN_POWER_LEVEL_SET_UNACK 0x8217u
#define	MESH_OP_GEN_POWER_LEVEL_STATUS	0x8218u
#define	MESH_OP_GEN_POWER_LAST_GET	0x8219u
#define	MESH_OP_GEN_POWER_LAST_STATUS	0x821au
#define	MESH_OP_GEN_POWER_DEFAULT_GET	0x821bu
#define	MESH_OP_GEN_POWER_DEFAULT_STATUS 0x821cu
#define	MESH_OP_GEN_POWER_RANGE_GET	0x821du
#define	MESH_OP_GEN_POWER_RANGE_STATUS	0x821eu
#define	MESH_OP_GEN_POWER_DEFAULT_SET	0x821fu
#define	MESH_OP_GEN_POWER_DEFAULT_SET_UNACK 0x8220u
#define	MESH_OP_GEN_POWER_RANGE_SET	0x8221u
#define	MESH_OP_GEN_POWER_RANGE_SET_UNACK 0x8222u
#define	MESH_OP_GEN_BATTERY_GET		0x8223u
#define	MESH_OP_GEN_BATTERY_STATUS	0x8224u
#define	MESH_OP_GEN_LOCATION_GLOBAL_GET 0x8225u
#define	MESH_OP_GEN_LOCATION_LOCAL_GET	0x8226u
#define	MESH_OP_GEN_LOCATION_LOCAL_STATUS 0x8227u
#define	MESH_OP_GEN_LOCATION_LOCAL_SET	0x8228u
#define	MESH_OP_GEN_LOCATION_LOCAL_SET_UNACK 0x8229u
#define	MESH_OP_GEN_LOCATION_GLOBAL_STATUS 0x40u
#define	MESH_OP_GEN_LOCATION_GLOBAL_SET 0x41u
#define	MESH_OP_GEN_LOCATION_GLOBAL_SET_UNACK 0x42u

#define	MESH_GEN_ONPOWERUP_OFF		0x00
#define	MESH_GEN_ONPOWERUP_DEFAULT	0x01
#define	MESH_GEN_ONPOWERUP_RESTORE	0x02

/* OnOff state values (MshMDL_v1.1 Section 3.1.1). */
#define	MESH_GEN_OFF	0x00
#define	MESH_GEN_ON	0x01

/* Largest model message parameter block emitted here (Level Status = 5). */
#define	MESH_GEN_PARAMS_MAX	7

/* ================================================================
 * Message structures.
 * ================================================================ */

/* Generic OnOff Set / Set Unacknowledged (Section 3.2.1.2). */
struct mesh_gen_onoff_set {
	uint8_t		onoff;			/* 0 off, 1 on */
	uint8_t		tid;			/* transaction identifier */
	int		has_transition;		/* 1 => transition_time/delay present */
	uint8_t		transition_time;	/* Generic transition time octet */
	uint8_t		delay;			/* message execution delay, 5 ms units */
};

/* Generic OnOff Status (Section 3.2.1.4). */
struct mesh_gen_onoff_status {
	uint8_t		present;		/* Present OnOff */
	int		has_target;		/* 1 => target/remaining present */
	uint8_t		target;			/* Target OnOff */
	uint8_t		remaining;		/* Remaining Time octet */
};

/* Generic Level Set / Set Unacknowledged (Section 3.2.2.2). */
struct mesh_gen_level_set {
	int16_t		level;			/* Level (signed, little-endian) */
	uint8_t		tid;
	int		has_transition;
	uint8_t		transition_time;
	uint8_t		delay;
};

/* Generic Delta Set / Set Unacknowledged (Section 3.2.2.3). */
struct mesh_gen_delta_set {
	int32_t		delta;			/* Delta Level (signed 32-bit, LE) */
	uint8_t		tid;
	int		has_transition;
	uint8_t		transition_time;
	uint8_t		delay;
};

/* Generic Move Set / Set Unacknowledged (Section 3.2.2.5). */
struct mesh_gen_move_set {
	int16_t		delta;			/* Delta Level (signed 16-bit, LE) */
	uint8_t		tid;
	int		has_transition;
	uint8_t		transition_time;
	uint8_t		delay;
};

/* Generic Level Status (Section 3.2.2.8). */
struct mesh_gen_level_status {
	int16_t		present;		/* Present Level */
	int		has_target;
	int16_t		target;			/* Target Level */
	uint8_t		remaining;		/* Remaining Time octet */
};

/* ================================================================
 * Message parameter codecs (opcode PARAMETERS only, little-endian).
 * Each returns 0 on success, -1 on malformed/short/oversized input with
 * the decoded structure or *outlen left zeroed.
 * ================================================================ */

int	mesh_gen_onoff_set_encode(const struct mesh_gen_onoff_set *in,
	    uint8_t *out, size_t *outlen);
int	mesh_gen_onoff_set_decode(const uint8_t *in, size_t inlen,
	    struct mesh_gen_onoff_set *out);
int	mesh_gen_onoff_status_encode(const struct mesh_gen_onoff_status *in,
	    uint8_t *out, size_t *outlen);
int	mesh_gen_onoff_status_decode(const uint8_t *in, size_t inlen,
	    struct mesh_gen_onoff_status *out);

int	mesh_gen_level_set_encode(const struct mesh_gen_level_set *in,
	    uint8_t *out, size_t *outlen);
int	mesh_gen_level_set_decode(const uint8_t *in, size_t inlen,
	    struct mesh_gen_level_set *out);
int	mesh_gen_delta_set_encode(const struct mesh_gen_delta_set *in,
	    uint8_t *out, size_t *outlen);
int	mesh_gen_delta_set_decode(const uint8_t *in, size_t inlen,
	    struct mesh_gen_delta_set *out);
int	mesh_gen_move_set_encode(const struct mesh_gen_move_set *in,
	    uint8_t *out, size_t *outlen);
int	mesh_gen_move_set_decode(const uint8_t *in, size_t inlen,
	    struct mesh_gen_move_set *out);
int	mesh_gen_level_status_encode(const struct mesh_gen_level_status *in,
	    uint8_t *out, size_t *outlen);
int	mesh_gen_level_status_decode(const uint8_t *in, size_t inlen,
	    struct mesh_gen_level_status *out);

/* ================================================================
 * Server state and receive logic.
 * ================================================================ */

/*
 * Per-server transaction tracker (MshMDL_v1.1 Section 3.1: a message with the
 * same TID from the same source is a retransmission of the same transaction).
 * A transaction expires six seconds after its first message.
 */
struct mesh_gen_tid {
	int		valid;
	uint16_t	src;
	uint16_t	dst;
	uint8_t		tid;
	uint64_t	expires_ms;
};

struct mesh_gen_dtt_srv;

/* Generic OnOff Server state (Section 3.2.1). */
struct mesh_gen_onoff_srv {
	uint8_t			present;	/* Present OnOff (0/1) */
	struct mesh_gen_tid	txn;
	struct mesh_transition_state transition;
	const struct mesh_gen_dtt_srv *dtt;
	void			(*changed)(void *, uint8_t);
	void			*changed_arg;
	/*
	 * P-H4: internal upward state-binding hook (e.g. Generic OnOff ->
	 * Light Lightness Actual, MMDL 6.1.2.2.3).  Distinct from changed so an
	 * application notification callback is not clobbered by the binding.
	 */
	void			(*bound_sink)(void *, uint8_t);
	void			*bound_sink_arg;
};

/* Generic Level Server state (Section 3.2.2). */
struct mesh_gen_level_srv {
	int16_t			present;	/* Present Level */
	int16_t			txn_base;	/* Level at transaction start (Delta) */
	int32_t			last_delta;
	int			delta_valid;
	struct mesh_gen_tid	txn;
	struct mesh_transition_state transition;
	const struct mesh_gen_dtt_srv *dtt;
	void			(*changed)(void *, int16_t);
	void			*changed_arg;
	/*
	 * P-H4: internal upward state-binding hook (e.g. Generic Level ->
	 * Light Lightness/CTL Temperature/HSL, MMDL 6.1.2.2.2 and 6.1.3.1.1).
	 */
	void			(*bound_sink)(void *, int16_t);
	void			*bound_sink_arg;
};

struct mesh_gen_power_onoff_srv {
	uint8_t			 on_power_up;
	uint8_t			 last_onoff;
	struct mesh_gen_onoff_srv *bound_onoff;
};

struct mesh_gen_dtt_srv {
	uint8_t	transition_time;
};

struct mesh_gen_dtt_cli {
	int	have_status;
	uint8_t	transition_time;
};

struct mesh_gen_power_level_srv {
	uint16_t	actual;
	uint16_t	last;
	uint16_t	default_power;
	uint16_t	range_min;
	uint16_t	range_max;
	uint8_t		range_status;
	struct mesh_gen_tid txn;
	struct mesh_transition_state transition;
	const struct mesh_gen_dtt_srv *dtt;
	struct mesh_gen_onoff_srv *bound_onoff;
	struct mesh_gen_level_srv *bound_level;
	struct mesh_gen_power_onoff_srv *bound_power_onoff;
};

struct mesh_gen_power_level_cli {
	int		have_actual;
	int		have_last;
	int		have_default;
	int		have_range;
	uint16_t	actual;
	uint16_t	last;
	uint16_t	default_power;
	uint16_t	range_min;
	uint16_t	range_max;
	uint8_t		range_status;
};

struct mesh_gen_battery_status {
	uint8_t		level;
	uint32_t	discharge_minutes;
	uint32_t	charge_minutes;
	uint8_t		flags;
};

struct mesh_gen_battery_srv {
	struct mesh_gen_battery_status state;
};

struct mesh_gen_battery_cli {
	int have_status;
	struct mesh_gen_battery_status last;
};

struct mesh_gen_location_global {
	int32_t	latitude;
	int32_t	longitude;
	int16_t	altitude;
};

struct mesh_gen_location_local {
	int16_t	north;
	int16_t	east;
	int16_t	altitude;
	uint8_t	floor;
	uint16_t	uncertainty;
};

struct mesh_gen_location_srv {
	struct mesh_gen_location_global global;
	struct mesh_gen_location_local local;
};

struct mesh_gen_location_cli {
	int have_global;
	int have_local;
	struct mesh_gen_location_global global;
	struct mesh_gen_location_local local;
};

struct mesh_gen_power_onoff_cli {
	int		have_status;
	uint8_t		on_power_up;
};

void	mesh_gen_onoff_srv_init(struct mesh_gen_onoff_srv *srv, uint8_t present);
void	mesh_gen_onoff_srv_bind(struct mesh_gen_onoff_srv *srv,
	    void (*changed)(void *, uint8_t), void *arg);
void	mesh_gen_onoff_srv_set_present(struct mesh_gen_onoff_srv *srv,
	    uint8_t present);
void	mesh_gen_level_srv_init(struct mesh_gen_level_srv *srv, int16_t present);
void	mesh_gen_level_srv_bind(struct mesh_gen_level_srv *srv,
	    void (*changed)(void *, int16_t), void *arg);
void	mesh_gen_level_srv_set_present(struct mesh_gen_level_srv *srv,
	    int16_t present);
int	mesh_gen_transition_time_valid(uint8_t transition_time);
void	mesh_gen_dtt_srv_init(struct mesh_gen_dtt_srv *srv,
	    uint8_t transition_time);
int	mesh_gen_dtt_srv_recv(struct mesh_gen_dtt_srv *srv, uint32_t opcode,
	    const uint8_t *params, size_t plen, uint8_t *status,
	    int *want_status);
void	mesh_gen_power_level_srv_init(struct mesh_gen_power_level_srv *srv,
	    struct mesh_gen_onoff_srv *onoff, struct mesh_gen_level_srv *level,
	    struct mesh_gen_power_onoff_srv *power_onoff);
void	mesh_gen_power_level_set_actual(struct mesh_gen_power_level_srv *srv,
	    uint16_t actual);
void	mesh_gen_power_level_power_cycle(struct mesh_gen_power_level_srv *srv);
int	mesh_gen_battery_status_encode(const struct mesh_gen_battery_status *in,
	    uint8_t out[8]);
int	mesh_gen_battery_status_decode(const uint8_t *in, size_t inlen,
	    struct mesh_gen_battery_status *out);
void	mesh_gen_battery_srv_init(struct mesh_gen_battery_srv *srv);
int	mesh_gen_location_global_encode(const struct mesh_gen_location_global *in,
	    uint8_t out[10]);
int	mesh_gen_location_global_decode(const uint8_t *in, size_t inlen,
	    struct mesh_gen_location_global *out);
int	mesh_gen_location_local_encode(const struct mesh_gen_location_local *in,
	    uint8_t out[9]);
int	mesh_gen_location_local_decode(const uint8_t *in, size_t inlen,
	    struct mesh_gen_location_local *out);
void	mesh_gen_location_srv_init(struct mesh_gen_location_srv *srv);
int	mesh_gen_power_level_srv_recv(struct mesh_gen_power_level_srv *srv,
	    uint16_t src, uint32_t opcode, const uint8_t *params, size_t plen,
	    struct mesh_model_reply *reply);
int	mesh_gen_power_level_srv_recv_at(struct mesh_gen_power_level_srv *srv,
	    uint16_t src, uint32_t opcode, const uint8_t *params, size_t plen,
	    struct mesh_model_reply *reply, uint64_t now_ms);
int	mesh_gen_power_level_srv_recv_at_dst(struct mesh_gen_power_level_srv *srv,
	    uint16_t src, uint16_t dst, uint32_t opcode, const uint8_t *params,
	    size_t plen, struct mesh_model_reply *reply, uint64_t now_ms);
void	mesh_gen_power_onoff_srv_init(struct mesh_gen_power_onoff_srv *srv,
	    struct mesh_gen_onoff_srv *bound, uint8_t on_power_up);
void	mesh_gen_power_onoff_srv_power_cycle(struct mesh_gen_power_onoff_srv *srv);
int	mesh_gen_power_onoff_srv_recv(struct mesh_gen_power_onoff_srv *srv,
	    uint32_t opcode, const uint8_t *params, size_t plen, uint8_t *status,
	    int *want_status);

/*
 * Deliver one received Generic OnOff message to a server.  opcode is the
 * access opcode (GET/SET/SET_UNACK); params/plen are the opcode parameters.
 * On a GET or an acknowledged SET, *status is filled and *want_status set to
 * 1; a Set Unacknowledged leaves *want_status 0.  Returns 0 on success, -1 on
 * a malformed message or an opcode this server does not handle.
 */
int	mesh_gen_onoff_srv_recv(struct mesh_gen_onoff_srv *srv, uint16_t src,
	    uint32_t opcode, const uint8_t *params, size_t plen,
		    struct mesh_gen_onoff_status *status, int *want_status);
int	mesh_gen_onoff_srv_recv_at(struct mesh_gen_onoff_srv *srv, uint16_t src,
		    uint32_t opcode, const uint8_t *params, size_t plen,
		    struct mesh_gen_onoff_status *status, int *want_status,
		    uint64_t now_ms);
int	mesh_gen_onoff_srv_recv_at_dst(struct mesh_gen_onoff_srv *srv,
		    uint16_t src, uint16_t dst, uint32_t opcode,
		    const uint8_t *params, size_t plen,
		    struct mesh_gen_onoff_status *status, int *want_status,
		    uint64_t now_ms);

/*
 * Deliver one received Generic Level message (GET/SET/SET_UNACK/DELTA/MOVE
 * and their unacknowledged forms) to a server.  Same contract as above.
 */
int	mesh_gen_level_srv_recv(struct mesh_gen_level_srv *srv, uint16_t src,
	    uint32_t opcode, const uint8_t *params, size_t plen,
		    struct mesh_gen_level_status *status, int *want_status);
int	mesh_gen_level_srv_recv_at(struct mesh_gen_level_srv *srv, uint16_t src,
		    uint32_t opcode, const uint8_t *params, size_t plen,
		    struct mesh_gen_level_status *status, int *want_status,
		    uint64_t now_ms);
int	mesh_gen_level_srv_recv_at_dst(struct mesh_gen_level_srv *srv,
		    uint16_t src, uint16_t dst, uint32_t opcode,
		    const uint8_t *params, size_t plen,
		    struct mesh_gen_level_status *status, int *want_status,
		    uint64_t now_ms);

/* ================================================================
 * Access-layer dispatch integration (mesh_access model registry).
 *
 * The servers plug into mesh_access_dispatch() via an opcode table.  The
 * receive handler reads the server state from mesh_model.user and, when a
 * Status must be returned, records it in a struct mesh_model_reply passed as
 * the dispatch ctx.  The caller (e.g. mesh_sim) then transmits the recorded
 * reply from elem_addr back to the message source.
 * ================================================================ */

/*
 * Build a mesh_model referencing the given server instance (user pointer),
 * ready to place in a mesh_element's model list.  The opcode table is a
 * module-static constant shared by all instances of the model.
 */
struct mesh_model mesh_gen_onoff_srv_model(struct mesh_gen_onoff_srv *srv);
struct mesh_model mesh_gen_level_srv_model(struct mesh_gen_level_srv *srv);
struct mesh_model mesh_gen_dtt_srv_model(struct mesh_gen_dtt_srv *srv);
struct mesh_model mesh_gen_power_onoff_srv_model(
	    struct mesh_gen_power_onoff_srv *srv);
struct mesh_model mesh_gen_power_onoff_setup_srv_model(
	    struct mesh_gen_power_onoff_srv *srv);
struct mesh_model mesh_gen_power_level_srv_model(
	    struct mesh_gen_power_level_srv *srv);
struct mesh_model mesh_gen_power_level_setup_srv_model(
	    struct mesh_gen_power_level_srv *srv);
struct mesh_model mesh_gen_battery_srv_model(struct mesh_gen_battery_srv *srv);
struct mesh_model mesh_gen_location_srv_model(struct mesh_gen_location_srv *srv);
struct mesh_model mesh_gen_location_setup_srv_model(
	    struct mesh_gen_location_srv *srv);

/* ================================================================
 * Client state and helpers.
 * ================================================================ */

/* Generic OnOff Client (Section 3.2.1): records the last received Status. */
struct mesh_gen_onoff_cli {
	int				have_status;
	struct mesh_gen_onoff_status	last;
};

/* Generic Level Client (Section 3.2.2). */
struct mesh_gen_level_cli {
	int				have_status;
	struct mesh_gen_level_status	last;
};

void	mesh_gen_onoff_cli_init(struct mesh_gen_onoff_cli *cli);
void	mesh_gen_level_cli_init(struct mesh_gen_level_cli *cli);
void	mesh_gen_dtt_cli_init(struct mesh_gen_dtt_cli *cli);
void	mesh_gen_power_onoff_cli_init(struct mesh_gen_power_onoff_cli *cli);

/*
 * Client message builders: produce a complete Access PDU (opcode || params)
 * ready to hand to the transport layer.  For the Set builders ack selects the
 * acknowledged (0x8202/0x8206) vs unacknowledged (0x8203/0x8207) opcode.
 * Return 0 on success, -1 on failure with *outlen zeroed.
 */
int	mesh_gen_onoff_cli_get(uint8_t *out, size_t *outlen);
int	mesh_gen_onoff_cli_set(const struct mesh_gen_onoff_set *in, int ack,
	    uint8_t *out, size_t *outlen);
int	mesh_gen_level_cli_get(uint8_t *out, size_t *outlen);
int	mesh_gen_level_cli_set(const struct mesh_gen_level_set *in, int ack,
	    uint8_t *out, size_t *outlen);
int	mesh_gen_delta_cli_set(const struct mesh_gen_delta_set *in, int ack,
	    uint8_t *out, size_t *outlen);
int	mesh_gen_move_cli_set(const struct mesh_gen_move_set *in, int ack,
	    uint8_t *out, size_t *outlen);
int	mesh_gen_dtt_cli_get(uint8_t *out, size_t *outlen);
int	mesh_gen_dtt_cli_set(uint8_t transition_time, int ack, uint8_t *out,
	    size_t *outlen);
int	mesh_gen_dtt_cli_recv(struct mesh_gen_dtt_cli *cli, uint32_t opcode,
	    const uint8_t *params, size_t plen);
int	mesh_gen_power_onoff_cli_get(uint8_t *out, size_t *outlen);
int	mesh_gen_power_onoff_cli_set(uint8_t on_power_up, int ack, uint8_t *out,
	    size_t *outlen);
int	mesh_gen_power_onoff_cli_recv(struct mesh_gen_power_onoff_cli *cli,
	    uint32_t opcode, const uint8_t *params, size_t plen);
void	mesh_gen_power_level_cli_init(struct mesh_gen_power_level_cli *cli);
int	mesh_gen_power_level_cli_get(uint8_t *out, size_t *outlen);
int	mesh_gen_power_level_cli_set(uint16_t power, uint8_t tid, int ack,
	    uint8_t *out, size_t *outlen);
int	mesh_gen_power_last_cli_get(uint8_t *out, size_t *outlen);
int	mesh_gen_power_default_cli_get(uint8_t *out, size_t *outlen);
int	mesh_gen_power_default_cli_set(uint16_t power, int ack, uint8_t *out,
	    size_t *outlen);
int	mesh_gen_power_range_cli_get(uint8_t *out, size_t *outlen);
int	mesh_gen_power_range_cli_set(uint16_t min, uint16_t max, int ack,
	    uint8_t *out, size_t *outlen);
int	mesh_gen_power_level_cli_recv(struct mesh_gen_power_level_cli *cli,
	    uint32_t opcode, const uint8_t *params, size_t plen);
void	mesh_gen_battery_cli_init(struct mesh_gen_battery_cli *cli);
int	mesh_gen_battery_cli_get(uint8_t *out, size_t *outlen);
int	mesh_gen_battery_cli_recv(struct mesh_gen_battery_cli *cli,
	    uint32_t opcode, const uint8_t *params, size_t plen);
void	mesh_gen_location_cli_init(struct mesh_gen_location_cli *cli);
int	mesh_gen_location_cli_get(int global, uint8_t *out, size_t *outlen);
int	mesh_gen_location_cli_set_global(
	    const struct mesh_gen_location_global *in, int ack, uint8_t *out,
	    size_t *outlen);
int	mesh_gen_location_cli_set_local(
	    const struct mesh_gen_location_local *in, int ack, uint8_t *out,
	    size_t *outlen);
int	mesh_gen_location_cli_recv(struct mesh_gen_location_cli *cli,
	    uint32_t opcode, const uint8_t *params, size_t plen);

/*
 * Client receive: parse a Status Access PDU into the client's last-status
 * cache.  opcode must be the matching STATUS opcode.  Returns 0 on success,
 * -1 on an opcode/length mismatch.
 */
int	mesh_gen_onoff_cli_recv(struct mesh_gen_onoff_cli *cli, uint32_t opcode,
	    const uint8_t *params, size_t plen);
int	mesh_gen_level_cli_recv(struct mesh_gen_level_cli *cli, uint32_t opcode,
	    const uint8_t *params, size_t plen);

/* Model tables for a client instance (Status handler updates *cli). */
struct mesh_model mesh_gen_onoff_cli_model(struct mesh_gen_onoff_cli *cli);
struct mesh_model mesh_gen_level_cli_model(struct mesh_gen_level_cli *cli);

/*
 * Saturating signed 16-bit add used by Delta Set (Section 3.2.2.3): the
 * result is clamped to the [-32768, 32767] Level range.  Exposed for tests.
 */
int16_t	mesh_gen_level_sat_add(int32_t base, int32_t delta);

#endif /* _MESH_GENERIC_H_ */
