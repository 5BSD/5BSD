/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Internal declarations shared between SMP implementation files.
 * Not for inclusion by code outside of the SMP module.
 */

#ifndef _BLUED_SMP_INTERNAL_H_
#define _BLUED_SMP_INTERNAL_H_

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>		/* struct timespec (smp_now clock seam) */

#include "smp.h"

/*
 * ------------------------------------------------------------------
 * Test-only monotonic-clock seam (Core Spec Vol 3 Part H §3.4 timer).
 * ------------------------------------------------------------------
 * SMP reads a monotonic clock for the cumulative 30 s pairing timer and
 * for the pairing rate-limit window.  Production ALWAYS reads the real
 * CLOCK_MONOTONIC because smp_clock_hook is NULL; smp_now() then simply
 * forwards to clock_gettime(CLOCK_MONOTONIC).  A test may install a hook
 * to drive a deterministic virtual clock (advancing time with no real
 * sleeping) so the §3.4 timeout-abort and rate-limit-window paths can be
 * exercised in-tree.  The hook is inert unless a test explicitly sets it,
 * so production timing behaviour is bit-for-bit unchanged.
 */
typedef void (*smp_clock_hook_t)(struct timespec *now);
extern smp_clock_hook_t smp_clock_hook;		/* NULL => real clock */
void	smp_now(struct timespec *ts);

/*
 * ------------------------------------------------------------------
 * Test-only LE Secure Connections ephemeral-key seam (§2.3.5.6.1).
 * ------------------------------------------------------------------
 * Every SC flow generates a fresh random P-256 ephemeral key pair for
 * ECDH.  Production ALWAYS generates a new key here (forward secrecy)
 * because smp_sc_ephemeral_hook is NULL.  A test may install the hook to
 * inject a known key pair so that (a) a spec Appendix-D style flow is
 * deterministic and (b) an SC-OOB payload precomputed from the same
 * public key (via smp_generate_sc_oob) is tied to the ephemeral the
 * pairing actually uses.  The hook returns ownership of a newly created
 * EVP_PKEY (freed by the SMP code as usual); it is inert in production.
 */
struct evp_pkey_st;			/* OpenSSL EVP_PKEY, opaque here */
typedef struct evp_pkey_st *(*smp_sc_ephemeral_hook_t)(void);
extern smp_sc_ephemeral_hook_t smp_sc_ephemeral_hook;	/* NULL => keygen */

/* Test-only fault seam for otherwise non-deterministic legacy crypto-provider
 * failures.  NULL in production preserves the normal c1/s1 implementation. */
typedef int (*smp_legacy_crypto_hook_t)(const char *operation);
extern smp_legacy_crypto_hook_t smp_legacy_crypto_hook;

/* HCI LE_Start_Encryption opcode */
#define HCI_OP_LE_START_ENCRYPTION \
	NG_HCI_OPCODE(NG_HCI_OGF_LE, NG_HCI_OCF_LE_START_ENCRYPTION)

/* Association model */
#define SMP_MODEL_JUST_WORKS		0
#define SMP_MODEL_PASSKEY_ENTRY		1
#define SMP_MODEL_NUMERIC_COMPARISON	2
#define SMP_MODEL_OOB			3
#define SMP_MODEL_INVALID		(-1)

/* Core Vol 3, Part H, Section 2.2.6: f4 Z is 0x80 or 0x81 for a passkey bit. */
#define SMP_F4_PASSKEY_PREFIX		0x80u
#define SMP_F4_PASSKEY_Z(bit)		(SMP_F4_PASSKEY_PREFIX | ((bit) & 1u))

/*
 * Sentinel returned by the timeout-aware recv wrappers when the cumulative
 * §3.4 pairing timer expires: the link has already been force-disconnected
 * and NO SMP PDU may be sent, so callers must abort straight to cleanup
 * WITHOUT emitting a Pairing Failed.  Distinct from a short/other recv (>= -1).
 */
#define SMP_RECV_TIMED_OUT	((ssize_t)-2)

/* --- SMP PDU send/recv helpers (smp.c) --- */
ssize_t	smp_log_send(struct smp_conn *, const void *, size_t);
ssize_t	smp_log_recv(struct smp_conn *, void *, size_t);
bool	smp_record_is_truncated(int, int);
ssize_t	smp_recv_skip_keypress(struct smp_conn *, uint8_t *, size_t);
ssize_t	smp_recv_timed(struct smp_conn *, void *, size_t);
ssize_t	smp_recv_timed_kp(struct smp_conn *, uint8_t *, size_t);

/* --- SMP AuthReq / key-distribution policy (smp.c) --- */
void	smp_seed_policy_defaults(struct smp_conn *);
uint8_t	smp_build_authreq(const struct smp_conn *);

/* --- Utility (smp.c) --- */
int	smp_random(uint8_t *, size_t);
bool	smp_pairing_expired_at(const struct timespec *, const struct timespec *);
bool	smp_pairing_expired(const struct timespec *);
/*
 * Cumulative pairing timer (Core Spec Vol 3 Part H §3.4) helpers.
 * smp_pairing_arm() arms sc->pair_start once (idempotent); the five pairing
 * flows call it at entry so direct-call unit tests get an armed deadline.
 * smp_pairing_timed_out() returns true (and forces the HCI link down without
 * sending any PDU) once the deadline has passed.
 */
void	smp_pairing_arm(struct smp_conn *);
bool	smp_pairing_timed_out(struct smp_conn *);

/* --- Crypto (smp_crypto.c) --- */
int	smp_validate_public_key(const uint8_t *, const uint8_t *);

/* --- Key distribution and bond helpers (smp_keys.c) --- */
int	smp_distribute_init_keys(struct smp_conn *, const uint8_t *,
	    const uint8_t *, bool);
int	smp_receive_peer_keys(struct smp_conn *, struct smp_bond *, uint8_t,
	    bool);
int	smp_ensure_local_irk(struct smp_bond_db *);
int	smp_ensure_local_csrk(struct smp_bond_db *);
int	smp_local_irk_get(struct smp_bond_db *, uint8_t [16]);

/*
 * Test-only random-source seam for RPA generation.  Production leaves this
 * NULL and uses arc4random_buf(3).  A hook returns 0 after filling the buffer,
 * or -1 on entropy-source failure.
 */
typedef int (*smp_rpa_random_hook_t)(uint8_t *, size_t);
extern smp_rpa_random_hook_t smp_rpa_random_hook;

/* --- Legacy pairing (smp_legacy.c) --- */
int	smp_respond_legacy(struct smp_conn *, const uint8_t[7],
	    const uint8_t[7], const uint8_t[16]);

/* --- Secure Connections pairing (smp_sc.c) --- */
int	smp_pair_sc(struct smp_conn *, const uint8_t[7], const uint8_t[7],
	    int);
int	smp_pair_sc_passkey(struct smp_conn *, const uint8_t[7],
	    const uint8_t[7]);
int	smp_respond_sc(struct smp_conn *, const uint8_t[7],
	    const uint8_t[7], int);
int	smp_respond_sc_passkey(struct smp_conn *, const uint8_t[7],
	    const uint8_t[7]);
void	smp_pack_addr(uint8_t[7], const uint8_t[6], uint8_t);

#endif /* _BLUED_SMP_INTERNAL_H_ */
