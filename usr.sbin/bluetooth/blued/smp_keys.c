/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * SMP key distribution, bond database, CCCD persistence, and CTKD.
 *
 * Bond database at-rest encryption uses AES-256-GCM with a random per-file
 * salt (format version 4).
 */

#include <sys/types.h>
#include <sys/param.h>		/* nitems() */
#include <sys/endian.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <fcntl.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_l2cap.h>

#include "att.h"
#include "att_server.h"
#include "ble_util.h"
#include "blued_probes.h"
#include "config.h"
#include "hci_log.h"
#include "hci_util.h"
#include "smp.h"
#include "smp_internal.h"

smp_rpa_random_hook_t smp_rpa_random_hook = NULL;

#define SMP_RPA_RANDOM_ATTEMPTS 16

static int
smp_bond_db_flush(struct smp_bond_db *db)
{

	/* A DB without an atomic target is explicitly ephemeral (unit tests). */
	if (db->dir_fd < 0 || db->file_name[0] == '\0')
		return (0);
	return (smp_bond_db_save(db));
}

static bool
smp_bond_db_uncommitted(int rc)
{

	return (rc == -1);
}

/*
 * Ensure the bond database has a local IRK for identity distribution.
 * If one was previously persisted, it is already loaded; otherwise
 * generate a fresh 128-bit IRK via arc4random_buf and save immediately.
 *
 * All callers reference db->local_irk directly -- there is no file-scope
 * static copy, so the IRK cannot diverge from the bond database.
 */
int __attribute__((no_thread_safety_analysis))
smp_ensure_local_irk(struct smp_bond_db *db)
{

	if (db == NULL)
		return (-1);

	if (db->lock != NULL)
		pthread_mutex_lock(db->lock);
	if (!db->has_local_irk) {
		int rc;

		arc4random_buf(db->local_irk, 16);
		db->has_local_irk = true;
		rc = smp_bond_db_flush(db);
		if (rc != 0) {
			if (smp_bond_db_uncommitted(rc)) {
				explicit_bzero(db->local_irk, sizeof(db->local_irk));
				db->has_local_irk = false;
			}
			if (db->lock != NULL)
				pthread_mutex_unlock(db->lock);
			return (-1);
		}
		LOG_SMP(1, "generated local IRK for identity distribution");
	}
	if (db->lock != NULL)
		pthread_mutex_unlock(db->lock);
	return (0);
}

/*
 * Return the single persistent local identity key used both for SMP identity
 * distribution and controller-side RPA generation.  Keeping this copy seam
 * in the bond database prevents a daemon-global IRK from diverging from the
 * key peers were actually given.
 */
int __attribute__((no_thread_safety_analysis))
smp_local_irk_get(struct smp_bond_db *db, uint8_t out[16])
{

	if (db == NULL || out == NULL || smp_ensure_local_irk(db) != 0)
		return (-1);
	if (db->lock != NULL)
		pthread_mutex_lock(db->lock);
	memcpy(out, db->local_irk, 16);
	if (db->lock != NULL)
		pthread_mutex_unlock(db->lock);
	return (0);
}

int __attribute__((no_thread_safety_analysis))
smp_ensure_local_csrk(struct smp_bond_db *db)
{

	if (db == NULL)
		return (-1);
	if (db->lock != NULL)
		pthread_mutex_lock(db->lock);
	if (!db->has_local_csrk) {
		int rc;

		arc4random_buf(db->local_csrk, sizeof(db->local_csrk));
		db->has_local_csrk = true;
		rc = smp_bond_db_flush(db);
		if (rc != 0) {
			if (smp_bond_db_uncommitted(rc)) {
				explicit_bzero(db->local_csrk,
				    sizeof(db->local_csrk));
				db->has_local_csrk = false;
			}
			if (db->lock != NULL)
				pthread_mutex_unlock(db->lock);
			return (-1);
		}
	}
	if (db->lock != NULL)
		pthread_mutex_unlock(db->lock);
	return (0);
}

/*
 * Distribute initiator keys to the responder.
 * For SC, only IdKey applies (EncKey is ignored per spec).
 * For Legacy, both EncKey and IdKey may be distributed.
 */
int
smp_distribute_init_keys(struct smp_conn *sc, const uint8_t *preq,
    const uint8_t *pres, bool is_sc)
{
	uint8_t init_dist = preq[5] & pres[5];
	uint8_t kpdu[19];

	/*
	 * IdKey distribution requires the persistent local IRK, and the
	 * previously-used SignKey distribution requires the persistent local
	 * CSRK.  Once either bit has been negotiated, silently omitting its
	 * command sequence violates the key-distribution agreement (Core Spec
	 * Vol 3 Part H §3.6.1).  Fail before emitting any earlier EncKey PDU so
	 * the peer never observes a partial transaction.
	 */
	if (sc->bond_db == NULL &&
	    (init_dist & (SMP_KEY_DIST_ID_KEY |
	    SMP_KEY_DIST_LEGACY_SIGN_KEY)) != 0)
		goto fail;

	/* SC ignores EncKey distribution (LTK derived from DH key) */
	if (!is_sc && (init_dist & SMP_KEY_DIST_ENC_KEY)) {
		uint8_t our_ltk[16];
		uint64_t our_rand;
		uint16_t our_ediv;

		arc4random_buf(our_ltk, 16);
		/*
		 * Mask the LTK to the negotiated key size before it is
		 * distributed (Vol 3 Part H §2.3.4).
		 */
		smp_mask_key(our_ltk, sc->neg_key_size);
		arc4random_buf(&our_rand, sizeof(our_rand));
		arc4random_buf(&our_ediv, sizeof(our_ediv));

		kpdu[0] = SMP_ENCRYPTION_INFORMATION;
		memcpy(kpdu + 1, our_ltk, 16);
		if (smp_log_send(sc, kpdu, 17) != 17) {
			explicit_bzero(our_ltk, sizeof(our_ltk));
			goto fail;
		}
		BLUED_PROBE_SMP_KEY_DIST(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
		    SMP_ENCRYPTION_INFORMATION);

		kpdu[0] = SMP_CENTRAL_IDENTIFICATION;
		put_le16(kpdu + 1, our_ediv);
		memcpy(kpdu + 3, &our_rand, 8);
		if (smp_log_send(sc, kpdu, 11) != 11) {
			explicit_bzero(our_ltk, sizeof(our_ltk));
			goto fail;
		}
		BLUED_PROBE_SMP_KEY_DIST(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
		    SMP_CENTRAL_IDENTIFICATION);

		explicit_bzero(our_ltk, sizeof(our_ltk));
	}

	if ((init_dist & SMP_KEY_DIST_ID_KEY) && sc->bond_db != NULL) {
		/*
		 * Guard on bond_db != NULL like the sibling SignKey branch:
		 * with no bond DB there is no local IRK to distribute, and the
		 * local_irk deref below would fault (K-low ID-key NULL deref).
		 */
		if (smp_ensure_local_irk(sc->bond_db) != 0) {
			LOG_SMP(1, "cannot persist local IRK; not distributing it");
			goto fail;
		}

		kpdu[0] = SMP_IDENTITY_INFORMATION;
		memcpy(kpdu + 1, sc->bond_db->local_irk, 16);
		if (smp_log_send(sc, kpdu, 17) != 17)
			goto fail;
		BLUED_PROBE_SMP_KEY_DIST(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
		    SMP_IDENTITY_INFORMATION);

		kpdu[0] = SMP_IDENTITY_ADDRESS_INFO;
		/*
		 * Map the internal BDADDR_LE_* type to the SMP wire AddrType
		 * octet: Core Spec Vol 3 Part H §3.6.5 defines 0x00 = public,
		 * 0x01 = static random.  The internal enum (BDADDR_LE_PUBLIC=1,
		 * BDADDR_LE_RANDOM=2) is NOT the wire encoding, so sending it
		 * raw mislabels the distributed identity address (matching the
		 * responder path in smp_legacy.c).
		 */
		kpdu[1] = (sc->local_addr_type == BDADDR_LE_RANDOM) ?
		    SMP_ID_ADDR_STATIC_RANDOM : SMP_ID_ADDR_PUBLIC;
		memcpy(kpdu + 2, sc->local_addr, 6);
		if (smp_log_send(sc, kpdu, 8) != 8)
			goto fail;
		BLUED_PROBE_SMP_KEY_DIST(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
		    SMP_IDENTITY_ADDRESS_INFO);
	}

	if (init_dist & SMP_KEY_DIST_LEGACY_SIGN_KEY) {
		if (smp_ensure_local_csrk(sc->bond_db) != 0) {
			LOG_SMP(1, "cannot persist local CSRK; not distributing it");
			goto fail;
		}
		kpdu[0] = SMP_LEGACY_SIGNING_INFORMATION;
		memcpy(kpdu + 1, sc->bond_db->local_csrk, 16);
		if (smp_log_send(sc, kpdu, 17) != 17)
			goto fail;
		BLUED_PROBE_SMP_KEY_DIST(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
		    SMP_LEGACY_SIGNING_INFORMATION);
		LOG_SMP(1, "distributed local CSRK");

	}

	explicit_bzero(kpdu, sizeof(kpdu));
	return (0);

fail:
	explicit_bzero(kpdu, sizeof(kpdu));
	return (-1);
}

/*
 * Receive and store the peer's distributed keys.
 *
 * Reads `expected` key-distribution PDUs (the caller computes `expected`
 * from the negotiated key-distribution mask) and parses Identity
 * Information, Identity Address Information, and Signing Information into
 * `bond`.  This is the receive-side counterpart to
 * smp_distribute_init_keys() and is shared by all five pairing flows
 * (legacy responder plus the SC initiator/responder/passkey paths) so the
 * length/bounds checks and the address-type mapping cannot drift between
 * copies.  The receive timeout is applied once, before the loop.
 */
int
smp_receive_peer_keys(struct smp_conn *sc, struct smp_bond *bond,
    uint8_t key_dist, bool is_sc)
{
	struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
	struct smp_bond pending;
	uint8_t pdu[66];
	uint8_t expected[5];
	ssize_t n;
	int count, i;
	bool received_irk, received_id_addr, received_csrk;

	if (setsockopt(sc->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		return (-1);
	pending = *bond;
	received_irk = false;
	received_id_addr = false;
	received_csrk = false;
	count = 0;
	if (!is_sc && (key_dist & SMP_KEY_DIST_ENC_KEY)) {
		expected[count++] = SMP_ENCRYPTION_INFORMATION;
		expected[count++] = SMP_CENTRAL_IDENTIFICATION;
	}
	if (key_dist & SMP_KEY_DIST_ID_KEY) {
		expected[count++] = SMP_IDENTITY_INFORMATION;
		expected[count++] = SMP_IDENTITY_ADDRESS_INFO;
	}
	if (key_dist & SMP_KEY_DIST_LEGACY_SIGN_KEY)
		expected[count++] = SMP_LEGACY_SIGNING_INFORMATION;

	for (i = 0; i < count; i++) {
		n = smp_log_recv(sc, pdu, sizeof(pdu));
		if (n < 1 || pdu[0] != expected[i])
			goto fail;
		if (pdu[0] == SMP_ENCRYPTION_INFORMATION && n == 17) {
			memcpy(pending.ltk, pdu + 1, 16);
			pending.has_ltk = true;
		} else if (pdu[0] == SMP_CENTRAL_IDENTIFICATION && n == 11) {
			pending.ediv = get_le16(pdu + 1);
			memcpy(&pending.rand, pdu + 3, 8);
		} else if (pdu[0] == SMP_IDENTITY_INFORMATION && n == 17) {
			memcpy(pending.irk, pdu + 1, 16);
			pending.has_irk = true;
			received_irk = true;
		} else if (pdu[0] == SMP_IDENTITY_ADDRESS_INFO && n == 8 &&
		    pdu[1] <= SMP_ID_ADDR_STATIC_RANDOM) {
			pending.addr_type = (pdu[1] == SMP_ID_ADDR_STATIC_RANDOM) ?
			    BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
			memcpy(pending.addr, pdu + 2, 6);
			received_id_addr = true;
		} else if (pdu[0] == SMP_LEGACY_SIGNING_INFORMATION && n == 17) {
			memcpy(pending.csrk, pdu + 1, 16);
			pending.has_csrk = true;
			received_csrk = true;
		} else
			goto fail;
	}
	*bond = pending;
	explicit_bzero(&pending, sizeof(pending));
	if (received_irk)
		BLUED_PROBE_SMP_KEY_RECV(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
		    SMP_IDENTITY_INFORMATION);
	if (received_id_addr)
		BLUED_PROBE_SMP_KEY_RECV(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
		    SMP_IDENTITY_ADDRESS_INFO);
	if (received_csrk) {
		BLUED_PROBE_SMP_KEY_RECV(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
		    SMP_LEGACY_SIGNING_INFORMATION);
		LOG_SMP(1, "stored peer CSRK");
	}
	return (0);

fail:
	explicit_bzero(&pending, sizeof(pending));
	return (-1);
}

/*
 * Copy only the distributed key material, and the crypto attributes that
 * describe it, from src into dst -- leaving dst's peer metadata (name, GATT
 * handle cache, CCCD subscriptions, sign counter, DB hash) untouched.  This is
 * the in-place bond update shared by a normal re-pair and an operator-driven
 * key refresh (Core Spec Vol 3 Part H §2.4): the fresh LTK/IRK/CSRK overwrite
 * the old ones in place, so the previous keys do not linger, while the peer
 * record survives so no rediscovery storm is forced on the next connect.
 */
static void
smp_bond_copy_keys(struct smp_bond *dst, const struct smp_bond *src)
{

	memcpy(dst->ltk, src->ltk, sizeof(dst->ltk));
	dst->rand = src->rand;
	dst->ediv = src->ediv;
	dst->has_ltk = src->has_ltk;
	memcpy(dst->irk, src->irk, sizeof(dst->irk));
	dst->has_irk = src->has_irk;
	memcpy(dst->csrk, src->csrk, sizeof(dst->csrk));
	dst->has_csrk = src->has_csrk;
	memcpy(dst->link_key, src->link_key, sizeof(dst->link_key));
	dst->has_link_key = src->has_link_key;
	dst->is_sc = src->is_sc;
	dst->is_mitm = src->is_mitm;
	dst->key_size = src->key_size;
}

/*
 * Store or update a bond in the database.
 * If a bond for this device already exists, refresh its key material in place
 * (preserving peer metadata via smp_bond_copy_keys).  Otherwise append a new
 * entry.
 */
int __attribute__((no_thread_safety_analysis))
smp_bond_db_store(struct smp_bond_db *db, const struct smp_bond *bond)
{
	struct smp_bond old;
	int i, rc;
	bool evicted = false;

	if (db == NULL || bond == NULL)
		return (-1);

	if (db->lock != NULL)
		pthread_mutex_lock(db->lock);

	/* Update existing bond for this device if present */
	for (i = 0; i < db->count; i++) {
		if (db->bonds[i].addr_type == bond->addr_type &&
		    memcmp(db->bonds[i].addr, bond->addr, 6) == 0) {
			old = db->bonds[i];
			smp_bond_copy_keys(&db->bonds[i], bond);
			rc = smp_bond_db_flush(db);
			if (rc != 0) {
				if (smp_bond_db_uncommitted(rc))
					db->bonds[i] = old;
				if (db->lock != NULL)
					pthread_mutex_unlock(db->lock);
				return (-1);
			}
			if (db->lock != NULL)
				pthread_mutex_unlock(db->lock);
			return (0);
		}
	}

	/* Append new bond, evicting the oldest if full */
	if (db->count < SMP_MAX_BONDS) {
		db->bonds[db->count++] = *bond;
	} else {
		/*
		 * Database full — evict the first (oldest) entry by
		 * shifting the array down, then store the new bond at
		 * the end.  This provides simple LRU/FIFO eviction.
		 */
		LOG_SMP(1, "bond database full (%d), evicting oldest bond",
		    SMP_MAX_BONDS);
		BLUED_LOG_SECURITY("bond eviction: db full (%d), "
		    "evicting addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "for new addr=%02x:%02x:%02x:%02x:%02x:%02x",
		    SMP_MAX_BONDS,
		    db->bonds[0].addr[5], db->bonds[0].addr[4],
		    db->bonds[0].addr[3], db->bonds[0].addr[2],
		    db->bonds[0].addr[1], db->bonds[0].addr[0],
		    bond->addr[5], bond->addr[4],
		    bond->addr[3], bond->addr[2],
		    bond->addr[1], bond->addr[0]);
		old = db->bonds[0];
		evicted = true;
		memmove(&db->bonds[0], &db->bonds[1],
		    (SMP_MAX_BONDS - 1) * sizeof(db->bonds[0]));
		/* Zero the last slot before writing new bond —
		 * scrubs the stale copy left by memmove */
		explicit_bzero(&db->bonds[SMP_MAX_BONDS - 1],
		    sizeof(db->bonds[0]));
		db->bonds[SMP_MAX_BONDS - 1] = *bond;
	}
	rc = smp_bond_db_flush(db);
	if (rc != 0) {
		if (smp_bond_db_uncommitted(rc) && !evicted) {
			db->count--;
			explicit_bzero(&db->bonds[db->count],
			    sizeof(db->bonds[0]));
		} else if (smp_bond_db_uncommitted(rc)) {
			memmove(&db->bonds[1], &db->bonds[0],
			    (SMP_MAX_BONDS - 1) * sizeof(db->bonds[0]));
			db->bonds[0] = old;
		}
		if (db->lock != NULL)
			pthread_mutex_unlock(db->lock);
		return (-1);
	}

	/* Probe fires after the bond is committed */
	{
		char a[18];
		bdaddr_t tmp;
		memcpy(&tmp, bond->addr, sizeof(tmp));
		bt_ntoa(&tmp, a);
		BLUED_PROBE_BOND_ADD(a, bond->is_sc);
	}
	if (db->lock != NULL)
		pthread_mutex_unlock(db->lock);
	return (0);
}

int __attribute__((no_thread_safety_analysis))
smp_bond_db_commit_bond(struct smp_bond_db *db, struct smp_bond *bond,
    const struct smp_bond *previous)
{

	if (db == NULL || bond == NULL || previous == NULL ||
	    bond < &db->bonds[0] || bond >= &db->bonds[db->count])
		return (-1);
	int rc;

	rc = smp_bond_db_flush(db);
	if (rc == 0)
		return (0);
	if (smp_bond_db_uncommitted(rc))
		*bond = *previous;
	return (-1);
}

/*
 * Replace only the key material of an already-stored bond (BLE key refresh,
 * Core Spec Vol 3 Part H §2.4).  Matches the peer by identity address and
 * swaps LTK/IRK/CSRK (and the crypto attributes describing them) while
 * preserving the rest of the record.  Replace-on-success only: this runs from
 * a completed re-pair, so a failed re-pair never reaches here and leaves the
 * old bond intact -- there is never a window with no keys.
 *
 * Returns 0 if an existing bond was refreshed, -1 if no bond matched the
 * identity address (the caller should treat that as a first pairing).
 */
int __attribute__((no_thread_safety_analysis))
smp_bond_db_replace_keys(struct smp_bond_db *db, const struct smp_bond *bond)
{
	int i, rc = -1;

	if (db == NULL || bond == NULL)
		return (-1);

	if (db->lock != NULL)
		pthread_mutex_lock(db->lock);

	for (i = 0; i < db->count; i++) {
		if (db->bonds[i].addr_type == bond->addr_type &&
		    memcmp(db->bonds[i].addr, bond->addr, 6) == 0) {
			struct smp_bond old = db->bonds[i];
			smp_bond_copy_keys(&db->bonds[i], bond);
			rc = smp_bond_db_commit_bond(db, &db->bonds[i], &old);
			break;
		}
	}

	if (db->lock != NULL)
		pthread_mutex_unlock(db->lock);
	return (rc);
}

/*
 * Serialize one bond into a portable export record (PC4).
 *
 * Layout (little-endian, self-describing):
 *   "BREC"        magic (4)
 *   uint32_t      version (SMP_BOND_REC_VERSION)
 *   uint32_t      struct_size (sizeof(struct smp_bond))
 *   struct smp_bond  raw bond bytes
 *
 * The raw struct layout matches what the bond DB persists on disk, so the same
 * field set (LTK/rand/EDIV, IRK, CSRK, sign counter, is_sc/is_mitm/key_size,
 * name, GATT handle cache, CCCDs) round-trips without a second encoder.  The
 * struct_size lets the importer reject a record built against a different
 * struct before it reads any field.  Returns SMP_BOND_REC_LEN on success or 0
 * if the buffer is too small (no partial write).
 */
size_t
smp_bond_export_record(const struct smp_bond *bond, uint8_t *out, size_t outsz)
{
	uint32_t v;
	uint8_t *p = out;

	if (bond == NULL || out == NULL || outsz < SMP_BOND_REC_LEN)
		return (0);

	memcpy(p, SMP_BOND_REC_MAGIC, SMP_BOND_REC_MAGIC_LEN);
	p += SMP_BOND_REC_MAGIC_LEN;

	v = htole32(SMP_BOND_REC_VERSION);
	memcpy(p, &v, 4);
	p += 4;

	v = htole32((uint32_t)sizeof(struct smp_bond));
	memcpy(p, &v, 4);
	p += 4;

	memcpy(p, bond, sizeof(struct smp_bond));
	return (SMP_BOND_REC_LEN);
}

/*
 * Parse and validate an export record (PC4).  Hostile-input hardened: the
 * length is gated to exactly SMP_BOND_REC_LEN before any struct byte is read
 * (so a truncated or oversized record cannot cause an over-read), the magic and
 * version are checked, and the embedded struct_size must equal the running
 * sizeof(struct smp_bond) -- there is no lenient short-copy migration on import.
 * Every semantic field is then range-checked; a boolean flag byte outside {0,1}
 * or an out-of-range count is treated as corruption and rejected.  Returns 0
 * with *out filled on success, -1 on any failure (caller discards *out).
 */
int
smp_bond_import_record(const uint8_t *rec, size_t len, struct smp_bond *out)
{
	struct smp_bond b;
	uint32_t version, struct_size;

	if (rec == NULL || out == NULL)
		return (-1);

	/* Length gate first: exact match, no over-read past the record. */
	if (len != SMP_BOND_REC_LEN)
		return (-1);
	if (memcmp(rec, SMP_BOND_REC_MAGIC, SMP_BOND_REC_MAGIC_LEN) != 0)
		return (-1);

	memcpy(&version, rec + SMP_BOND_REC_MAGIC_LEN, 4);
	version = le32toh(version);
	if (version != SMP_BOND_REC_VERSION)
		return (-1);

	memcpy(&struct_size, rec + SMP_BOND_REC_MAGIC_LEN + 4, 4);
	struct_size = le32toh(struct_size);
	if (struct_size != (uint32_t)sizeof(struct smp_bond))
		return (-1);

	/*
	 * Validate the boolean flag bytes against the RAW record before the copy:
	 * a C bool normalizes any nonzero byte to 1 on read, so a corrupt 0x02
	 * would be silently laundered if read through the struct.  Inspect the
	 * on-record bytes at each flag's offset so a value outside {0,1} is caught.
	 */
	{
		const uint8_t *raw = rec + SMP_BOND_REC_HDR;
		static const size_t bool_off[] = {
			offsetof(struct smp_bond, has_ltk),
			offsetof(struct smp_bond, has_irk),
			offsetof(struct smp_bond, has_csrk),
			offsetof(struct smp_bond, has_link_key),
			offsetof(struct smp_bond, is_sc),
			offsetof(struct smp_bond, is_mitm),
			offsetof(struct smp_bond, has_name),
			offsetof(struct smp_bond, has_db_hash),
			offsetof(struct smp_bond, has_handle_cache),
		};
		size_t i;

		for (i = 0; i < nitems(bool_off); i++)
			if (raw[bool_off[i]] > 1)
				return (-1);
	}

	memcpy(&b, rec + SMP_BOND_REC_HDR, sizeof(b));

	/* Field validation. */
	if (b.addr_type != BDADDR_LE_PUBLIC && b.addr_type != BDADDR_LE_RANDOM)
		goto reject;
	/* Encryption key size: 0 (unknown) or a legal 7..16 octets (§2.3.4). */
	if (b.key_size != 0 && (b.key_size < 7 || b.key_size > 16))
		goto reject;
	if (b.num_cccds > SMP_MAX_CCCDS)
		goto reject;
	if (b.num_reports < 0 || b.num_reports > 16)
		goto reject;
	/* Force NUL-termination so the name can never over-read on use. */
	b.name[sizeof(b.name) - 1] = '\0';

	*out = b;
	explicit_bzero(&b, sizeof(b));
	return (0);

reject:
	explicit_bzero(&b, sizeof(b));
	return (-1);
}

/*
 * Insert an already-validated bond into the database, matched by identity
 * address+type (PC4 restore).  Replace-on-success only: an existing identity is
 * overwritten with a single struct assignment (no delete window, no partial
 * record), otherwise the bond is appended.  A full DB is rejected rather than
 * evicted so a restore cannot silently discard another peer's keys.  Persists
 * on success.  The caller must hold the bond-DB lock; this does not lock (it
 * runs under the ctl dispatcher's held lock, and locking db->lock -- the same
 * mutex -- would deadlock).  Returns 0 (replaced), 1 (appended), -1 (full).
 */
int __attribute__((no_thread_safety_analysis))
smp_bond_db_import(struct smp_bond_db *db, const struct smp_bond *bond)
{
	int i, rc;

	if (db == NULL || bond == NULL)
		return (-1);

	for (i = 0; i < db->count; i++) {
		if (db->bonds[i].addr_type == bond->addr_type &&
		    memcmp(db->bonds[i].addr, bond->addr, 6) == 0) {
			struct smp_bond old = db->bonds[i];
			db->bonds[i] = *bond;	/* atomic full-record replace */
			if (smp_bond_db_commit_bond(db, &db->bonds[i], &old) != 0)
				return (-2);
			return (0);
		}
	}

	if (db->count >= SMP_MAX_BONDS)
		return (-1);		/* capacity: restore must not evict */

	db->bonds[db->count++] = *bond;
	rc = smp_bond_db_flush(db);
	if (rc != 0) {
		if (smp_bond_db_uncommitted(rc)) {
			db->count--;
			explicit_bzero(&db->bonds[db->count],
			    sizeof(db->bonds[0]));
		}
		return (-2);
	}
	return (1);
}

/*
 * Persist an advanced Signed-Write replay counter into the matching bond
 * record (Core Spec Vol 3 Part H §2.4.5 / erratum 26047).
 *
 * The ATT server verifies a signed write and advances an in-session counter,
 * but without writing it back the accepted value is lost on disconnect and
 * the replay window resets to the stale stored counter on the next
 * connection.  This is called after each accepted signed write, keyed by the
 * peer CSRK the ATT layer already holds (ac->peer_csrk), because the ATT
 * connection does not carry the peer identity address.  The bond is matched
 * on that CSRK under the bond-DB lock, updated only when the counter is
 * strictly newer (monotonic), and the DB is then persisted.
 */
int __attribute__((no_thread_safety_analysis))
smp_bond_persist_sign_counter(struct smp_bond_db *db, const uint8_t csrk[16],
    uint32_t counter)
{
	int i;

	if (db == NULL || csrk == NULL)
		return (-1);

	if (db->lock != NULL)
		pthread_mutex_lock(db->lock);

	for (i = 0; i < db->count; i++) {
		if (!db->bonds[i].has_csrk)
			continue;
		if (timingsafe_bcmp(db->bonds[i].csrk, csrk, 16) != 0)
			continue;
		if (counter > db->bonds[i].peer_sign_counter) {
			uint32_t old = db->bonds[i].peer_sign_counter;
			int rc;
			db->bonds[i].peer_sign_counter = counter;
			rc = smp_bond_db_flush(db);
			if (rc != 0) {
				if (smp_bond_db_uncommitted(rc))
					db->bonds[i].peer_sign_counter = old;
				if (db->lock != NULL)
					pthread_mutex_unlock(db->lock);
				return (-1);
			}
		}
		break;
	}

	if (db->lock != NULL)
		pthread_mutex_unlock(db->lock);
	return (0);
}

/*
 * Find a bond by device address.
 *
 * First tries exact address match.  If the address is a Resolvable
 * Private Address (RPA) and no exact match is found, resolves against
 * each stored IRK per Core Spec Vol 3 Part H Section 2.2.2.
 */
struct smp_bond *
smp_find_bond(struct smp_bond_db *db, const uint8_t *addr, uint8_t addr_type)
{
	int i;

	/* Exact match first */
	for (i = 0; i < db->count; i++) {
		if (db->bonds[i].addr_type == addr_type &&
		    memcmp(db->bonds[i].addr, addr, 6) == 0) {
			LOG_SMP(1, "bond found (exact match)");
			return (&db->bonds[i]);
		}
	}

	/* Try IRK-based RPA resolution for random addresses */
	if (addr_type == BDADDR_LE_RANDOM) {
		for (i = 0; i < db->count; i++) {
			if (db->bonds[i].has_irk &&
			    smp_rpa_matches(db->bonds[i].irk, addr)) {
				LOG_SMP(1, "bond found (IRK resolved)");
				return (&db->bonds[i]);
			}
		}
	}

	return (NULL);
}

/*
 * Resolve a Resolvable Private Address (RPA) against an IRK.
 *
 * An RPA is a random address where the upper 2 bits of the MSB are 01.
 * Format: [prand(3) || hash(3)], total 6 bytes.
 * hash = ah(IRK, prand) = E(IRK, padding(13) || prand(3))[0..2]
 *
 * Core Spec Vol 3 Part H Section 2.2.2
 */
bool
smp_rpa_matches(const uint8_t irk[16], const uint8_t addr[6])
{
	uint8_t prand[3], hash_expected[3];
	uint8_t plaintext[16], cipher[16];

	/* RPA: addr[5] has upper 2 bits = 01 */
	if ((addr[5] & SMP_RANDOM_ADDRESS_TYPE_MASK) !=
	    SMP_RANDOM_ADDRESS_RESOLVABLE)
		return (false);

	/* prand is the upper 3 bytes (addr[3..5]) */
	prand[0] = addr[3];
	prand[1] = addr[4];
	prand[2] = addr[5];

	/* hash is the lower 3 bytes (addr[0..2]) */
	hash_expected[0] = addr[0];
	hash_expected[1] = addr[1];
	hash_expected[2] = addr[2];

	/*
	 * ah(k, r) = E(k, r') mod 2^24, where r' = padding || prand.
	 * "The least significant octet of r becomes the least significant
	 * octet of r'."  smp_aes128 expects LE input (byte[0]=LSB), so
	 * prand goes at bytes [0..2] and padding at bytes [3..15].
	 */
	memset(plaintext, 0, sizeof(plaintext));
	plaintext[0] = prand[0];
	plaintext[1] = prand[1];
	plaintext[2] = prand[2];

	if (smp_aes128(irk, plaintext, cipher) < 0)
		return (false);

	return (timingsafe_bcmp(cipher, hash_expected, 3) == 0);
}

/*
 * Generate a Resolvable Private Address (RPA) from an IRK.
 *
 * Core Spec Vol 3 Part H Section 2.2.2:
 *   prand = random 24-bit value with upper 2 bits = 01
 *   hash = ah(IRK, prand) = E(IRK, padding || prand)[0..2]
 *   RPA = hash(3) || prand(3)
 *
 * Returns 0 on success, or -1 if entropy generation is unavailable, no valid
 * prand is produced within the bounded retry count, or the underlying AES
 * primitive fails.  On failure the caller-supplied rpa buffer is untouched.
 */
int
smp_generate_rpa(const uint8_t irk[16], uint8_t rpa[6])
{
	uint8_t prand[3], plaintext[16], cipher[16];
	unsigned int attempts;

	/*
	 * Vol 6 Part B Section 1.3.2.2 requires the 22-bit random part of
	 * prand to contain at least one zero and at least one one.  Bound the
	 * retry loop so a broken injected entropy source cannot spin forever.
	 */
	for (attempts = 0; attempts < SMP_RPA_RANDOM_ATTEMPTS; attempts++) {
		if (smp_rpa_random_hook != NULL) {
			if (smp_rpa_random_hook(prand, sizeof(prand)) != 0)
				return (-1);
		} else
			arc4random_buf(prand, sizeof(prand));

		if (prand[0] == 0x00 && prand[1] == 0x00 &&
		    (prand[2] & SMP_RANDOM_ADDRESS_RANDOM_MASK) == 0x00)
			continue;
		if (prand[0] == 0xff && prand[1] == 0xff &&
		    (prand[2] & SMP_RANDOM_ADDRESS_RANDOM_MASK) ==
		    SMP_RANDOM_ADDRESS_RANDOM_MASK)
			continue;
		break;
	}
	if (attempts == SMP_RPA_RANDOM_ATTEMPTS) {
		errno = EAGAIN;
		return (-1);
	}

	/* Mark the validated random value as a resolvable private address. */
	prand[2] = (prand[2] & SMP_RANDOM_ADDRESS_RANDOM_MASK) |
	    SMP_RANDOM_ADDRESS_RESOLVABLE;

	/* ah(IRK, prand) */
	memset(plaintext, 0, sizeof(plaintext));
	plaintext[0] = prand[0];
	plaintext[1] = prand[1];
	plaintext[2] = prand[2];

	if (smp_aes128(irk, plaintext, cipher) < 0) {
		/*
		 * Do NOT emit an all-zero (predictable) RPA.  Signal the
		 * failure and leave rpa untouched so the caller aborts.
		 */
		warnx("smp_generate_rpa: ah() failed");
		return (-1);
	}

	/* RPA = hash[0..2] || prand[0..2] */
	rpa[0] = cipher[0];
	rpa[1] = cipher[1];
	rpa[2] = cipher[2];
	rpa[3] = prand[0];
	rpa[4] = prand[1];
	rpa[5] = prand[2];
	return (0);
}

/*
 * Cross-Transport Key Derivation: LE LTK -> BR/EDR Link Key.
 * Core Spec Vol 3 Part H Section 2.4.2.4
 *
 * Only valid for LE Secure Connections LTKs (not legacy).
 *
 * CT2 = 1 path (uses h7):
 *   ILK = h7(SALT_CT2, LTK)
 *   Link Key = h6(ILK, "lebr")
 *
 * Returns 0 on success, -1 if bond is not SC.
 */
int
smp_ctkd_derive_link_key(struct smp_bond *bond, bool ct2)
{
	/* SALT for CT2 = 1 path (Core Spec Vol 3 Part H Section 2.4.2.4) */
	static const uint8_t salt_ct2[16] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x74, 0x6D, 0x70, 0x31
	};
	/* keyID "lebr" in big-endian: 0x6C656272 */
	static const uint8_t keyid_lebr[4] = { 0x6C, 0x65, 0x62, 0x72 };
	/* keyID "tmp1" in big-endian: 0x746D7031 (CT2=0 path) */
	static const uint8_t keyid_tmp1[4] = { 0x74, 0x6D, 0x70, 0x31 };
	uint8_t ilk[16];

	if (!bond->is_sc || !bond->has_ltk)
		return (-1);

	/*
	 * Per Core Spec Vol 3 Part H Section 2.4.2.4, CTKD shall only
	 * derive a BR/EDR Link Key when the LE link was authenticated
	 * using an association model providing MITM protection (Passkey
	 * Entry, Numeric Comparison, or OOB).  Just Works does not
	 * provide MITM protection and must not produce a cross-transport
	 * key, as the unauthenticated key would be silently trusted on
	 * BR/EDR.
	 */
	if (!bond->is_mitm) {
		LOG_SMP(1, "CTKD: skipping — pairing was not MITM-protected");
		return (0);
	}

	if (ct2) {
		/* Both sides support CT2: use h7(SALT, LTK) */
		if (smp_h7(salt_ct2, bond->ltk, ilk) != 0) {
			explicit_bzero(ilk, sizeof(ilk));
			LOG_SMP(1, "CTKD: h7 failed, no link key derived");
			return (-1);
		}
	} else {
		/* At least one side lacks CT2: use h6(LTK, "tmp1") */
		if (smp_h6(bond->ltk, keyid_tmp1, ilk) != 0) {
			explicit_bzero(ilk, sizeof(ilk));
			LOG_SMP(1, "CTKD: h6 failed, no link key derived");
			return (-1);
		}
	}
	if (smp_h6(ilk, keyid_lebr, bond->link_key) != 0) {
		explicit_bzero(ilk, sizeof(ilk));
		LOG_SMP(1, "CTKD: h6 failed, no link key derived");
		return (-1);
	}
	explicit_bzero(ilk, sizeof(ilk));
	bond->has_link_key = true;

	LOG_SMP(1, "CTKD: ct2=%d, BR/EDR link key derived", ct2);

	return (0);
}

/*
 * Cross-Transport Key Derivation: BR/EDR Link Key -> LE LTK.
 * Core Spec Vol 3 Part H Section 2.4.2.5.
 *
 * The caller supplies a BR/EDR Secure Connections bond.  As with the reverse
 * direction above, unauthenticated (Just Works) material is deliberately not
 * promoted across transports.
 */
int
smp_ctkd_derive_ltk(struct smp_bond *bond, bool ct2)
{
	/* ASCII "tmp2" represented as the Section 2.4.2.5 128-bit SALT. */
	static const uint8_t salt_ct2[16] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x74, 0x6d, 0x70, 0x32
	};
	static const uint8_t keyid_brle[4] = { 0x62, 0x72, 0x6c, 0x65 };
	static const uint8_t keyid_tmp2[4] = { 0x74, 0x6d, 0x70, 0x32 };
	uint8_t iltk[16], ltk[16];

	if (!bond->is_sc || !bond->has_link_key)
		return (-1);
	if (!bond->is_mitm) {
		LOG_SMP(1, "CTKD: skipping LTK — pairing was not MITM-protected");
		return (0);
	}

	if (ct2) {
		if (smp_h7(salt_ct2, bond->link_key, iltk) != 0)
			goto fail;
	} else {
		if (smp_h6(bond->link_key, keyid_tmp2, iltk) != 0)
			goto fail;
	}
	if (smp_h6(iltk, keyid_brle, ltk) != 0)
		goto fail;

	memcpy(bond->ltk, ltk, sizeof(bond->ltk));
	explicit_bzero(iltk, sizeof(iltk));
	explicit_bzero(ltk, sizeof(ltk));
	bond->has_ltk = true;
	LOG_SMP(1, "CTKD: ct2=%d, LE LTK derived", ct2);
	return (0);

fail:
	explicit_bzero(iltk, sizeof(iltk));
	explicit_bzero(ltk, sizeof(ltk));
	LOG_SMP(1, "CTKD: key derivation failed, no LTK derived");
	return (-1);
}

/*
 * Save current per-connection CCCD values into a bond.
 * Core Spec Vol 3 Part G Section 2.4.5.1 requires the server to
 * persistently record CCCD values for bonded devices.
 *
 * CCCD values are per-connection state stored in ac->cccds[], not in
 * the shared att_db.  Only non-zero entries are saved.
 */
void
smp_bond_save_cccds(struct smp_bond *bond, const struct att_conn *ac)
{
	int i, n = 0;

	if (bond == NULL || ac == NULL)
		return;

	for (i = 0; i < ac->cccd_count && n < SMP_MAX_CCCDS; i++) {
		if (ac->cccds[i].value != 0) {
			bond->cccds[n].handle = ac->cccds[i].handle;
			bond->cccds[n].value = ac->cccds[i].value;
			n++;
		}
	}
	bond->num_cccds = (uint8_t)n;

	if (ac->cccd_count > SMP_MAX_CCCDS)
		warnx("CCCD persistence: %d/%d stored (cap=%d)",
		    n, ac->cccd_count, SMP_MAX_CCCDS);
}

/*
 * Restore saved CCCD values from a bond into the per-connection state.
 * Populates ac->cccds[] so the ATT server sees the restored values
 * on subsequent reads and can send notifications/indications.
 */
void
smp_bond_restore_cccds(const struct smp_bond *bond, struct att_conn *ac)
{
	int j, n;

	if (bond == NULL || ac == NULL)
		return;

	n = ac->cccd_count;
	/*
	 * Bound the loop by BOTH num_cccds AND the physical array size
	 * SMP_MAX_CCCDS (K4).  num_cccds is a uint8_t (0..255) while
	 * bond->cccds[] holds only SMP_MAX_CCCDS entries; a corrupt record with
	 * num_cccds > SMP_MAX_CCCDS would otherwise read past the array.
	 */
	for (j = 0; j < bond->num_cccds && j < SMP_MAX_CCCDS &&
	    n < ATT_MAX_CCCDS_PER_CONN; j++) {
		ac->cccds[n].handle = bond->cccds[j].handle;
		ac->cccds[n].value = bond->cccds[j].value;
		n++;
	}
	ac->cccd_count = n;
}

/* ================================================================
 * Bond database at-rest encryption.  Version 5 uses AES-256-GCM authenticated
 * encryption with a key derived from a per-machine secret and a random
 * 128-bit per-file salt.  A random 96-bit nonce and 128-bit authentication
 * tag are stored in the file header.
 * If secret material is unavailable, saves are refused to prevent plaintext
 * key exposure.
 * ================================================================ */

#define BOND_MAGIC_ENC		"BONDE"
#define BOND_MAGIC_ENC_LEN	5
#define BOND_ENC_VERSION	5
#define BOND_ENC_VERSION_MIN	4
#define BOND_ENC_PBKDF2_ITER	100000
#define BOND_ENC_KEYLEN		32		/* AES-256 key */
#define BOND_ENC_IVLEN		12		/* AES-256-GCM IV (96-bit nonce) */
#define BOND_ENC_TAGLEN		16		/* AES-256-GCM authentication tag */
#define BOND_ENC_SALTLEN	16		/* random per-file PBKDF2 salt */

/*
 * Bond secret key file path, placed alongside the bond database.
 * The file contains 32 raw random bytes generated on first use.
 * Permissions are restricted to 0600 (owner-only).
 *
 * This secret replaces kern.hostuuid as the PBKDF2 input.
 * kern.hostuuid is world-readable via sysctl, so any local user can
 * derive the same encryption key and decrypt the bond database.  A
 * dedicated key file with restricted permissions ensures only root
 * (or the daemon's uid) can access the secret material.
 */
#define BOND_SECRET_LEN		32
#define BOND_LEGACY_SECRET_FILE	BLUED_BONDDB_DEFAULT ".key"

/*
 * Load or generate the bond secret key file.
 *
 * Try to read BOND_SECRET_LEN bytes from the key file.  If the file
 * does not exist, generate random bytes with arc4random_buf(), write
 * them out with mode 0600, and use those bytes.  O_CREAT|O_EXCL
 * prevents TOCTOU races when two instances start simultaneously.
 *
 * Returns 0 on success (bond_secret_buf is filled), -1 on failure.
 */
static int
bond_secret_load(struct smp_bond_db *db)
{
	char name[sizeof(db->file_name) + 8];
	struct stat sb;
	uint8_t secret[BOND_SECRET_LEN];
	size_t off;
	int fd, legacy_fd, r;
	bool existing_db;
	ssize_t n;

	if (db == NULL || db->dir_fd < 0 || db->file_name[0] == '\0')
		return (-1);
	if (db->has_bond_secret)
		return (0);
	r = snprintf(name, sizeof(name), "%s.key", db->file_name);
	if (r < 0 || (size_t)r >= sizeof(name))
		return (-1);

	/* Try to read existing key file */
	fd = openat(db->dir_fd, name,
	    O_RDONLY | O_CLOEXEC | O_CLOFORK | O_NOFOLLOW);
	if (fd >= 0) {
		off = 0;
		while (off < sizeof(secret)) {
			n = read(fd, secret + off, sizeof(secret) - off);
			if (n < 0 && errno == EINTR)
				continue;
			if (n <= 0)
				break;
			off += (size_t)n;
		}
		if (fstat(fd, &sb) == 0 && S_ISREG(sb.st_mode) &&
		    sb.st_uid == geteuid() && (sb.st_mode & 077) == 0 &&
		    sb.st_size == BOND_SECRET_LEN && off == sizeof(secret)) {
			(void)close(fd);
			memcpy(db->bond_secret, secret, sizeof(secret));
			db->has_bond_secret = true;
			explicit_bzero(secret, sizeof(secret));
			return (0);
		}
		(void)close(fd);
		explicit_bzero(secret, sizeof(secret));
		warnx("bond secret file %s is corrupt or insecure", name);
		return (-1);
	}
	if (errno != ENOENT)
		return (-1);

	/*
	 * Never mint a different root for a non-empty database.  Older versions
	 * always used the default absolute key path even with a custom bond path;
	 * copy that secure root into the new sibling file as a one-time migration.
	 */
	if (db->fd < 0 || fstat(db->fd, &sb) != 0)
		return (-1);
	existing_db = sb.st_size != 0;
	if (existing_db) {
		legacy_fd = open(BOND_LEGACY_SECRET_FILE,
		    O_RDONLY | O_CLOEXEC | O_CLOFORK | O_NOFOLLOW);
		if (legacy_fd < 0 || fstat(legacy_fd, &sb) != 0 ||
		    !S_ISREG(sb.st_mode) || sb.st_uid != geteuid() ||
		    (sb.st_mode & 077) != 0 || sb.st_size != BOND_SECRET_LEN) {
			if (legacy_fd >= 0)
				(void)close(legacy_fd);
			return (-1);
		}
		off = 0;
		while (off < sizeof(secret)) {
			n = read(legacy_fd, secret + off, sizeof(secret) - off);
			if (n < 0 && errno == EINTR)
				continue;
			if (n <= 0)
				break;
			off += (size_t)n;
		}
		(void)close(legacy_fd);
		if (off != sizeof(secret)) {
			explicit_bzero(secret, sizeof(secret));
			return (-1);
		}
	} else {
		arc4random_buf(secret, sizeof(secret));
	}

	fd = openat(db->dir_fd, name, O_WRONLY | O_CREAT | O_EXCL |
	    O_CLOEXEC | O_CLOFORK | O_NOFOLLOW, 0600);
	if (fd >= 0) {
		off = 0;
		while (off < sizeof(secret)) {
			n = write(fd, secret + off, sizeof(secret) - off);
			if (n < 0 && errno == EINTR)
				continue;
			if (n <= 0)
				break;
			off += (size_t)n;
		}
		r = (off == sizeof(secret) && fsync(fd) == 0) ? 0 : -1;
		if (close(fd) != 0)
			r = -1;
		if (r == 0 && fsync(db->dir_fd) != 0)
			r = -1;
		if (r == 0) {
			memcpy(db->bond_secret, secret, sizeof(secret));
			db->has_bond_secret = true;
			explicit_bzero(secret, sizeof(secret));
			LOG_SMP(1, "generated bond secret key file %s", name);
			return (0);
		}
		(void)unlinkat(db->dir_fd, name, 0);
		explicit_bzero(secret, sizeof(secret));
		return (-1);
	}

	if (errno == EEXIST) {
		/*
		 * Another instance created the file between our open()
		 * attempts.  Read it.
		 */
		explicit_bzero(secret, sizeof(secret));
		return (bond_secret_load(db));
	}

	explicit_bzero(secret, sizeof(secret));
	warn("cannot create bond secret file %s", name);
	return (-1);
}

/*
 * Validate the per-machine identity root used to derive the bond-DB key.
 *
 * Threat model: the bond store must FAIL CLOSED when its identity root
 * (the per-database secret) is unavailable or empty.  Deriving a key from
 * nothing -- or otherwise proceeding as if a root
 * existed -- would let bonds be trusted without any binding to this machine.
 * Trailing NUL/newline/space are ignored; returns 0 if a significant byte
 * remains, -1 to refuse.
 */
int
smp_bond_identity_root_ok(const char *root, size_t len)
{
	size_t i;

	if (root == NULL)
		return (-1);
	for (i = 0; i < len; i++) {
		if (root[i] != '\0' && !isspace((unsigned char)root[i]))
			return (0);
	}
	return (-1);
}

/*
 * Derive an AES-256 encryption key from a per-machine secret.
 *
 * The secret is read from a dedicated sibling key file
 * that contains 32 random bytes generated on first use with mode 0600.
 * This replaces the prior use of kern.hostuuid, which was world-readable
 * and allowed any local user to derive the bond encryption key.
 *
 * There is deliberately no host-UUID fallback: host UUIDs are public and do
 * not provide confidentiality for LTKs, IRKs, CSRKs, or DeviceKeys.
 *
 * The caller provides the random per-file salt and its length.
 * Returns 0 on success, -1 if no secret material is available.
 */
static int
bond_db_derive_key(struct smp_bond_db *db, uint8_t key[BOND_ENC_KEYLEN],
    const uint8_t *salt, size_t salt_len)
{
	if (bond_secret_load(db) != 0) {
		BLUED_LOG_SECURITY("bond DB: unavailable per-database secret; "
		    "refusing key derivation");
		return (-1);
	}

	if (PKCS5_PBKDF2_HMAC((const char *)db->bond_secret, BOND_SECRET_LEN,
	    salt, (int)salt_len,
	    BOND_ENC_PBKDF2_ITER, EVP_sha256(),
	    BOND_ENC_KEYLEN, key) != 1) {
		warnx("PKCS5_PBKDF2_HMAC failed");
		return (-1);
	}

	return (0);
}

/*
 * Encrypt a plaintext buffer with AES-256-GCM (authenticated encryption).
 * Caller provides key and iv.  On success, *out is malloc'd ciphertext,
 * *out_len is set, and the authentication tag is written to tag[].
 * Returns 0 on success, -1 on failure.
 */
static int
bond_db_encrypt(const uint8_t *plaintext, size_t pt_len,
    const uint8_t key[BOND_ENC_KEYLEN], const uint8_t iv[BOND_ENC_IVLEN],
    uint8_t **out, size_t *out_len, uint8_t tag[BOND_ENC_TAGLEN])
{
	EVP_CIPHER_CTX *ctx;
	int outl, final_outl;
	uint8_t *ct;

	ct = malloc(pt_len);
	if (ct == NULL)
		return (-1);

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		free(ct);
		return (-1);
	}

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
		warnx("EVP_EncryptInit_ex failed (bond encrypt)");
		goto fail;
	}
	if (EVP_EncryptUpdate(ctx, ct, &outl, plaintext, (int)pt_len) != 1) {
		warnx("EVP_EncryptUpdate failed (bond encrypt)");
		goto fail;
	}
	if (EVP_EncryptFinal_ex(ctx, ct + outl, &final_outl) != 1) {
		warnx("EVP_EncryptFinal_ex failed (bond encrypt)");
		goto fail;
	}
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
	    BOND_ENC_TAGLEN, tag) != 1) {
		warnx("EVP_CTRL_GCM_GET_TAG failed (bond encrypt)");
		goto fail;
	}

	*out = ct;
	*out_len = (size_t)(outl + final_outl);
	EVP_CIPHER_CTX_free(ctx);
	return (0);

fail:
	EVP_CIPHER_CTX_free(ctx);
	explicit_bzero(ct, pt_len);
	free(ct);
	return (-1);
}

/*
 * Decrypt a ciphertext buffer with AES-256-GCM (authenticated decryption).
 * The authentication tag must be provided; DecryptFinal will fail if the
 * tag does not match (tampered or wrong key).
 * On success, *out is malloc'd plaintext and *out_len is set.
 * Returns 0 on success, -1 on failure (wrong key, tampered, corrupt).
 */
static int
bond_db_decrypt(const uint8_t *ciphertext, size_t ct_len,
    const uint8_t key[BOND_ENC_KEYLEN], const uint8_t iv[BOND_ENC_IVLEN],
    const uint8_t tag[BOND_ENC_TAGLEN],
    uint8_t **out, size_t *out_len)
{
	EVP_CIPHER_CTX *ctx;
	int outl, final_outl;
	uint8_t *pt;

	if (ct_len == 0)
		return (-1);

	pt = malloc(ct_len);
	if (pt == NULL)
		return (-1);

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		free(pt);
		return (-1);
	}

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
		warnx("EVP_DecryptInit_ex failed (bond decrypt)");
		goto fail;
	}
	if (EVP_DecryptUpdate(ctx, pt, &outl, ciphertext, (int)ct_len) != 1) {
		warnx("EVP_DecryptUpdate failed (bond decrypt)");
		goto fail;
	}
	/* Set the expected authentication tag before Finalize */
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
	    BOND_ENC_TAGLEN, (void *)(uintptr_t)tag) != 1) {
		warnx("EVP_CTRL_GCM_SET_TAG failed (bond decrypt)");
		goto fail;
	}
	if (EVP_DecryptFinal_ex(ctx, pt + outl, &final_outl) != 1) {
		warnx("bond db: authentication failed (wrong key or tampered file)");
		goto fail;
	}

	*out = pt;
	*out_len = (size_t)(outl + final_outl);
	EVP_CIPHER_CTX_free(ctx);
	return (0);

fail:
	EVP_CIPHER_CTX_free(ctx);
	explicit_bzero(pt, ct_len);
	free(pt);
	return (-1);
}

/* Load the current encrypted bond database format. */
int
smp_bond_db_load(struct smp_bond_db *db, int fd)
{
	enum {
		header_size = BOND_MAGIC_ENC_LEN + 4 + BOND_ENC_SALTLEN +
		    BOND_ENC_IVLEN + BOND_ENC_TAGLEN + 4
	};
	struct stat st;
	uint8_t header[header_size];
	uint8_t key[BOND_ENC_KEYLEN];
	uint8_t *ct = NULL, *pt = NULL;
	const uint8_t *salt, *iv, *tag;
	uint32_t version, ct_len, count, stored_size;
	size_t pt_len, bond_len, offset, expected_len;
	ssize_t n;
	int i, lock_result, ret = -1;

	if (db == NULL || fd < 0)
		return (-1);

	db->fd = fd;
	db->count = 0;
	db->has_local_irk = false;
	memset(db->local_irk, 0, sizeof(db->local_irk));
	db->has_local_csrk = false;
	memset(db->local_csrk, 0, sizeof(db->local_csrk));
	(void)fchmod(fd, 0600);

	do {
		lock_result = flock(fd, LOCK_EX);
	} while (lock_result < 0 && errno == EINTR);
	if (lock_result != 0)
		return (-1);
	if (fstat(fd, &st) != 0) {
		ret = -1;
		goto out;
	}
	if (st.st_size == 0) {
		ret = 0;
		goto out;
	}
	if (st.st_size < header_size) {
		warnx("bond db: truncated header");
		goto out;
	}
	n = pread(fd, header, sizeof(header), 0);
	if (n != (ssize_t)sizeof(header)) {
		if (n < 0)
			ret = -1;
		else
			warnx("bond db: truncated header");
		goto out;
	}
	if (memcmp(header, BOND_MAGIC_ENC, BOND_MAGIC_ENC_LEN) != 0) {
		warnx("bond db: unsupported format");
		goto out;
	}

	memcpy(&version, header + BOND_MAGIC_ENC_LEN, sizeof(version));
	version = le32toh(version);
	if (version < BOND_ENC_VERSION_MIN || version > BOND_ENC_VERSION) {
		warnx("bond db: unsupported version %u", version);
		goto out;
	}
	salt = header + BOND_MAGIC_ENC_LEN + 4;
	iv = salt + BOND_ENC_SALTLEN;
	tag = iv + BOND_ENC_IVLEN;
	memcpy(&ct_len, tag + BOND_ENC_TAGLEN, sizeof(ct_len));
	ct_len = le32toh(ct_len);
	if (ct_len == 0 || ct_len > 1024 * 1024 ||
	    (uintmax_t)st.st_size != (uintmax_t)header_size + ct_len) {
		warnx("bond db: invalid ciphertext length %u", ct_len);
		goto out;
	}

	ct = malloc(ct_len);
	if (ct == NULL) {
		ret = -1;
		goto out;
	}
	n = pread(fd, ct, ct_len, header_size);
	if (n != (ssize_t)ct_len) {
		if (n < 0)
			ret = -1;
		else
			warnx("bond db: truncated ciphertext");
		goto out;
	}
	if (bond_db_derive_key(db, key, salt, BOND_ENC_SALTLEN) != 0) {
		warnx("bond db: cannot derive key");
		goto out;
	}
	if (bond_db_decrypt(ct, ct_len, key, iv, tag, &pt, &pt_len) != 0) {
		warnx("bond db: authentication failed");
		BLUED_LOG_SECURITY("bond db authentication failed");
		goto out;
	}
	if (pt_len < 2 * sizeof(uint32_t) + 1) {
		warnx("bond db: truncated plaintext");
		goto out;
	}
	memcpy(&count, pt, sizeof(count));
	memcpy(&stored_size, pt + sizeof(count), sizeof(stored_size));
	count = le32toh(count);
	stored_size = le32toh(stored_size);
	if (count > SMP_MAX_BONDS ||
	    stored_size != sizeof(struct smp_bond)) {
		warnx("bond db: invalid record count or size");
		goto out;
	}
	bond_len = (size_t)count * sizeof(struct smp_bond);
	offset = 2 * sizeof(uint32_t) + bond_len;
	if (offset >= pt_len || pt[offset] > 1) {
		warnx("bond db: invalid plaintext payload");
		goto out;
	}
	expected_len = offset + 1 + (pt[offset] != 0 ? 16 : 0);
	if (version == 4) {
		if (pt_len != expected_len) {
			warnx("bond db: invalid v4 plaintext length");
			goto out;
		}
	} else {
		if (expected_len >= pt_len || pt[expected_len] > 1 ||
		    pt_len != expected_len + 1 +
		    (pt[expected_len] != 0 ? 16 : 0)) {
			warnx("bond db: invalid v5 plaintext length");
			goto out;
		}
	}

	memcpy(db->bonds, pt + 2 * sizeof(uint32_t), bond_len);
	db->count = (int)count;
	for (i = 0; i < db->count; i++)
		if (db->bonds[i].num_cccds > SMP_MAX_CCCDS)
			db->bonds[i].num_cccds = SMP_MAX_CCCDS;
	if (pt[offset] != 0) {
		memcpy(db->local_irk, pt + offset + 1, 16);
		db->has_local_irk = true;
	}
	if (version >= 5 && pt[expected_len] != 0) {
		memcpy(db->local_csrk, pt + expected_len + 1, 16);
		db->has_local_csrk = true;
	}
	BLUED_PROBE_BOND_LOAD(db->count);
	LOG_SMP(1, "loaded %d bonds from encrypted database", db->count);
	ret = 0;

out:
	explicit_bzero(key, sizeof(key));
	if (pt != NULL) {
		explicit_bzero(pt, pt_len);
		free(pt);
	}
	if (ct != NULL) {
		explicit_bzero(ct, ct_len);
		free(ct);
	}
	(void)flock(fd, LOCK_UN);
	return (ret);
}

/*
 * Enable atomic bond-DB persistence.  The daemon passes the state
 * directory fd (whose capability rights already permit openat/fsync/
 * renameat/unlinkat) and the bond file path; the basename is retained for
 * temp + fsync + rename saves.
 */
void
smp_bond_db_set_atomic(struct smp_bond_db *db, int dir_fd, const char *path)
{
	const char *base;

	if (db == NULL)
		return;
	db->dir_fd = -1;
	db->file_name[0] = '\0';
	if (dir_fd < 0 || path == NULL)
		return;
	base = strrchr(path, '/');
	base = (base != NULL) ? base + 1 : path;
	if (base[0] == '\0' || strlen(base) >= sizeof(db->file_name))
		return;
	db->dir_fd = dir_fd;
	strlcpy(db->file_name, base, sizeof(db->file_name));
}

/* Write the full buffer, retrying short/interrupted writes. */
static int
bond_write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t off = 0;
	ssize_t n;

	while (off < len) {
		n = write(fd, p + off, len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (n == 0)
			return (-1);
		off += (size_t)n;
	}
	return (0);
}

/*
 * Atomic bond-DB write: stage the header + ciphertext in a sibling
 * temp file, fsync it, then renameat() it over the live bond file.  A crash
 * or error at any step leaves the previous good bond file untouched -- the
 * live name is only ever replaced by a complete, fsync'd file.  Mirrors the
 * blued_persist engine's temp + fsync + rename discipline.
 */
static int
bond_db_save_atomic(struct smp_bond_db *db, const uint8_t *hdr, size_t hlen,
    const uint8_t *ct, size_t ctlen)
{
	char tmp[sizeof(db->file_name) + 16];
	int fd, r;

	r = snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", db->file_name);
	if (r < 0 || (size_t)r >= sizeof(tmp))
		return (-1);

	fd = mkostempsat(db->dir_fd, tmp, 0, O_CLOEXEC | O_CLOFORK);
	if (fd < 0)
		return (-1);
	if (fchmod(fd, 0600) != 0)
		goto fail;

	if (bond_write_all(fd, hdr, hlen) != 0)
		goto fail;
	if (ctlen > 0 && bond_write_all(fd, ct, ctlen) != 0)
		goto fail;
	if (fsync(fd) != 0)
		goto fail;
	if (renameat(db->dir_fd, tmp, db->dir_fd, db->file_name) != 0) {
		(void)close(fd);
		(void)unlinkat(db->dir_fd, tmp, 0);
		return (-1);
	}
	if (fsync(db->dir_fd) != 0) {
		(void)close(fd);
		return (SMP_BOND_DB_COMMIT_UNCERTAIN);
	}
	do {
		r = dup2(fd, db->fd);
	} while (r < 0 && errno == EINTR);
	if (r < 0) {
		(void)close(fd);
		return (SMP_BOND_DB_COMMIT_UNCERTAIN);
	}
	if (fd != db->fd)
		(void)close(fd);
	return (0);

fail:
	(void)close(fd);
	(void)unlinkat(db->dir_fd, tmp, 0);
	return (-1);
}

/*
 * Save bond database to file descriptor.
 *
 * Always writes encrypted v5 format ("BONDE", AES-256-GCM with a random
 * per-file PBKDF2 salt).  Refuses to save if key derivation fails --
 * plaintext storage of bond keys is a security risk.  When an atomic target
 * directory is configured (smp_bond_db_set_atomic), the encrypted image is
 * written via temp + fsync + rename so a crash mid-save cannot corrupt the
 * previous good bond file.
 */
int
smp_bond_db_save(struct smp_bond_db *db)
{
	uint8_t key[BOND_ENC_KEYLEN];
	uint8_t file_salt[BOND_ENC_SALTLEN];
	size_t bond_len, irk_len, csrk_len, pt_len;
	uint8_t *pt, *p;
	uint32_t count_le;
	uint8_t iv[BOND_ENC_IVLEN];
	uint8_t tag[BOND_ENC_TAGLEN];
	uint8_t *ct = NULL;
	size_t ct_len;
	int lock_result, r;

	if (db == NULL || db->fd < 0 || db->dir_fd < 0 ||
	    db->file_name[0] == '\0' || db->count < 0 ||
	    db->count > SMP_MAX_BONDS)
		return (-1);

	/* Ensure owner-only permissions on bond file (contains LTK/IRK) */
	if (fchmod(db->fd, 0600) != 0) {
		warn("fchmod bond db");
		return (-1);
	}

	do {
		lock_result = flock(db->fd, LOCK_EX);
	} while (lock_result < 0 && errno == EINTR);
	if (lock_result < 0) {
		warn("flock LOCK_EX");
		return (-1);
	}

	/* Generate a random per-file salt for PBKDF2 key derivation */
	if (RAND_bytes(file_salt, sizeof(file_salt)) != 1) {
		warnx("RAND_bytes failed for bond db salt");
		flock(db->fd, LOCK_UN);
		return (-1);
	}

	/* Derive encryption key using the random salt */
	if (bond_db_derive_key(db, key, file_salt, BOND_ENC_SALTLEN) != 0) {
		/*
		 * Key derivation failed (no secret material available).
		 * Refuse to save -- writing bonds in plaintext would
		 * expose LTK/IRK material on disk.  Existing encrypted
		 * data on disk is preserved.
		 */
		BLUED_LOG_SECURITY("bond db: cannot derive encryption "
		    "key, REFUSING to save bonds -- existing bond file "
		    "preserved");
		warnx("bond db: cannot derive key, refusing to save");
		explicit_bzero(key, sizeof(key));
		flock(db->fd, LOCK_UN);
		return (-1);
	}

	/*
	 * Build plaintext payload:
	 *   uint32_t        count (LE)
	 *   uint32_t        bond_struct_size (LE) — sizeof(struct smp_bond)
	 *   smp_bond[]      bonds[count]
	 *   uint8_t         has_local_irk
	 *   uint8_t[16]     local_irk (if has_local_irk)
	 *   uint8_t         has_local_csrk
	 *   uint8_t[16]     local_csrk (if has_local_csrk)
	 */
	bond_len = (size_t)db->count * sizeof(struct smp_bond);
	irk_len = 1 + (db->has_local_irk ? 16 : 0);
	csrk_len = 1 + (db->has_local_csrk ? 16 : 0);
	pt_len = sizeof(uint32_t) + sizeof(uint32_t) + bond_len + irk_len +
	    csrk_len;

	pt = malloc(pt_len);
	if (pt == NULL) {
		explicit_bzero(key, sizeof(key));
		flock(db->fd, LOCK_UN);
		return (-1);
	}

	p = pt;
	count_le = htole32((uint32_t)db->count);
	memcpy(p, &count_le, sizeof(uint32_t));
	p += sizeof(uint32_t);

	{
		uint32_t struct_size_le;
		struct_size_le = htole32((uint32_t)sizeof(struct smp_bond));
		memcpy(p, &struct_size_le, sizeof(uint32_t));
		p += sizeof(uint32_t);
	}

	memcpy(p, db->bonds, bond_len);
	p += bond_len;

	*p++ = db->has_local_irk ? 1 : 0;
	if (db->has_local_irk) {
		memcpy(p, db->local_irk, 16);
		p += 16;
	}
	*p++ = db->has_local_csrk ? 1 : 0;
	if (db->has_local_csrk)
		memcpy(p, db->local_csrk, 16);

	/* Generate random IV for this save */
	if (RAND_bytes(iv, sizeof(iv)) != 1) {
		warnx("RAND_bytes failed for bond db IV");
		explicit_bzero(pt, pt_len);
		free(pt);
		explicit_bzero(key, sizeof(key));
		flock(db->fd, LOCK_UN);
		return (-1);
	}

	/* Encrypt */
	if (bond_db_encrypt(pt, pt_len, key, iv, &ct, &ct_len, tag) != 0) {
		warnx("bond db encryption failed");
		explicit_bzero(pt, pt_len);
		free(pt);
		explicit_bzero(key, sizeof(key));
		flock(db->fd, LOCK_UN);
		return (-1);
	}

	explicit_bzero(pt, pt_len);
	free(pt);
	explicit_bzero(key, sizeof(key));

	/*
	 * Write encrypted file (v5, AES-256-GCM + random salt):
	 *   "BONDE"     (5 bytes)
	 *   uint32_t    version = 5 (LE)
	 *   uint8_t[16] salt (PBKDF2 salt)
	 *   uint8_t[12] iv (96-bit nonce)
	 *   uint8_t[16] tag (authentication tag)
	 *   uint32_t    ciphertext_len (LE)
	 *   uint8_t[]   ciphertext
	 */
	{
		uint8_t file_hdr[BOND_MAGIC_ENC_LEN + 4 +
		    BOND_ENC_SALTLEN + BOND_ENC_IVLEN +
		    BOND_ENC_TAGLEN + 4];
		uint32_t version_le, ct_len_le;
		uint8_t *hp = file_hdr;

		memcpy(hp, BOND_MAGIC_ENC, BOND_MAGIC_ENC_LEN);
		hp += BOND_MAGIC_ENC_LEN;

		version_le = htole32(BOND_ENC_VERSION);
		memcpy(hp, &version_le, 4);
		hp += 4;

		memcpy(hp, file_salt, BOND_ENC_SALTLEN);
		hp += BOND_ENC_SALTLEN;

		memcpy(hp, iv, BOND_ENC_IVLEN);
		hp += BOND_ENC_IVLEN;

		memcpy(hp, tag, BOND_ENC_TAGLEN);
		hp += BOND_ENC_TAGLEN;

		ct_len_le = htole32((uint32_t)ct_len);
		memcpy(hp, &ct_len_le, 4);

		r = bond_db_save_atomic(db, file_hdr, sizeof(file_hdr), ct,
		    ct_len);
		if (r != 0) {
			warn("atomic bond db save");
			explicit_bzero(ct, ct_len);
			free(ct);
			flock(db->fd, LOCK_UN);
			return (r);
		}
	}

	explicit_bzero(ct, ct_len);
	free(ct);

	flock(db->fd, LOCK_UN);

	BLUED_PROBE_BOND_SAVE(db->count);
	return (0);
}
