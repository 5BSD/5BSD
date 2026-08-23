/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * Bluetooth Mesh network manager / provisioner application.  See
 * mesh_manager.h for the layer's role, the four capabilities (create-network,
 * address allocation, node roster / DevKey store, Config Client) and the
 * spec citations.
 */

#include <sys/endian.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/rand.h>

#include "mesh_manager.h"
#include "mesh_access.h"
#include "mesh_iv.h"
#include "mesh_transport.h"
#include "mesh_cfg_model.h"

/* ================================================================
 * Address-range bookkeeping.
 * ================================================================ */

/*
 * True if the block [addr, addr+n) is a valid unicast block (in range, no
 * wrap).  A device with n elements occupies n consecutive unicast addresses
 * (MshPRT_v1.1 Section 3.4.2).
 */
static int
block_valid(uint16_t addr, uint8_t n)
{

	if (n == 0)
		return (0);
	if (addr < MESH_MGR_UNICAST_MIN)
		return (0);
	/* addr + n - 1 must not exceed the unicast maximum (compute in 32-bit). */
	if ((uint32_t)addr + (uint32_t)n - 1u > MESH_MGR_UNICAST_MAX)
		return (0);
	return (1);
}

/* True if the two half-open unicast blocks [a,a+na) and [b,b+nb) overlap. */
static int
blocks_overlap(uint16_t a, uint8_t na, uint16_t b, uint8_t nb)
{
	uint32_t a0 = a, a1 = (uint32_t)a + na;
	uint32_t b0 = b, b1 = (uint32_t)b + nb;

	return (a0 < b1 && b0 < a1);
}

/* True if [addr,addr+n) overlaps the Provisioner block or any roster node. */
static int
range_used(const struct mesh_mgr *mgr, uint16_t addr, uint8_t n)
{
	size_t i;

	if (blocks_overlap(addr, n, mgr->self_addr, mgr->self_elements))
		return (1);
	/*
	 * An in-flight provisioning reservation is not yet in the roster, so it
	 * must be checked explicitly -- otherwise import-remote-node (or a second
	 * allocation) can hand out the block a live handshake is completing onto,
	 * guaranteeing a unicast collision when that handshake commits (NB-21).
	 */
	if (mgr->pending.active &&
	    blocks_overlap(addr, n, mgr->pending.addr, mgr->pending.num_elements))
		return (1);
	for (i = 0; i < mgr->n_nodes; i++) {
		if (blocks_overlap(addr, n, mgr->nodes[i].addr,
		    mgr->nodes[i].num_elements))
			return (1);
	}
	return (0);
}

/*
 * Advance the allocator high-water mark past a just-claimed block.  A valid
 * unicast block never ends above 0x8000, so the mark may hold the 0x8000
 * past-the-end sentinel; that is what makes the next allocation fail cleanly
 * (block_valid rejects 0x8000) rather than re-hand the top address.
 */
static void
bump_high_water(struct mesh_mgr *mgr, uint16_t addr, uint8_t n)
{
	uint32_t end = (uint32_t)addr + n;	/* first address past the block */

	if (end > mgr->next_unicast)
		mgr->next_unicast = (uint16_t)end;
}

/* ================================================================
 * MPROV1 - create a network.
 * ================================================================ */

int
mesh_mgr_create_network(struct mesh_mgr *mgr, uint8_t out_netkey[16],
    uint8_t out_appkey[16])
{

	if (mgr == NULL)
		return (-1);
	memset(mgr, 0, sizeof(*mgr));
	if (RAND_bytes(mgr->netkey, sizeof(mgr->netkey)) != 1)
		return (-1);
	if (RAND_bytes(mgr->appkey, sizeof(mgr->appkey)) != 1)
		return (-1);
	/* Stage a distinct Phase-1 AppKey for a future Config AppKey Update. */
	if (RAND_bytes(mgr->appkey_new, sizeof(mgr->appkey_new)) != 1)
		return (-1);
	if (RAND_bytes(mgr->self_devkey, sizeof(mgr->self_devkey)) != 1)
		return (-1);
	mgr->netkey_index = 0;
	mgr->appkey_index = 0;
	mgr->iv_index = 0;
	mgr->flags = 0;
	mgr->seq = 0;
	mgr->self_addr = MESH_MGR_PROVISIONER_ADDR;
	mgr->self_elements = 1;
	mgr->n_nodes = 0;
	mgr->pending.active = 0;
	/* First device address sits just past the Provisioner's element block. */
	mgr->next_unicast = mgr->self_addr + mgr->self_elements;

	if (out_netkey != NULL)
		memcpy(out_netkey, mgr->netkey, sizeof(mgr->netkey));
	if (out_appkey != NULL)
		memcpy(out_appkey, mgr->appkey, sizeof(mgr->appkey));
	return (0);
}

int
mesh_mgr_set_self(struct mesh_mgr *mgr, uint16_t addr, uint8_t num_elements,
    const uint8_t devkey[16])
{

	if (mgr == NULL || !block_valid(addr, num_elements))
		return (-1);
	/* Only before any device address has been handed out. */
	if (mgr->n_nodes != 0 || mgr->pending.active)
		return (-1);
	mgr->self_addr = addr;
	mgr->self_elements = num_elements;
	if (devkey != NULL)
		memcpy(mgr->self_devkey, devkey, sizeof(mgr->self_devkey));
	mgr->next_unicast = 0;
	bump_high_water(mgr, addr, num_elements);
	if (mgr->next_unicast < MESH_MGR_UNICAST_MIN)
		mgr->next_unicast = MESH_MGR_UNICAST_MIN;
	return (0);
}

/* ================================================================
 * MPROV2 - unicast address allocator.
 * ================================================================ */

int
mesh_mgr_alloc_unicast(struct mesh_mgr *mgr, uint8_t num_elements,
    uint16_t *out_addr)
{
	uint16_t addr;

	if (mgr == NULL || out_addr == NULL || num_elements == 0)
		return (-1);

	/*
	 * The high-water mark only ever advances, so it never points inside a
	 * claimed block; skip forward over the Provisioner / roster blocks in
	 * the rare case a manually added node was placed above it.
	 */
	addr = mgr->next_unicast;
	while (block_valid(addr, num_elements) &&
	    range_used(mgr, addr, num_elements)) {
		if ((uint32_t)addr + 1u > MESH_MGR_UNICAST_MAX)
			return (-1);
		addr++;
	}
	if (!block_valid(addr, num_elements))
		return (-1);		/* address space exhausted */

	*out_addr = addr;
	bump_high_water(mgr, addr, num_elements);
	return (0);
}

/* ================================================================
 * MPROV3 - node roster and DevKey store.
 * ================================================================ */

struct mesh_mgr_node *
mesh_mgr_add_node(struct mesh_mgr *mgr, const uint8_t uuid[16], uint16_t addr,
    uint8_t num_elements, const uint8_t devkey[16], uint64_t prov_time)
{
	struct mesh_mgr_node *n;

	if (mgr == NULL || uuid == NULL || devkey == NULL)
		return (NULL);
	if (!block_valid(addr, num_elements))
		return (NULL);
	if (range_used(mgr, addr, num_elements))
		return (NULL);
	if (mgr->n_nodes >= MESH_MGR_MAX_NODES)
		return (NULL);

	n = &mgr->nodes[mgr->n_nodes++];
	memset(n, 0, sizeof(*n));
	memcpy(n->uuid, uuid, sizeof(n->uuid));
	n->addr = addr;
	n->num_elements = num_elements;
	memcpy(n->devkey, devkey, sizeof(n->devkey));
	n->prov_time = prov_time;
	bump_high_water(mgr, addr, num_elements);
	return (n);
}

struct mesh_mgr_node *
mesh_mgr_find_by_addr(struct mesh_mgr *mgr, uint16_t addr)
{
	size_t i;

	if (mgr == NULL)
		return (NULL);
	for (i = 0; i < mgr->n_nodes; i++) {
		struct mesh_mgr_node *n = &mgr->nodes[i];

		if (addr >= n->addr &&
		    (uint32_t)addr < (uint32_t)n->addr + n->num_elements)
			return (n);
	}
	return (NULL);
}

struct mesh_mgr_node *
mesh_mgr_find_by_uuid(struct mesh_mgr *mgr, const uint8_t uuid[16])
{
	size_t i;

	if (mgr == NULL || uuid == NULL)
		return (NULL);
	for (i = 0; i < mgr->n_nodes; i++) {
		if (memcmp(mgr->nodes[i].uuid, uuid, MESH_MGR_UUID_LEN) == 0)
			return (&mgr->nodes[i]);
	}
	return (NULL);
}

int
mesh_mgr_remove_node(struct mesh_mgr *mgr, uint16_t addr)
{
	size_t i;

	if (mgr == NULL)
		return (-1);
	for (i = 0; i < mgr->n_nodes; i++) {
		if (mgr->nodes[i].addr != addr)
			continue;
		/* Compact: move the tail entry into the hole. */
		mgr->nodes[i] = mgr->nodes[mgr->n_nodes - 1];
		memset(&mgr->nodes[mgr->n_nodes - 1], 0,
		    sizeof(mgr->nodes[0]));
		mgr->n_nodes--;
		return (0);
	}
	return (-1);
}

size_t
mesh_mgr_node_count(const struct mesh_mgr *mgr)
{

	return (mgr == NULL ? 0 : mgr->n_nodes);
}

const struct mesh_mgr_node *
mesh_mgr_node_at(const struct mesh_mgr *mgr, size_t i)
{

	if (mgr == NULL || i >= mgr->n_nodes)
		return (NULL);
	return (&mgr->nodes[i]);
}

/* ================================================================
 * Persistence.  A single versioned, CRC-checked frame:
 *
 *   magic[8] | version(2 LE) | flags(2 LE) | reserved(4) | crc32(4 LE) |
 *   payload
 *
 * where crc32 covers everything from the magic through the payload with the
 * crc field taken as zero.  The payload is the fixed network/self header
 * followed by n_nodes fixed-size node records, all little-endian.  Only the
 * fields the manager needs to resume owning the network are serialised (the
 * pending reservation is transient and is not persisted).
 * ================================================================ */

#define	MESH_MGR_MAGIC		"MSHMGR\0\1"	/* 8 octets */
#define	MESH_MGR_MAGIC_LEN	8
/*
 * v2 added the persisted SEQ high-water mark; v3 adds the staged Phase-1
 * AppKey; v4 adds the per-node Key Refresh distribution state (kr_state) so a
 * NetKey key-refresh in progress survives a crash instead of silently ejecting
 * the not-yet-acked nodes at the next phase advance.
 */
#define	MESH_MGR_VERSION	4
#define	MESH_MGR_HDR_LEN	20		/* magic..crc32 inclusive */

/* Serialised network/self header (little-endian), 82 octets. */
#define	MESH_MGR_NETHDR_LEN	82

/*
 * Reserved SEQ block persisted ahead of the in-memory high-water mark
 * (MshPRT_v1.1 Section 3.4.4.5).  On save the manager records seq + RESERVE and
 * on reload resumes from that reserved-ahead value, so a crash between saves
 * cannot re-issue a SEQ already used (which would repeat an (IV, SEQ, SRC)
 * nonce).  The manager must therefore be persisted at least once per RESERVE
 * DevKey seals; every save renews the reservation.
 */
#define	MESH_MGR_SEQ_RESERVE	100u
/* Serialised per-node record (little-endian), 44 octets (v4: +kr_state). */
#define	MESH_MGR_NODEREC_LEN	44

/* CRC32 (IEEE 802.3, reflected polynomial 0xEDB88320). */
static uint32_t
mgr_crc32(uint32_t crc, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t i;
	int k;

	crc = ~crc;
	for (i = 0; i < len; i++) {
		crc ^= p[i];
		for (k = 0; k < 8; k++)
			crc = (crc >> 1) ^ (0xEDB88320u & (~(crc & 1) + 1));
	}
	return (~crc);
}

static int
write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t off = 0;
	ssize_t n;

	while (off < len) {
		n = write(fd, p + off, len - off);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			if (n == 0)
				errno = EIO;
			return (-1);
		}
		off += (size_t)n;
	}
	return (0);
}

static int
read_all(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t off = 0;
	ssize_t n;

	while (off < len) {
		n = read(fd, p + off, len - off);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return (-1);
		off += (size_t)n;
	}
	return (0);
}

/* Little-endian field writers advancing *pp. */
static void
put_u16(uint8_t **pp, uint16_t v)
{

	le16enc(*pp, v);
	*pp += 2;
}

static void
put_u32(uint8_t **pp, uint32_t v)
{

	le32enc(*pp, v);
	*pp += 4;
}

static void
put_u64(uint8_t **pp, uint64_t v)
{

	le64enc(*pp, v);
	*pp += 8;
}

static uint16_t
get_u16(const uint8_t **pp)
{
	uint16_t v = le16dec(*pp);

	*pp += 2;
	return (v);
}

static uint32_t
get_u32(const uint8_t **pp)
{
	uint32_t v = le32dec(*pp);

	*pp += 4;
	return (v);
}

static uint64_t
get_u64(const uint8_t **pp)
{
	uint64_t v = le64dec(*pp);

	*pp += 8;
	return (v);
}

/* Serialise the network/self header into an 82-octet buffer. */
static void
encode_nethdr(const struct mesh_mgr *mgr, uint8_t out[MESH_MGR_NETHDR_LEN])
{
	uint8_t *p = out;

	memcpy(p, mgr->netkey, 16);		p += 16;
	memcpy(p, mgr->appkey, 16);		p += 16;
	memcpy(p, mgr->self_devkey, 16);	p += 16;
	put_u16(&p, mgr->netkey_index);
	put_u16(&p, mgr->appkey_index);
	put_u32(&p, mgr->iv_index);
	put_u16(&p, mgr->self_addr);
	put_u16(&p, mgr->next_unicast);
	*p++ = mgr->flags;
	*p++ = mgr->self_elements;
	/*
	 * Persist the outbound SEQ high-water mark PLUS a reserved block: on
	 * reload the manager resumes above every SEQ it might already have used
	 * since the last save (up to RESERVE seals), so mesh_mgr_devkey_seal()
	 * never re-issues a SEQ - which would repeat an (IV, SEQ, SRC) nonce.
	 */
	put_u32(&p, mgr->seq + MESH_MGR_SEQ_RESERVE);
	/* Persist the staged Phase-1 AppKey (Config AppKey Update payload). */
	memcpy(p, mgr->appkey_new, 16);		p += 16;
	/* p - out == 82 */
}

static int
decode_nethdr(struct mesh_mgr *mgr, const uint8_t *in)
{
	const uint8_t *p = in;

	memcpy(mgr->netkey, p, 16);		p += 16;
	memcpy(mgr->appkey, p, 16);		p += 16;
	memcpy(mgr->self_devkey, p, 16);	p += 16;
	mgr->netkey_index = get_u16(&p);
	mgr->appkey_index = get_u16(&p);
	mgr->iv_index = get_u32(&p);
	mgr->self_addr = get_u16(&p);
	mgr->next_unicast = get_u16(&p);
	mgr->flags = *p++;
	mgr->self_elements = *p++;
	/* Resume from the reserved-ahead SEQ (see encode_nethdr / P-H8). */
	mgr->seq = get_u32(&p);
	memcpy(mgr->appkey_new, p, 16);		p += 16;
	return (0);
}

static void
encode_node(const struct mesh_mgr_node *n, uint8_t out[MESH_MGR_NODEREC_LEN])
{
	uint8_t *p = out;

	memcpy(p, n->uuid, 16);		p += 16;
	memcpy(p, n->devkey, 16);	p += 16;
	put_u16(&p, n->addr);
	put_u64(&p, n->prov_time);
	*p++ = n->num_elements;
	*p++ = n->kr_state;		/* v4: Key Refresh distribution state */
	/* p - out == 44 */
}

static void
decode_node(struct mesh_mgr_node *n, const uint8_t in[MESH_MGR_NODEREC_LEN])
{
	const uint8_t *p = in;

	memset(n, 0, sizeof(*n));
	memcpy(n->uuid, p, 16);		p += 16;
	memcpy(n->devkey, p, 16);	p += 16;
	n->addr = get_u16(&p);
	n->prov_time = get_u64(&p);
	n->num_elements = *p++;
	n->kr_state = *p++;		/* v4: Key Refresh distribution state */
}

int
mesh_mgr_save(const struct mesh_mgr *mgr, const char *path)
{
	struct stat sb;
	uint8_t hdr[MESH_MGR_HDR_LEN];
	uint8_t body[MESH_MGR_NETHDR_LEN +
	    MESH_MGR_MAX_NODES * MESH_MGR_NODEREC_LEN];
	uint8_t *p;
	uint32_t crc;
	size_t i, body_len;
	char dir[PATH_MAX], *slash, *tmp;
	size_t path_len;
	int dfd, fd, rc, saved_errno;

	if (mgr == NULL || path == NULL)
		return (-1);

	/* Body: network header + node records. */
	encode_nethdr(mgr, body);
	body_len = MESH_MGR_NETHDR_LEN;
	for (i = 0; i < mgr->n_nodes; i++) {
		encode_node(&mgr->nodes[i], body + body_len);
		body_len += MESH_MGR_NODEREC_LEN;
	}

	/* Header: magic, version, flags, reserved, crc (filled last). */
	p = hdr;
	memcpy(p, MESH_MGR_MAGIC, MESH_MGR_MAGIC_LEN);	p += MESH_MGR_MAGIC_LEN;
	put_u16(&p, MESH_MGR_VERSION);
	put_u16(&p, 0);				/* flags, reserved */
	put_u16(&p, (uint16_t)mgr->n_nodes);	/* record count */
	put_u16(&p, 0);				/* reserved */
	/* crc field (last 4 octets) is left as zero for the CRC computation. */
	memset(p, 0, 4);

	crc = mgr_crc32(0, hdr, MESH_MGR_HDR_LEN);
	crc = mgr_crc32(crc, body, body_len);
	le32enc(hdr + MESH_MGR_HDR_LEN - 4, crc);

	/* Refuse to replace an unsafe existing object, then write beside it. */
	if (lstat(path, &sb) == 0) {
		if (!S_ISREG(sb.st_mode) || sb.st_uid != geteuid()) {
			errno = EPERM;
			return (-1);
		}
	} else if (errno != ENOENT)
		return (-1);
	path_len = strlen(path);
	if (path_len == 0 || path_len > SIZE_MAX - 8) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	tmp = malloc(path_len + 8);
	if (tmp == NULL)
		return (-1);
	(void)snprintf(tmp, path_len + 8, "%s.XXXXXX", path);
	fd = mkstemp(tmp);
	if (fd < 0) {
		free(tmp);
		return (-1);
	}
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 || fchmod(fd, 0600) != 0) {
		saved_errno = errno;
		(void)close(fd);
		(void)unlink(tmp);
		free(tmp);
		errno = saved_errno;
		return (-1);
	}
	rc = write_all(fd, hdr, MESH_MGR_HDR_LEN);
	if (rc == 0)
		rc = write_all(fd, body, body_len);
	if (rc == 0)
		rc = fsync(fd);
	if (close(fd) != 0)
		rc = -1;
	if (rc != 0) {
		saved_errno = errno;
		(void)unlink(tmp);
		free(tmp);
		errno = saved_errno;
		return (-1);
	}
	if (rename(tmp, path) != 0) {
		saved_errno = errno;
		(void)unlink(tmp);
		free(tmp);
		errno = saved_errno;
		return (-1);
	}
	free(tmp);

	/* Persist the directory entry as well as the file contents. */
	if (path_len >= sizeof(dir)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	memcpy(dir, path, path_len + 1);
	slash = strrchr(dir, '/');
	if (slash == NULL)
		(void)strcpy(dir, ".");
	else if (slash == dir)
		slash[1] = '\0';
	else
		*slash = '\0';
	dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dfd < 0)
		return (-1);
	rc = fsync(dfd);
	if (close(dfd) != 0)
		rc = -1;
	return (rc);
}

int
mesh_mgr_load(struct mesh_mgr *mgr, const char *path)
{
	struct mesh_mgr tmp;
	struct stat sb;
	uint8_t hdr[MESH_MGR_HDR_LEN];
	uint8_t nethdr[MESH_MGR_NETHDR_LEN];
	uint8_t noderec[MESH_MGR_NODEREC_LEN];
	const uint8_t *p;
	uint32_t crc, stored_crc, running;
	uint16_t version, count;
	size_t i, nethdr_len;
	int fd;

	if (mgr == NULL || path == NULL)
		return (-1);
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return (-1);
	if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode) ||
	    sb.st_uid != geteuid() || (sb.st_mode & 077) != 0) {
		(void)close(fd);
		return (-1);
	}
	if (read_all(fd, hdr, MESH_MGR_HDR_LEN) != 0) {
		(void)close(fd);
		return (-1);
	}
	if (memcmp(hdr, MESH_MGR_MAGIC, MESH_MGR_MAGIC_LEN) != 0) {
		(void)close(fd);
		return (-1);
	}
	p = hdr + MESH_MGR_MAGIC_LEN;
	version = get_u16(&p);
	(void)get_u16(&p);			/* flags */
	count = get_u16(&p);
	(void)get_u16(&p);			/* reserved */
	stored_crc = le32dec(hdr + MESH_MGR_HDR_LEN - 4);
	if (version != MESH_MGR_VERSION || count > MESH_MGR_MAX_NODES) {
		(void)close(fd);
		return (-1);
	}
	nethdr_len = MESH_MGR_NETHDR_LEN;

	memset(&tmp, 0, sizeof(tmp));

	/* CRC accumulates over the header (with the crc field taken as zero). */
	{
		uint8_t hcopy[MESH_MGR_HDR_LEN];

		memcpy(hcopy, hdr, MESH_MGR_HDR_LEN);
		memset(hcopy + MESH_MGR_HDR_LEN - 4, 0, 4);
		running = mgr_crc32(0, hcopy, MESH_MGR_HDR_LEN);
	}

	if (read_all(fd, nethdr, nethdr_len) != 0) {
		(void)close(fd);
		return (-1);
	}
	running = mgr_crc32(running, nethdr, nethdr_len);
	if (decode_nethdr(&tmp, nethdr) != 0) {
		(void)close(fd);
		return (-1);
	}

	for (i = 0; i < count; i++) {
		if (read_all(fd, noderec, MESH_MGR_NODEREC_LEN) != 0) {
			(void)close(fd);
			return (-1);
		}
		running = mgr_crc32(running, noderec, MESH_MGR_NODEREC_LEN);
		decode_node(&tmp.nodes[i], noderec);
	}
	(void)close(fd);

	crc = running;
	if (crc != stored_crc)
		return (-1);

	tmp.n_nodes = count;
	tmp.pending.active = 0;
	/* tmp.seq was restored from the persisted SEQ high-water mark. */
	*mgr = tmp;
	return (0);
}

/* ================================================================
 * MPROV3 - provisioning integration seam.
 * ================================================================ */

int
mesh_mgr_provision_prepare(struct mesh_mgr *mgr, const uint8_t uuid[16],
    uint8_t num_elements, struct mesh_prov_data *out_data)
{
	uint16_t addr;

	if (mgr == NULL || uuid == NULL || out_data == NULL || num_elements == 0)
		return (-1);
	if (mgr->pending.active)
		return (-1);
	if (mesh_mgr_find_by_uuid(mgr, uuid) != NULL)
		return (-1);
	if (mesh_mgr_alloc_unicast(mgr, num_elements, &addr) != 0)
		return (-1);

	memset(out_data, 0, sizeof(*out_data));
	memcpy(out_data->netkey, mgr->netkey, sizeof(out_data->netkey));
	out_data->netkey_index = mgr->netkey_index;
	out_data->flags = mgr->flags;
	out_data->iv_index = mgr->iv_index;
	out_data->unicast_addr = addr;

	memcpy(mgr->pending.uuid, uuid, sizeof(mgr->pending.uuid));
	mgr->pending.addr = addr;
	mgr->pending.num_elements = num_elements;
	mgr->pending.active = 1;
	return (0);
}

struct mesh_mgr_node *
mesh_mgr_provision_commit(struct mesh_mgr *mgr, const uint8_t devkey[16],
    uint8_t dev_num_elements, uint64_t prov_time)
{
	struct mesh_mgr_node *n;
	uint8_t nel;

	if (mgr == NULL || devkey == NULL || !mgr->pending.active)
		return (NULL);
	/*
	 * The unicast block was reserved from an operator-supplied element
	 * count before the device spoke.  If the device actually has MORE
	 * elements than reserved (NB-20), its element block would extend past
	 * the reservation and overlap the next allocation -- refuse rather than
	 * record a colliding node.  A device with 0 (no Capabilities seen) or
	 * fewer elements is recorded with the reserved size.
	 */
	if (dev_num_elements > mgr->pending.num_elements) {
		mgr->pending.active = 0;
		return (NULL);
	}
	nel = dev_num_elements != 0 ? dev_num_elements :
	    mgr->pending.num_elements;
	/*
	 * Clear the reservation BEFORE adding the node: the node is placed at
	 * the pending block, and range_used() rejects overlap with an active
	 * pending block (the import-collision guard), so leaving pending.active
	 * set here would make add_node see the block overlapping itself and
	 * fail.
	 */
	{
		uint16_t addr = mgr->pending.addr;
		uint8_t uuid[MESH_MGR_UUID_LEN];

		memcpy(uuid, mgr->pending.uuid, sizeof(uuid));
		mgr->pending.active = 0;
		n = mesh_mgr_add_node(mgr, uuid, addr, nel, devkey, prov_time);
	}
	return (n);
}

void
mesh_mgr_provision_abort(struct mesh_mgr *mgr)
{

	if (mgr != NULL)
		mgr->pending.active = 0;
}

/* ================================================================
 * MPROV4 - Config Client message builders.
 * ================================================================ */

int
mesh_mgr_cfg_appkey_add_pdu(const struct mesh_mgr *mgr, uint8_t *out,
    size_t *outlen)
{
	struct mesh_cfg_appkey in;

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	memset(&in, 0, sizeof(in));
	in.net_idx = mgr->netkey_index;
	in.app_idx = mgr->appkey_index;
	memcpy(in.key, mgr->appkey, sizeof(in.key));
	return (mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_ADD, &in, out,
	    outlen));
}

int
mesh_mgr_cfg_model_app_bind_pdu(const struct mesh_mgr *mgr, uint16_t elem_addr,
    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen)
{
	struct mesh_cfg_model_app in;

	if (mgr == NULL || model == NULL || out == NULL || outlen == NULL)
		return (-1);
	memset(&in, 0, sizeof(in));
	in.elem_addr = elem_addr;
	in.app_idx = mgr->appkey_index;
	in.model = *model;
	return (mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_BIND, &in, out,
	    outlen));
}

int
mesh_mgr_cfg_model_sub_add_pdu(const struct mesh_mgr *mgr, uint16_t elem_addr,
    uint16_t sub_addr, const struct mesh_cfg_model_id *model, uint8_t *out,
    size_t *outlen)
{
	struct mesh_cfg_model_sub in;

	if (mgr == NULL || model == NULL || out == NULL || outlen == NULL)
		return (-1);
	memset(&in, 0, sizeof(in));
	in.elem_addr = elem_addr;
	in.address = sub_addr;
	in.model = *model;
	return (mesh_cfg_model_sub_build(MESH_CFG_OP_MODEL_SUB_ADD, &in, out,
	    outlen));
}

int
mesh_mgr_cfg_model_pub_set_pdu(const struct mesh_mgr *mgr, uint16_t elem_addr,
    uint16_t pub_addr, uint8_t ttl, uint8_t period, uint8_t retransmit,
    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen)
{
	struct mesh_cfg_model_pub in;

	if (mgr == NULL || model == NULL || out == NULL || outlen == NULL)
		return (-1);
	memset(&in, 0, sizeof(in));
	in.elem_addr = elem_addr;
	in.pub_addr = pub_addr;
	in.app_idx = mgr->appkey_index;
	in.cred_flag = 0;
	in.ttl = ttl;
	in.period = period;
	in.retransmit = retransmit;
	in.model = *model;
	return (mesh_cfg_model_pub_set_build(&in, out, outlen));
}

/* ================================================================
 * MPROV4 - DevKey transport and Status parsing.
 * ================================================================ */

int
mesh_mgr_devkey_seal(struct mesh_mgr *mgr, const struct mesh_mgr_node *node,
    const uint8_t *access, size_t access_len, uint32_t *out_seq,
    uint8_t *out_upper, size_t *out_upper_len)
{
	uint32_t seq;

	if (mgr == NULL || node == NULL || access == NULL || out_upper == NULL ||
	    out_upper_len == NULL)
		return (-1);
	if (access_len == 0 || access_len > MESH_ACCESS_MAX)
		return (-1);

	seq = mgr->seq;
	if (seq > MESH_IV_SEQ_MAX)
		return (-1);
	/* AKF=0 (device key), szmic=0 (32-bit TransMIC), no virtual AAD. */
	if (mesh_upper_encrypt(node->devkey, 0, 0, seq, mgr->self_addr,
	    node->addr, mgr->iv_index, NULL, access, access_len, out_upper,
	    out_upper_len) != 0)
		return (-1);
	mgr->seq = seq + 1;
	if (out_seq != NULL)
		*out_seq = seq;
	return (0);
}

int
mesh_mgr_devkey_open(const struct mesh_mgr *mgr, const struct mesh_mgr_node *node,
    uint32_t seq, uint16_t src, uint16_t dst, const uint8_t *upper,
    size_t upper_len, uint8_t *access, size_t *access_len)
{

	if (mgr == NULL || node == NULL || upper == NULL || access == NULL ||
	    access_len == NULL)
		return (-1);
	return (mesh_upper_decrypt(node->devkey, 0, 0, seq, src, dst,
	    mgr->iv_index, NULL, upper, upper_len, access, access_len));
}

int
mesh_mgr_cfg_appkey_status_parse(const uint8_t *access, size_t len,
    uint8_t *status, uint16_t *net_idx, uint16_t *app_idx)
{

	return (mesh_cfg_appkey_status_parse(access, len, status, net_idx,
	    app_idx));
}

int
mesh_mgr_cfg_model_app_status_parse(const uint8_t *access, size_t len,
    uint8_t *status, struct mesh_cfg_model_app *out)
{

	return (mesh_cfg_model_app_status_parse(access, len, status, out));
}

/* ================================================================
 * Config Client - node discovery (Composition Data).
 * ================================================================ */

int
mesh_mgr_cfg_comp_get_pdu(const struct mesh_mgr *mgr, uint8_t page, uint8_t *out,
    size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_comp_get_build(page, out, outlen));
}

int
mesh_mgr_cfg_comp_status_apply(struct mesh_mgr_node *node, const uint8_t *access,
    size_t len)
{
	struct mesh_cfg_comp_status st;
	struct mesh_cfg_comp_page0 page0;

	if (node == NULL || access == NULL)
		return (-1);
	/* Parse the Status envelope (opcode 0x02 + Page + page data). */
	if (mesh_cfg_comp_status_parse(access, len, &st) != 0)
		return (-1);
	/* Only Page 0 carries the element/model layout this store understands. */
	if (st.page != 0)
		return (-1);
	/* Decode is fully length-gated (element/model counts bounded). */
	if (mesh_cfg_comp_page0_decode(st.data, st.data_len, &page0) != 0)
		return (-1);
	node->comp = page0;
	node->have_comp = 1;
	return (0);
}

/* ================================================================
 * Config Client - key management.
 * ================================================================ */

int
mesh_mgr_cfg_netkey_add_pdu(const struct mesh_mgr *mgr, uint16_t net_idx,
    const uint8_t key[16], uint8_t *out, size_t *outlen)
{
	struct mesh_cfg_netkey in;

	if (mgr == NULL || key == NULL || out == NULL || outlen == NULL)
		return (-1);
	memset(&in, 0, sizeof(in));
	in.net_idx = net_idx;
	memcpy(in.key, key, sizeof(in.key));
	return (mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_ADD, &in, out,
	    outlen));
}

int
mesh_mgr_cfg_netkey_status_parse(const uint8_t *access, size_t len,
    uint8_t *status, uint16_t *net_idx)
{

	return (mesh_cfg_netkey_status_parse(access, len, status, net_idx));
}

int
mesh_mgr_cfg_netkey_update_pdu(const struct mesh_mgr *mgr, uint16_t net_idx,
    const uint8_t key[16], uint8_t *out, size_t *outlen)
{
	struct mesh_cfg_netkey in;

	if (mgr == NULL || key == NULL || out == NULL || outlen == NULL)
		return (-1);
	memset(&in, 0, sizeof(in));
	in.net_idx = net_idx;
	memcpy(in.key, key, sizeof(in.key));
	return (mesh_cfg_netkey_add_build(MESH_CFG_OP_NETKEY_UPDATE, &in, out,
	    outlen));
}

int
mesh_mgr_cfg_netkey_delete_pdu(const struct mesh_mgr *mgr, uint16_t net_idx,
    uint8_t *out, size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_netkey_delete_build(net_idx, out, outlen));
}

int
mesh_mgr_cfg_kr_phase_get_pdu(const struct mesh_mgr *mgr, uint16_t net_idx,
    uint8_t *out, size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_kr_phase_get_build(net_idx, out, outlen));
}

int
mesh_mgr_cfg_kr_phase_set_pdu(const struct mesh_mgr *mgr, uint16_t net_idx,
    uint8_t transition, uint8_t *out, size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_kr_phase_set_build(net_idx, transition, out, outlen));
}

int
mesh_mgr_cfg_kr_phase_status_parse(const uint8_t *access, size_t len,
    uint8_t *status, uint16_t *net_idx, uint8_t *phase)
{

	return (mesh_cfg_kr_phase_status_parse(access, len, status, net_idx,
	    phase));
}

void
mesh_mgr_kr_begin(struct mesh_mgr *mgr)
{
	size_t i;

	if (mgr == NULL)
		return;
	for (i = 0; i < mgr->n_nodes; i++)
		mgr->nodes[i].kr_state = MESH_MGR_KR_DISTRIBUTING;
}

int
mesh_mgr_kr_ack(struct mesh_mgr *mgr, uint16_t addr)
{
	struct mesh_mgr_node *n;

	if (mgr == NULL)
		return (-1);
	n = mesh_mgr_find_by_addr(mgr, addr);
	if (n == NULL)
		return (-1);
	n->kr_state = MESH_MGR_KR_ACKED;
	return (0);
}

size_t
mesh_mgr_kr_pending(const struct mesh_mgr *mgr)
{
	size_t i, n = 0;

	if (mgr == NULL)
		return (0);
	for (i = 0; i < mgr->n_nodes; i++)
		if (mgr->nodes[i].kr_state == MESH_MGR_KR_DISTRIBUTING)
			n++;
	return (n);
}

int
mesh_mgr_cfg_appkey_update_pdu(const struct mesh_mgr *mgr, uint8_t *out,
    size_t *outlen)
{
	struct mesh_cfg_appkey in;

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	memset(&in, 0, sizeof(in));
	in.net_idx = mgr->netkey_index;
	in.app_idx = mgr->appkey_index;
	/*
	 * A Key Refresh Phase-1 AppKey Update distributes the NEW AppKey, not the
	 * current one; re-sending the in-use key is rejected by conformant nodes
	 * with Cannot Update (MshPRT_v1.1 Section 3.11.4).  Mirror the NetKey
	 * Update path, which carries the new key.
	 */
	memcpy(in.key, mgr->appkey_new, sizeof(in.key));
	return (mesh_cfg_appkey_add_build(MESH_CFG_OP_APPKEY_UPDATE, &in, out,
	    outlen));
}

int
mesh_mgr_appkey_promote(struct mesh_mgr *mgr, uint8_t out_appkey[16])
{

	if (mgr == NULL)
		return (-1);
	/*
	 * Key Refresh Phase-3 completion for the primary AppKey (MshPRT_v1.1
	 * Section 3.11.4).  Once every node has replaced its AppKey via Config
	 * AppKey Update, the staged Phase-1 key becomes the current key and a
	 * fresh Phase-1 key is minted for the next rotation.  Without this the
	 * manager keeps handing the revoked key to AppKey Add and re-distributes
	 * an already-installed key on the next AppKey Update (C6-H3).
	 */
	memcpy(mgr->appkey, mgr->appkey_new, sizeof(mgr->appkey));
	if (RAND_bytes(mgr->appkey_new, sizeof(mgr->appkey_new)) != 1)
		return (-1);
	if (out_appkey != NULL)
		memcpy(out_appkey, mgr->appkey, sizeof(mgr->appkey));
	return (0);
}

int
mesh_mgr_cfg_appkey_delete_pdu(const struct mesh_mgr *mgr, uint8_t *out,
    size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_appkey_delete_build(mgr->netkey_index, mgr->appkey_index,
	    out, outlen));
}

int
mesh_mgr_cfg_appkey_get_pdu(const struct mesh_mgr *mgr, uint16_t net_idx,
    uint8_t *out, size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_appkey_get_build(net_idx, out, outlen));
}

int
mesh_mgr_cfg_appkey_list_parse(const uint8_t *access, size_t len,
    uint8_t *status, uint16_t *net_idx, uint16_t *app_idx, size_t max,
    size_t *n)
{

	return (mesh_cfg_appkey_list_parse(access, len, status, net_idx, app_idx,
	    max, n));
}

/* ================================================================
 * Config Client - node-wide state.
 * ================================================================ */

int
mesh_mgr_cfg_u8_state_get_pdu(const struct mesh_mgr *mgr, uint32_t get_opcode,
    uint8_t *out, size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_empty_build(get_opcode, out, outlen));
}

int
mesh_mgr_cfg_u8_state_set_pdu(const struct mesh_mgr *mgr, uint32_t set_opcode,
    uint8_t value, uint8_t *out, size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_u8_state_build(set_opcode, value, out, outlen));
}

int
mesh_mgr_cfg_u8_state_status_parse(const uint8_t *access, size_t len,
    uint32_t *opcode, uint8_t *value)
{

	return (mesh_cfg_u8_state_parse(access, len, opcode, value));
}

int
mesh_mgr_cfg_relay_get_pdu(const struct mesh_mgr *mgr, uint8_t *out,
    size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_empty_build(MESH_CFG_OP_RELAY_GET, out, outlen));
}

int
mesh_mgr_cfg_relay_set_pdu(const struct mesh_mgr *mgr, uint8_t relay,
    uint8_t retransmit, uint8_t *out, size_t *outlen)
{
	struct mesh_cfg_relay in;

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	memset(&in, 0, sizeof(in));
	in.relay = relay;
	in.retransmit = retransmit;
	return (mesh_cfg_relay_set_build(MESH_CFG_OP_RELAY_SET, &in, out, outlen));
}

int
mesh_mgr_cfg_relay_status_parse(const uint8_t *access, size_t len,
    uint8_t *relay, uint8_t *retransmit)
{
	struct mesh_cfg_relay r;
	uint32_t op;

	if (mesh_cfg_relay_set_parse(access, len, &op, &r) != 0)
		return (-1);
	if (op != MESH_CFG_OP_RELAY_STATUS)
		return (-1);
	if (relay != NULL)
		*relay = r.relay;
	if (retransmit != NULL)
		*retransmit = r.retransmit;
	return (0);
}

int
mesh_mgr_cfg_net_transmit_get_pdu(const struct mesh_mgr *mgr, uint8_t *out,
    size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_net_transmit_get_build(out, outlen));
}

int
mesh_mgr_cfg_net_transmit_set_pdu(const struct mesh_mgr *mgr, uint8_t count,
    uint8_t interval_steps, uint8_t *out, size_t *outlen)
{
	struct mesh_cfg_net_transmit in;

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	memset(&in, 0, sizeof(in));
	in.count = count;
	in.interval_steps = interval_steps;
	return (mesh_cfg_net_transmit_set_build(MESH_CFG_OP_NET_TRANSMIT_SET, &in,
	    out, outlen));
}

int
mesh_mgr_cfg_net_transmit_status_parse(const uint8_t *access, size_t len,
    uint8_t *count, uint8_t *interval_steps)
{
	struct mesh_cfg_net_transmit nt;
	uint32_t op;

	if (mesh_cfg_net_transmit_set_parse(access, len, &op, &nt) != 0)
		return (-1);
	if (op != MESH_CFG_OP_NET_TRANSMIT_STATUS)
		return (-1);
	if (count != NULL)
		*count = nt.count;
	if (interval_steps != NULL)
		*interval_steps = nt.interval_steps;
	return (0);
}

/* ================================================================
 * Config Client - binding / subscription removal + Node Reset.
 * ================================================================ */

int
mesh_mgr_cfg_model_app_unbind_pdu(const struct mesh_mgr *mgr, uint16_t elem_addr,
    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen)
{
	struct mesh_cfg_model_app in;

	if (mgr == NULL || model == NULL || out == NULL || outlen == NULL)
		return (-1);
	memset(&in, 0, sizeof(in));
	in.elem_addr = elem_addr;
	in.app_idx = mgr->appkey_index;
	in.model = *model;
	return (mesh_cfg_model_app_build(MESH_CFG_OP_MODEL_APP_UNBIND, &in, out,
	    outlen));
}

int
mesh_mgr_cfg_model_sub_delete_pdu(const struct mesh_mgr *mgr, uint16_t elem_addr,
    uint16_t sub_addr, const struct mesh_cfg_model_id *model, uint8_t *out,
    size_t *outlen)
{
	struct mesh_cfg_model_sub in;

	if (mgr == NULL || model == NULL || out == NULL || outlen == NULL)
		return (-1);
	memset(&in, 0, sizeof(in));
	in.elem_addr = elem_addr;
	in.address = sub_addr;
	in.model = *model;
	return (mesh_cfg_model_sub_build(MESH_CFG_OP_MODEL_SUB_DELETE, &in, out,
	    outlen));
}

int
mesh_mgr_cfg_model_sub_overwrite_pdu(const struct mesh_mgr *mgr,
    uint16_t elem_addr, uint16_t sub_addr, const struct mesh_cfg_model_id *model,
    uint8_t *out, size_t *outlen)
{
	struct mesh_cfg_model_sub in;

	if (mgr == NULL || model == NULL || out == NULL || outlen == NULL)
		return (-1);
	memset(&in, 0, sizeof(in));
	in.elem_addr = elem_addr;
	in.address = sub_addr;
	in.model = *model;
	return (mesh_cfg_model_sub_build(MESH_CFG_OP_MODEL_SUB_OVERWRITE, &in, out,
	    outlen));
}

int
mesh_mgr_cfg_model_sub_delete_all_pdu(const struct mesh_mgr *mgr,
    uint16_t elem_addr, const struct mesh_cfg_model_id *model, uint8_t *out,
    size_t *outlen)
{

	if (mgr == NULL || model == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_model_sub_del_all_build(elem_addr, model, out, outlen));
}

int
mesh_mgr_cfg_model_sub_status_parse(const uint8_t *access, size_t len,
    uint8_t *status, struct mesh_cfg_model_sub *out)
{

	return (mesh_cfg_model_sub_status_parse(access, len, status, out));
}

int
mesh_mgr_cfg_node_reset_pdu(const struct mesh_mgr *mgr, uint8_t *out,
    size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_node_reset_build(out, outlen));
}

int
mesh_mgr_cfg_node_reset_status_parse(const uint8_t *access, size_t len)
{
	struct mesh_access_pdu ap;

	if (access == NULL)
		return (-1);
	if (mesh_access_pdu_parse(access, len, &ap) != 0)
		return (-1);
	/* Node Reset Status (0x804A) carries no parameters. */
	if (ap.opcode != MESH_CFG_OP_NODE_RESET_STATUS || ap.params_len != 0)
		return (-1);
	return (0);
}

/* ================================================================
 * Config Client - virtual-address publication / subscription.
 * ================================================================ */

int
mesh_mgr_label_to_virtual_addr(const uint8_t label[16], uint16_t *va)
{

	if (label == NULL || va == NULL)
		return (-1);
	return (mesh_virtual_addr(label, va));
}

int
mesh_mgr_cfg_model_pub_va_set_pdu(const struct mesh_mgr *mgr, uint16_t elem_addr,
    const uint8_t label[16], uint8_t ttl, uint8_t period, uint8_t retransmit,
    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen)
{
	struct mesh_cfg_model_pub_va in;

	if (mgr == NULL || label == NULL || model == NULL || out == NULL ||
	    outlen == NULL)
		return (-1);
	memset(&in, 0, sizeof(in));
	in.elem_addr = elem_addr;
	memcpy(in.label, label, sizeof(in.label));
	in.app_idx = mgr->appkey_index;
	in.cred_flag = 0;
	in.ttl = ttl;
	in.period = period;
	in.retransmit = retransmit;
	in.model = *model;
	return (mesh_cfg_model_pub_va_set_build(&in, out, outlen));
}

/* Shared builder for the three virtual-address subscription verbs. */
static int
mgr_model_sub_va_pdu(const struct mesh_mgr *mgr, uint32_t opcode,
    uint16_t elem_addr, const uint8_t label[16],
    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen)
{
	struct mesh_cfg_model_sub_va in;

	if (mgr == NULL || label == NULL || model == NULL || out == NULL ||
	    outlen == NULL)
		return (-1);
	memset(&in, 0, sizeof(in));
	in.elem_addr = elem_addr;
	memcpy(in.label, label, sizeof(in.label));
	in.model = *model;
	return (mesh_cfg_model_sub_va_build(opcode, &in, out, outlen));
}

int
mesh_mgr_cfg_model_sub_va_add_pdu(const struct mesh_mgr *mgr, uint16_t elem_addr,
    const uint8_t label[16], const struct mesh_cfg_model_id *model, uint8_t *out,
    size_t *outlen)
{

	return (mgr_model_sub_va_pdu(mgr, MESH_CFG_OP_MODEL_SUB_VA_ADD, elem_addr,
	    label, model, out, outlen));
}

int
mesh_mgr_cfg_model_sub_va_delete_pdu(const struct mesh_mgr *mgr,
    uint16_t elem_addr, const uint8_t label[16],
    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen)
{

	return (mgr_model_sub_va_pdu(mgr, MESH_CFG_OP_MODEL_SUB_VA_DELETE,
	    elem_addr, label, model, out, outlen));
}

int
mesh_mgr_cfg_model_sub_va_overwrite_pdu(const struct mesh_mgr *mgr,
    uint16_t elem_addr, const uint8_t label[16],
    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen)
{

	return (mgr_model_sub_va_pdu(mgr, MESH_CFG_OP_MODEL_SUB_VA_OVERWRITE,
	    elem_addr, label, model, out, outlen));
}

int
mesh_mgr_cfg_model_pub_get_pdu(const struct mesh_mgr *mgr, uint16_t elem_addr,
    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen)
{

	if (mgr == NULL || model == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_model_pub_get_build(elem_addr, model, out, outlen));
}

int
mesh_mgr_cfg_model_pub_status_parse(const uint8_t *access, size_t len,
    uint8_t *status, struct mesh_cfg_model_pub *out)
{

	return (mesh_cfg_model_pub_status_parse(access, len, status, out));
}

int
mesh_mgr_cfg_model_sub_get_pdu(const struct mesh_mgr *mgr, uint16_t elem_addr,
    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen)
{
	uint32_t opcode;

	if (mgr == NULL || model == NULL || out == NULL || outlen == NULL)
		return (-1);
	/* Vendor models use the vendor Get opcode; SIG models the SIG one. */
	opcode = model->vendor ? MESH_CFG_OP_VND_MODEL_SUB_GET :
	    MESH_CFG_OP_SIG_MODEL_SUB_GET;
	return (mesh_cfg_model_sub_get_build(opcode, elem_addr, model, out,
	    outlen));
}

int
mesh_mgr_cfg_model_sub_list_parse(const uint8_t *access, size_t len,
    uint8_t *status, uint16_t *elem_addr, struct mesh_cfg_model_id *model,
    uint16_t *addrs, size_t max, size_t *n)
{
	uint32_t opcode;

	if (mesh_cfg_model_sub_list_parse(access, len, &opcode, status, elem_addr,
	    model, addrs, max, n) != 0)
		return (-1);
	if (opcode != MESH_CFG_OP_SIG_MODEL_SUB_LIST &&
	    opcode != MESH_CFG_OP_VND_MODEL_SUB_LIST)
		return (-1);
	return (0);
}

int
mesh_mgr_cfg_model_app_get_pdu(const struct mesh_mgr *mgr, uint16_t elem_addr,
    const struct mesh_cfg_model_id *model, uint8_t *out, size_t *outlen)
{
	uint32_t opcode;

	if (mgr == NULL || model == NULL || out == NULL || outlen == NULL)
		return (-1);
	opcode = model->vendor ? MESH_CFG_OP_VND_MODEL_APP_GET :
	    MESH_CFG_OP_SIG_MODEL_APP_GET;
	return (mesh_cfg_model_app_get_build(opcode, elem_addr, model, out,
	    outlen));
}

int
mesh_mgr_cfg_model_app_list_parse(const uint8_t *access, size_t len,
    uint8_t *status, uint16_t *elem_addr, struct mesh_cfg_model_id *model,
    uint16_t *app_idx, size_t max, size_t *n)
{
	uint32_t opcode;

	if (mesh_cfg_model_app_list_parse(access, len, &opcode, status, elem_addr,
	    model, app_idx, max, n) != 0)
		return (-1);
	if (opcode != MESH_CFG_OP_SIG_MODEL_APP_LIST &&
	    opcode != MESH_CFG_OP_VND_MODEL_APP_LIST)
		return (-1);
	return (0);
}

/* ================================================================
 * Config Client - Node Identity and LPN PollTimeout.
 * ================================================================ */

int
mesh_mgr_cfg_node_identity_get_pdu(const struct mesh_mgr *mgr, uint16_t net_idx,
    uint8_t *out, size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_node_identity_get_build(net_idx, out, outlen));
}

int
mesh_mgr_cfg_node_identity_set_pdu(const struct mesh_mgr *mgr, uint16_t net_idx,
    uint8_t identity, uint8_t *out, size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_node_identity_set_build(net_idx, identity, out, outlen));
}

int
mesh_mgr_cfg_node_identity_status_parse(const uint8_t *access, size_t len,
    uint8_t *status, uint16_t *net_idx, uint8_t *identity)
{

	return (mesh_cfg_node_identity_status_parse(access, len, status, net_idx,
	    identity));
}

int
mesh_mgr_cfg_lpn_polltimeout_get_pdu(const struct mesh_mgr *mgr,
    uint16_t lpn_addr, uint8_t *out, size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_lpn_polltimeout_get_build(lpn_addr, out, outlen));
}

int
mesh_mgr_cfg_lpn_polltimeout_status_parse(const uint8_t *access, size_t len,
    uint16_t *lpn_addr, uint32_t *poll_timeout)
{

	return (mesh_cfg_lpn_polltimeout_status_parse(access, len, lpn_addr,
	    poll_timeout));
}

/* ================================================================
 * Config Client - Heartbeat publication / subscription.
 * ================================================================ */

int
mesh_mgr_cfg_hb_pub_get_pdu(const struct mesh_mgr *mgr, uint8_t *out,
    size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_hb_pub_get_build(out, outlen));
}

int
mesh_mgr_cfg_hb_pub_set_pdu(const struct mesh_mgr *mgr,
    const struct mesh_hb_pub *pub, uint8_t *out, size_t *outlen)
{

	if (mgr == NULL || pub == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_hb_pub_set_build(pub, out, outlen));
}

int
mesh_mgr_cfg_hb_pub_status_parse(const uint8_t *access, size_t len,
    uint8_t *status, struct mesh_hb_pub *out)
{

	return (mesh_hb_pub_status_parse(access, len, status, out));
}

int
mesh_mgr_cfg_hb_sub_get_pdu(const struct mesh_mgr *mgr, uint8_t *out,
    size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_hb_sub_get_build(out, outlen));
}

int
mesh_mgr_cfg_hb_sub_set_pdu(const struct mesh_mgr *mgr, uint16_t src,
    uint16_t dst, uint8_t period_log, uint8_t *out, size_t *outlen)
{
	struct mesh_hb_sub_set in;

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	memset(&in, 0, sizeof(in));
	in.src = src;
	in.dst = dst;
	in.period_log = period_log;
	return (mesh_hb_sub_set_build(&in, out, outlen));
}

int
mesh_mgr_cfg_hb_sub_status_parse(const uint8_t *access, size_t len,
    struct mesh_hb_sub_status *out)
{

	return (mesh_hb_sub_status_parse(access, len, out));
}

/* ================================================================
 * Config Client - Mesh Protocol 1.1 node states.
 * ================================================================ */

int
mesh_mgr_cfg_sar_tx_get_pdu(const struct mesh_mgr *mgr, uint8_t *out,
    size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_sar_tx_get_build(out, outlen));
}

int
mesh_mgr_cfg_sar_tx_set_pdu(const struct mesh_mgr *mgr,
    const struct mesh_cfg_sar_transmitter *in, uint8_t *out, size_t *outlen)
{

	if (mgr == NULL || in == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_sar_tx_build(MESH_CFG_OP_SAR_TRANSMITTER_SET, in, out,
	    outlen));
}

int
mesh_mgr_cfg_sar_tx_status_parse(const uint8_t *access, size_t len,
    struct mesh_cfg_sar_transmitter *out)
{
	uint32_t opcode;

	if (mesh_cfg_sar_tx_parse(access, len, &opcode, out) != 0)
		return (-1);
	if (opcode != MESH_CFG_OP_SAR_TRANSMITTER_STATUS)
		return (-1);
	return (0);
}

int
mesh_mgr_cfg_sar_rx_get_pdu(const struct mesh_mgr *mgr, uint8_t *out,
    size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_sar_rx_get_build(out, outlen));
}

int
mesh_mgr_cfg_sar_rx_set_pdu(const struct mesh_mgr *mgr,
    const struct mesh_cfg_sar_receiver *in, uint8_t *out, size_t *outlen)
{

	if (mgr == NULL || in == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_sar_rx_build(MESH_CFG_OP_SAR_RECEIVER_SET, in, out,
	    outlen));
}

int
mesh_mgr_cfg_sar_rx_status_parse(const uint8_t *access, size_t len,
    struct mesh_cfg_sar_receiver *out)
{
	uint32_t opcode;

	if (mesh_cfg_sar_rx_parse(access, len, &opcode, out) != 0)
		return (-1);
	if (opcode != MESH_CFG_OP_SAR_RECEIVER_STATUS)
		return (-1);
	return (0);
}

int
mesh_mgr_cfg_od_priv_proxy_get_pdu(const struct mesh_mgr *mgr, uint8_t *out,
    size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_od_priv_proxy_get_build(out, outlen));
}

int
mesh_mgr_cfg_od_priv_proxy_set_pdu(const struct mesh_mgr *mgr, uint8_t value,
    uint8_t *out, size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_od_priv_proxy_build(MESH_CFG_OP_OD_PRIV_PROXY_SET, value,
	    out, outlen));
}

int
mesh_mgr_cfg_od_priv_proxy_status_parse(const uint8_t *access, size_t len,
    uint8_t *value)
{
	uint32_t opcode;

	if (mesh_cfg_od_priv_proxy_parse(access, len, &opcode, value) != 0)
		return (-1);
	if (opcode != MESH_CFG_OP_OD_PRIV_PROXY_STATUS)
		return (-1);
	return (0);
}

int
mesh_mgr_cfg_priv_beacon_get_pdu(const struct mesh_mgr *mgr, uint8_t *out,
    size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_priv_beacon_get_build(out, outlen));
}

int
mesh_mgr_cfg_priv_beacon_set_pdu(const struct mesh_mgr *mgr,
    const struct mesh_cfg_priv_beacon *in, uint8_t *out, size_t *outlen)
{

	if (mgr == NULL || in == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_priv_beacon_set_build(in, out, outlen));
}

int
mesh_mgr_cfg_priv_beacon_status_parse(const uint8_t *access, size_t len,
    struct mesh_cfg_priv_beacon *out)
{

	return (mesh_cfg_priv_beacon_status_parse(access, len, out));
}

int
mesh_mgr_cfg_priv_gatt_proxy_get_pdu(const struct mesh_mgr *mgr, uint8_t *out,
    size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_priv_gatt_proxy_get_build(out, outlen));
}

int
mesh_mgr_cfg_priv_gatt_proxy_set_pdu(const struct mesh_mgr *mgr, uint8_t value,
    uint8_t *out, size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_priv_gatt_proxy_build(MESH_CFG_OP_PRIV_GATT_PROXY_SET,
	    value, out, outlen));
}

int
mesh_mgr_cfg_priv_gatt_proxy_status_parse(const uint8_t *access, size_t len,
    uint8_t *value)
{
	uint32_t opcode;

	if (mesh_cfg_priv_gatt_proxy_parse(access, len, &opcode, value) != 0)
		return (-1);
	if (opcode != MESH_CFG_OP_PRIV_GATT_PROXY_STATUS)
		return (-1);
	return (0);
}

int
mesh_mgr_cfg_priv_node_identity_get_pdu(const struct mesh_mgr *mgr,
    uint16_t net_idx, uint8_t *out, size_t *outlen)
{

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	return (mesh_cfg_priv_node_identity_get_build(net_idx, out, outlen));
}

int
mesh_mgr_cfg_priv_node_identity_set_pdu(const struct mesh_mgr *mgr,
    uint16_t net_idx, uint8_t identity, uint8_t *out, size_t *outlen)
{
	struct mesh_cfg_priv_node_identity in;

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	memset(&in, 0, sizeof(in));
	in.net_idx = net_idx;
	in.identity = identity;
	return (mesh_cfg_priv_node_identity_set_build(&in, out, outlen));
}

int
mesh_mgr_cfg_priv_node_identity_status_parse(const uint8_t *access, size_t len,
    uint8_t *status, struct mesh_cfg_priv_node_identity *out)
{

	return (mesh_cfg_priv_node_identity_status_parse(access, len, status,
	    out));
}

int
mesh_mgr_cfg_lcd_get_pdu(const struct mesh_mgr *mgr, uint8_t page,
    uint16_t offset, uint8_t *out, size_t *outlen)
{
	struct mesh_cfg_lcd_get in;

	if (mgr == NULL || out == NULL || outlen == NULL)
		return (-1);
	memset(&in, 0, sizeof(in));
	in.page = page;
	in.offset = offset;
	return (mesh_cfg_lcd_get_build(MESH_CFG_OP_LARGE_COMP_DATA_GET, &in, out,
	    outlen));
}

int
mesh_mgr_cfg_lcd_status_parse(const uint8_t *access, size_t len,
    struct mesh_cfg_lcd_status *out)
{
	uint32_t opcode;

	if (mesh_cfg_lcd_status_parse(access, len, &opcode, out) != 0)
		return (-1);
	if (opcode != MESH_CFG_OP_LARGE_COMP_DATA_STATUS)
		return (-1);
	return (0);
}

/* ================================================================
 * Config Client transaction: request -> Status correlation + retry.
 * ================================================================ */

int
mesh_mgr_txn_begin(struct mesh_mgr *mgr, struct mesh_mgr_txn *t,
    const struct mesh_mgr_node *node, const uint8_t *req, size_t req_len,
    uint32_t expect_opcode, uint64_t now, uint64_t interval,
    unsigned max_attempts, uint8_t *out_upper, size_t *out_upper_len,
    uint32_t *out_seq)
{
	uint32_t seq;

	if (mgr == NULL || t == NULL || node == NULL || req == NULL ||
	    out_upper == NULL || out_upper_len == NULL)
		return (-1);
	if (req_len == 0 || req_len > sizeof(t->req) || max_attempts == 0)
		return (-1);

	memset(t, 0, sizeof(*t));
	memcpy(t->req, req, req_len);
	t->req_len = req_len;
	t->expect_opcode = expect_opcode;
	t->node_addr = node->addr;
	t->interval = interval;
	t->max_attempts = max_attempts;

	/* First transmission (attempt 1). */
	if (mesh_mgr_devkey_seal(mgr, node, t->req, t->req_len, &seq, out_upper,
	    out_upper_len) != 0)
		return (-1);
	t->last_seq = seq;
	t->attempts = 1;
	t->deadline = now + interval;
	t->state = MESH_MGR_TXN_WAITING;
	if (out_seq != NULL)
		*out_seq = seq;
	return (0);
}

int
mesh_mgr_txn_rx(struct mesh_mgr_txn *t, const struct mesh_mgr *mgr,
    const struct mesh_mgr_node *node, uint32_t seq, uint16_t src, uint16_t dst,
    const uint8_t *upper, size_t upper_len)
{
	uint8_t access[MESH_ACCESS_MAX];
	size_t alen = sizeof(access);
	struct mesh_access_pdu ap;

	if (t == NULL || mgr == NULL || node == NULL || upper == NULL)
		return (-1);
	if (t->state != MESH_MGR_TXN_WAITING)
		return (0);		/* terminal or idle: ignore (no double-apply) */
	/* The reply must come from the node this transaction targets. */
	if (src != t->node_addr)
		return (0);
	/* A wrong DevKey / wrong nonce simply fails the MIC and is ignored. */
	if (mesh_mgr_devkey_open(mgr, node, seq, src, dst, upper, upper_len,
	    access, &alen) != 0)
		return (0);
	if (mesh_access_pdu_parse(access, alen, &ap) != 0)
		return (0);
	if (ap.opcode != t->expect_opcode)
		return (0);		/* not the Status we are correlating on */

	memcpy(t->status, access, alen);
	t->status_len = alen;
	t->state = MESH_MGR_TXN_COMPLETE;
	return (1);
}

int
mesh_mgr_txn_tick(struct mesh_mgr *mgr, struct mesh_mgr_txn *t,
    const struct mesh_mgr_node *node, uint64_t now, uint8_t *out_upper,
    size_t *out_upper_len, uint32_t *out_seq)
{
	uint32_t seq;

	if (mgr == NULL || t == NULL || node == NULL || out_upper == NULL ||
	    out_upper_len == NULL)
		return (-1);
	if (t->state != MESH_MGR_TXN_WAITING)
		return (0);		/* already complete / timed out / idle */
	if (now < t->deadline)
		return (0);		/* retry not due yet */

	/* Retry due: stop if the bounded budget is spent (cannot loop forever). */
	if (t->attempts >= t->max_attempts) {
		t->state = MESH_MGR_TXN_TIMEOUT;
		return (0);
	}

	/* Retransmit with a fresh sequence number (a new nonce for the peer). */
	if (mesh_mgr_devkey_seal(mgr, node, t->req, t->req_len, &seq, out_upper,
	    out_upper_len) != 0)
		return (-1);
	t->last_seq = seq;
	t->attempts++;
	t->deadline = now + t->interval;
	if (out_seq != NULL)
		*out_seq = seq;
	return (1);
}
