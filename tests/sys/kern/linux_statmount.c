/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * listmount(2)/statmount(2): enumerate mounts and query one.  listmount from
 * LSMT_ROOT returns >=1 mount id; statmount fills fs_type/mnt_point/sb_source
 * strings and the basic sb/mnt fields for a given id, with the root mount's
 * point being "/".  Validation: bad flags (EINVAL), a too-small buffer
 * (EOVERFLOW), a nonexistent id (ENOENT), a short mnt_id_req (EINVAL), and
 * reverse listing.  Exit status = failed check number.
 */
#include "linux_test.h"

#define	SYS_statmount		457
#define	SYS_listmount		458
#define	LSMT_ROOT		0xffffffffffffffffULL
#define	LISTMOUNT_REVERSE	1
#define	ST_FS_TYPE		0x20
#define	ST_MNT_POINT		0x10
#define	ST_MNT_ROOT		0x08
#define	ST_SB_SOURCE		0x200
#define	ST_SB_BASIC		0x01
#define	ST_MNT_BASIC		0x02
#define	EOVERFLOW		75

typedef unsigned long long u64_;
typedef unsigned int u32_;

struct mnt_id_req { u32_ size; u32_ spare; u64_ mnt_id, param, mnt_ns_id; };
struct statmount {
	u32_ size, mnt_opts; u64_ mask; u32_ sb_dev_major, sb_dev_minor;
	u64_ sb_magic; u32_ sb_flags, fs_type; u64_ mnt_id, mnt_parent_id;
	u32_ mnt_id_old, mnt_parent_id_old; u64_ mnt_attr, mnt_propagation,
	    mnt_peer_group, mnt_master, propagate_from; u32_ mnt_root, mnt_point;
	u64_ mnt_ns_id; u32_ fs_subtype, sb_source, opt_num, opt_array,
	    opt_sec_num, opt_sec_array; u64_ supported_mask; u32_ mnt_uidmap_num,
	    mnt_uidmap, mnt_gidmap_num, mnt_gidmap; u64_ __spare2[43]; char str[];
};

static long
listmount(struct mnt_id_req *r, u64_ *ids, long nr, long flags)
{

	return (sys4(SYS_listmount, (long)r, (long)ids, nr, flags));
}

static long
statmount(struct mnt_id_req *r, void *buf, long bufsize, long flags)
{

	return (sys4(SYS_statmount, (long)r, (long)buf, bufsize, flags));
}

static const char *
smstr(struct statmount *sm, u32_ off)
{

	return ((const char *)sm + sizeof(*sm) + off);
}

static int
test(int argc __attribute__((unused)), char **argv __attribute__((unused)),
    char **envp __attribute__((unused)))
{
	static u64_ ids[256], rids[256];
	static char sbuf[8192];
	struct mnt_id_req req;
	struct statmount *sm = (struct statmount *)sbuf;
	long n, rn, i, r;
	u64_ rootid;

	/* 1: listmount(LSMT_ROOT) returns at least the root filesystem. */
	xmemset(&req, 0, sizeof(req));
	req.size = 32; req.mnt_id = LSMT_ROOT; req.param = 0;
	n = listmount(&req, ids, 256, 0);
	if (n < 1) { msgnum("listmount root ", n); return (1); }
	for (i = 0; i < n; i++) if (ids[i] == 0) return (1);

	/* 2: bad flags -> EINVAL. */
	if (listmount(&req, ids, 256, 0x2) != -EINVAL) return (2);
	/* 3: a short mnt_id_req -> EINVAL. */
	{ struct mnt_id_req bad; xmemset(&bad, 0, sizeof(bad)); bad.size = 8;
	  if (listmount(&bad, ids, 256, 0) != -EINVAL) return (3); }

	/* 4-7: statmount each listed id; find the root ("/") mount. */
	rootid = 0;
	for (i = 0; i < n; i++) {
		xmemset(&req, 0, sizeof(req));
		req.size = 32; req.mnt_id = ids[i];
		req.param = ST_FS_TYPE | ST_MNT_POINT | ST_MNT_ROOT |
		    ST_SB_SOURCE | ST_SB_BASIC | ST_MNT_BASIC;
		r = statmount(&req, sbuf, sizeof(sbuf), 0);
		if (r != 0) { msgnum("statmount ", r); return (4); }
		if (sm->size < sizeof(*sm)) return (4);
		if ((sm->mask & ST_MNT_BASIC) == 0 || sm->mnt_id != ids[i]) return (5);
		if ((sm->mask & ST_FS_TYPE) == 0 || smstr(sm, sm->fs_type)[0] == '\0') return (6);
		if ((sm->mask & ST_MNT_POINT) == 0) return (7);
		if (smstr(sm, sm->mnt_point)[0] == '/' &&
		    smstr(sm, sm->mnt_point)[1] == '\0')
			rootid = ids[i];
	}
	if (rootid == 0) return (7);		/* no "/" mount found */

	/* 8: statmount the root: mnt_root is "/" and supported_mask is set. */
	xmemset(&req, 0, sizeof(req));
	req.size = 32; req.mnt_id = rootid;
	req.param = ST_MNT_ROOT | ST_MNT_POINT | ST_FS_TYPE;
	if (statmount(&req, sbuf, sizeof(sbuf), 0) != 0) return (8);
	if (smstr(sm, sm->mnt_root)[0] != '/') return (8);
	if (sm->supported_mask == 0) return (8);

	/* 9: a too-small buffer -> EOVERFLOW. */
	req.param = ST_FS_TYPE;
	if (statmount(&req, sbuf, 64, 0) != -EOVERFLOW) return (9);
	/* 10: a nonexistent mount id -> ENOENT. */
	req.mnt_id = 0x123456789aULL;
	if (statmount(&req, sbuf, sizeof(sbuf), 0) != -ENOENT) return (10);

	/* 11: reverse listing returns the same count. */
	xmemset(&req, 0, sizeof(req));
	req.size = 32; req.mnt_id = LSMT_ROOT;
	rn = listmount(&req, rids, 256, LISTMOUNT_REVERSE);
	if (rn != n) { msgnum("reverse count ", rn); return (11); }

	/* 12: listing children of the root id returns nested mounts (>=0) and
	 * none equal to the root itself. */
	xmemset(&req, 0, sizeof(req));
	req.size = 32; req.mnt_id = rootid;
	rn = listmount(&req, rids, 256, 0);
	if (rn < 0) { msgnum("children ", rn); return (12); }
	for (i = 0; i < rn; i++) if (rids[i] == rootid) return (12);

	/* 13: param-cursor pagination reassembles the full list one id at a
	 * time and matches the single-shot enumeration exactly. */
	if (n >= 2) {
		u64_ cursor = 0;
		long got = 0;

		for (;;) {
			u64_ one[1];
			long m;

			xmemset(&req, 0, sizeof(req));
			req.size = 32; req.mnt_id = LSMT_ROOT; req.param = cursor;
			m = listmount(&req, one, 1, 0);
			if (m < 0) { msgnum("paginate ", m); return (13); }
			if (m == 0) break;
			if (got >= 256 || one[0] != ids[got]) { msgnum("paginate mismatch at ", got); return (13); }
			cursor = one[0];
			got++;
		}
		if (got != n) { msgnum("paginate total ", got); return (13); }
	}
	return (0);
}
