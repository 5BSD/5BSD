/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Falsification tests for lib9p's on-the-wire marshalling (pack.c).  These
 * drive the production packer/unpacker through l9p_pufcall()/l9p_pudirent()
 * and assert byte-exact round trips.  They cover gaps that four prior
 * regressions passed through undetected:
 *
 *   - l9p_pu64() must move all eight bytes of a 64-bit field (the byteswap
 *     branch read only four; the fault is dormant on little-endian hosts,
 *     so the round trip here is the big-endian regression guard and, on any
 *     host, proves full-width fidelity through the public entry point).
 *   - qid.type bits (QTDIR/QTSYMLINK/QTAUTH/QTAPPEND) must survive a round
 *     trip; a truncated qid.type silently mistypes files to the client.
 *   - l9p_puqids() must reject an attacker-supplied nwqid larger than
 *     L9P_MAX_WELEM instead of writing past the fixed wqid[] array.
 *   - .L (Rlerror) and .u/.legacy (Rerror) use different error encodings.
 */

#include <sys/types.h>

#include <atf-c.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fcall.h"
#include "lib9p.h"

/*
 * Pack "in" into buf, then unpack the resulting bytes into "out".  Returns
 * the encoded length, or -1 if either direction fails.  On success the
 * caller owns any strings allocated into "out" (free with l9p_freefcall).
 */
static ssize_t
roundtrip(union l9p_fcall *in, union l9p_fcall *out, enum l9p_version version,
    uint8_t *buf, size_t buflen)
{
	struct l9p_message msg;

	memset(&msg, 0, sizeof(msg));
	msg.lm_mode = L9P_PACK;
	msg.lm_iov[0].iov_base = buf;
	msg.lm_iov[0].iov_len = buflen;
	msg.lm_niov = 1;
	if (l9p_pufcall(&msg, in, version) != 0)
		return (-1);

	memset(out, 0, sizeof(*out));
	memset(&msg, 0, sizeof(msg));
	msg.lm_mode = L9P_UNPACK;
	msg.lm_iov[0].iov_base = buf;
	msg.lm_iov[0].iov_len = buflen;
	msg.lm_niov = 1;
	if (l9p_pufcall(&msg, out, version) != 0)
		return (-1);
	return ((ssize_t)msg.lm_size);
}

ATF_TC_WITHOUT_HEAD(pu64_full_width_roundtrip);
ATF_TC_BODY(pu64_full_width_roundtrip, tc)
{
	union l9p_fcall in, out;
	uint8_t buf[512];

	/*
	 * Every 64-bit field is given a value whose high 32 bits are
	 * non-zero, so any half-width transfer corrupts it.  qid.path is
	 * the pu64 that also exercises l9p_puqid().
	 */
	memset(&in, 0, sizeof(in));
	in.hdr.type = L9P_RGETATTR;
	in.hdr.tag = 0x2718;
	in.rgetattr.valid = UINT64_C(0x00000fff00000000);
	in.rgetattr.qid.type = L9P_QTSYMLINK;
	in.rgetattr.qid.version = 0x89abcdef;
	in.rgetattr.qid.path = UINT64_C(0xdeadbeefcafef00d);
	in.rgetattr.mode = 0120777;
	in.rgetattr.uid = 0x11223344;
	in.rgetattr.gid = 0x55667788;
	in.rgetattr.nlink = UINT64_C(0x0102030405060708);
	in.rgetattr.rdev = UINT64_C(0x1122334455667788);
	in.rgetattr.size = UINT64_C(0x8877665544332211);
	in.rgetattr.blksize = UINT64_C(0x00000001ffffffff);
	in.rgetattr.blocks = UINT64_C(0xffffffff00000000);
	in.rgetattr.atime_sec = UINT64_C(0x0f1e2d3c4b5a6978);
	in.rgetattr.mtime_sec = UINT64_C(0x1122334455667788);
	in.rgetattr.ctime_sec = UINT64_C(0x99aabbccddeeff00);

	ATF_REQUIRE(roundtrip(&in, &out, L9P_2000L, buf, sizeof(buf)) > 0);

	ATF_CHECK_EQ(out.hdr.type, L9P_RGETATTR);
	ATF_CHECK_EQ(out.rgetattr.valid, in.rgetattr.valid);
	ATF_CHECK_EQ(out.rgetattr.qid.type, L9P_QTSYMLINK);
	ATF_CHECK_EQ(out.rgetattr.qid.version, in.rgetattr.qid.version);
	ATF_CHECK_EQ(out.rgetattr.qid.path, in.rgetattr.qid.path);
	ATF_CHECK_EQ(out.rgetattr.nlink, in.rgetattr.nlink);
	ATF_CHECK_EQ(out.rgetattr.rdev, in.rgetattr.rdev);
	ATF_CHECK_EQ(out.rgetattr.size, in.rgetattr.size);
	ATF_CHECK_EQ(out.rgetattr.blksize, in.rgetattr.blksize);
	ATF_CHECK_EQ(out.rgetattr.blocks, in.rgetattr.blocks);
	ATF_CHECK_EQ(out.rgetattr.atime_sec, in.rgetattr.atime_sec);
	ATF_CHECK_EQ(out.rgetattr.mtime_sec, in.rgetattr.mtime_sec);
	ATF_CHECK_EQ(out.rgetattr.ctime_sec, in.rgetattr.ctime_sec);
}

ATF_TC_WITHOUT_HEAD(qid_types_roundtrip);
ATF_TC_BODY(qid_types_roundtrip, tc)
{
	static const uint8_t types[] = {
		L9P_QTFILE, L9P_QTDIR, L9P_QTSYMLINK, L9P_QTAUTH,
		L9P_QTAPPEND, (uint8_t)(L9P_QTDIR | L9P_QTAPPEND),
	};
	union l9p_fcall in, out;
	uint8_t buf[4096];
	size_t i;

	memset(&in, 0, sizeof(in));
	in.hdr.type = L9P_RWALK;
	in.hdr.tag = 0x0007;
	in.rwalk.nwqid = (uint16_t)(sizeof(types) / sizeof(types[0]));
	for (i = 0; i < in.rwalk.nwqid; i++) {
		in.rwalk.wqid[i].type = types[i];
		in.rwalk.wqid[i].version = (uint32_t)(0xa0000000u + i);
		in.rwalk.wqid[i].path = UINT64_C(0xcc00000000000000) + i;
	}

	ATF_REQUIRE(roundtrip(&in, &out, L9P_2000L, buf, sizeof(buf)) > 0);
	ATF_CHECK_EQ(out.rwalk.nwqid, in.rwalk.nwqid);
	for (i = 0; i < in.rwalk.nwqid; i++) {
		ATF_CHECK_EQ(out.rwalk.wqid[i].type, types[i]);
		ATF_CHECK_EQ(out.rwalk.wqid[i].version,
		    in.rwalk.wqid[i].version);
		ATF_CHECK_EQ(out.rwalk.wqid[i].path, in.rwalk.wqid[i].path);
	}
}

ATF_TC_WITHOUT_HEAD(rwalk_nwqid_overflow_rejected);
ATF_TC_BODY(rwalk_nwqid_overflow_rejected, tc)
{
	/*
	 * Hand-encode an Rwalk whose nwqid exceeds L9P_MAX_WELEM, and supply
	 * a full complement of qid bytes for every declared element so the
	 * unpack loop never bails early on a short read.  l9p_puqids() must
	 * reject nwqid > L9P_MAX_WELEM up front (return -1).
	 *
	 * The destination fcall is heap-allocated with slack past its wqid[]
	 * array so that, when the bound check is absent, the over-long walk
	 * lands in owned memory and l9p_pufcall() wrongly *succeeds* (returns
	 * 0) instead of relying on a crash.  The assertion therefore detects
	 * the missing guard deterministically, without a sanitizer.
	 */
	const uint16_t nwqid = (uint16_t)(L9P_MAX_WELEM + 32);
	const size_t qidsz = 1 + 4 + 8;	/* type + version + path */
	size_t buflen = 9 + (size_t)nwqid * qidsz;
	struct l9p_message msg;
	union l9p_fcall *out;
	uint8_t *buf;
	size_t off = 0, i;

	buf = malloc(buflen);
	out = calloc(1, sizeof(*out) + 64 * qidsz);
	ATF_REQUIRE(buf != NULL);
	ATF_REQUIRE(out != NULL);
	buf[off++] = 0;			/* size[4] placeholder */
	buf[off++] = 0;
	buf[off++] = 0;
	buf[off++] = 0;
	buf[off++] = L9P_RWALK;		/* type[1] */
	buf[off++] = 0x34;		/* tag[2] */
	buf[off++] = 0x12;
	buf[off++] = (uint8_t)(nwqid & 0xff);	/* nwqid[2] */
	buf[off++] = (uint8_t)(nwqid >> 8);
	for (i = off; i < buflen; i++)	/* well-formed qid payload */
		buf[i] = (uint8_t)i;

	memset(&msg, 0, sizeof(msg));
	msg.lm_mode = L9P_UNPACK;
	msg.lm_iov[0].iov_base = buf;
	msg.lm_iov[0].iov_len = buflen;
	msg.lm_niov = 1;
	ATF_CHECK_EQ(l9p_pufcall(&msg, out, L9P_2000L), -1);
	l9p_freefcall(out);
	free(out);
	free(buf);
}

ATF_TC_WITHOUT_HEAD(error_format_dotl_vs_dotu);
ATF_TC_BODY(error_format_dotl_vs_dotu, tc)
{
	union l9p_fcall in, out;
	uint8_t buf[256];

	/* 9P2000.L: Rlerror carries only a numeric errno. */
	memset(&in, 0, sizeof(in));
	in.hdr.type = L9P_RLERROR;
	in.hdr.tag = 0x0101;
	in.error.errnum = 42;
	ATF_REQUIRE(roundtrip(&in, &out, L9P_2000L, buf, sizeof(buf)) > 0);
	ATF_CHECK_EQ(out.hdr.type, L9P_RLERROR);
	ATF_CHECK_EQ(out.error.errnum, 42);
	ATF_CHECK_EQ(out.error.ename, NULL);
	l9p_freefcall(&out);

	/* 9P2000.u: Rerror carries a string plus a numeric errno. */
	memset(&in, 0, sizeof(in));
	in.hdr.type = L9P_RERROR;
	in.hdr.tag = 0x0202;
	in.error.ename = __DECONST(char *, "permission denied");
	in.error.errnum = 13;
	ATF_REQUIRE(roundtrip(&in, &out, L9P_2000U, buf, sizeof(buf)) > 0);
	ATF_CHECK_EQ(out.hdr.type, L9P_RERROR);
	ATF_REQUIRE(out.error.ename != NULL);
	ATF_CHECK_STREQ(out.error.ename, "permission denied");
	ATF_CHECK_EQ(out.error.errnum, 13);
	l9p_freefcall(&out);

	/*
	 * Legacy 9P2000: Rerror is a bare string with no errno field.  A
	 * decoder that expected the .u trailer would over-run; confirm the
	 * string alone round-trips.
	 */
	memset(&in, 0, sizeof(in));
	in.hdr.type = L9P_RERROR;
	in.hdr.tag = 0x0303;
	in.error.ename = __DECONST(char *, "boom");
	ATF_REQUIRE(roundtrip(&in, &out, L9P_2000, buf, sizeof(buf)) > 0);
	ATF_CHECK_EQ(out.hdr.type, L9P_RERROR);
	ATF_REQUIRE(out.error.ename != NULL);
	ATF_CHECK_STREQ(out.error.ename, "boom");
	l9p_freefcall(&out);
}

ATF_TC_WITHOUT_HEAD(dirent_roundtrip);
ATF_TC_BODY(dirent_roundtrip, tc)
{
	struct l9p_message msg;
	struct l9p_dirent in, out;
	uint8_t buf[128];

	memset(&in, 0, sizeof(in));
	in.qid.type = L9P_QTDIR;
	in.qid.version = 0x01020304;
	in.qid.path = UINT64_C(0x1122334455667788);
	in.offset = UINT64_C(0x8877665544332211);
	in.type = 4 /* DT_DIR */;
	in.name = __DECONST(char *, "subdir");

	memset(&msg, 0, sizeof(msg));
	msg.lm_mode = L9P_PACK;
	msg.lm_iov[0].iov_base = buf;
	msg.lm_iov[0].iov_len = sizeof(buf);
	msg.lm_niov = 1;
	ATF_REQUIRE(l9p_pudirent(&msg, &in) > 0);

	memset(&out, 0, sizeof(out));
	memset(&msg, 0, sizeof(msg));
	msg.lm_mode = L9P_UNPACK;
	msg.lm_iov[0].iov_base = buf;
	msg.lm_iov[0].iov_len = sizeof(buf);
	msg.lm_niov = 1;
	ATF_REQUIRE(l9p_pudirent(&msg, &out) > 0);

	ATF_CHECK_EQ(out.qid.type, L9P_QTDIR);
	ATF_CHECK_EQ(out.qid.version, in.qid.version);
	ATF_CHECK_EQ(out.qid.path, in.qid.path);
	ATF_CHECK_EQ(out.offset, in.offset);
	ATF_CHECK_EQ(out.type, in.type);
	ATF_REQUIRE(out.name != NULL);
	ATF_CHECK_STREQ(out.name, "subdir");
	free(out.name);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, pu64_full_width_roundtrip);
	ATF_TP_ADD_TC(tp, qid_types_roundtrip);
	ATF_TP_ADD_TC(tp, rwalk_nwqid_overflow_rejected);
	ATF_TP_ADD_TC(tp, error_format_dotl_vs_dotu);
	ATF_TP_ADD_TC(tp, dirent_roundtrip);
	return (atf_no_error());
}
