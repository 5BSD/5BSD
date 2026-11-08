/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 *
 * DescriptorQueue: served directories, stage 1c-iii-b (D168).
 *
 * getdirentries(2) on a DQ_KIND_DIR descriptor posts READDIR with the
 * descriptor's offset, which holds the controller's cookie, and the space
 * the caller left; the controller answers native struct dirent records and
 * the cookie after them.  The kernel validates every record before it is
 * accepted (a malformed reply is EINVAL to the controller and the event
 * stays in flight, D105/D168), zeroes the pads, and moves the offset to
 * the answered cookie, so lseek(2), telldir(3) and seekdir(3) work as on a
 * filesystem whose offsets are cookies.  Everything else about a
 * directory descriptor (read(2) EISDIR, mmap(2) EINVAL, no write) is
 * dq_file.c's, by kind.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/dirent.h>
#include <sys/file.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sdt.h>
#include <sys/uio.h>

#include <dev/dq/dq.h>
#include <dev/dq/dq_kern.h>
#include <dev/dq/dq_var.h>

/* The errnos a READDIR reply may carry (dq(4)); anything else is EIO. */
bool
dq_readdir_errno_allowed(int error)
{

	switch (error) {
	case EIO: case ENOENT: case EACCES: case EINVAL: case ENOTDIR:
	case ESTALE: case EINTEGRITY:
		return (true);
	default:
		return (false);
	}
}

static bool
dq_dirent_type_known(uint8_t type)
{

	switch (type) {
	case DT_UNKNOWN: case DT_FIFO: case DT_CHR: case DT_DIR: case DT_BLK:
	case DT_REG: case DT_LNK: case DT_SOCK: case DT_WHT:
		return (true);
	default:
		return (false);
	}
}

/*
 * The READDIR reply against its event (D168): the cookie fits an offset,
 * the records are exactly drdr_len bytes within the request, each a
 * well-formed struct dirent; an empty answer that is not the end is
 * refused for any request that could hold one entry.
 */
int
dq_readdir_reply_validate(const struct dq_event_k *ev, int rerrno,
    const void *buf, size_t len)
{
	const struct dq_readdir_body *rb;
	const struct dq_readdir_reply *rr;
	const struct dirent *dp;
	const char *recs;
	size_t off, rem, reclen, namlen;

	if (rerrno != 0)
		return (len == 0 ? 0 : EINVAL);
	rb = (const struct dq_readdir_body *)((const char *)&ev->ev_hdr +
	    sizeof(struct dq_event));
	if (len < sizeof(*rr))
		return (EINVAL);
	rr = buf;
	if (rr->drdr_next > OFF_MAX || rr->drdr_eof > 1 ||
	    rr->drdr_len != len - sizeof(*rr) || rr->drdr_len > rb->drd_len)
		return (EINVAL);
	if (rr->drdr_len == 0 && rr->drdr_eof == 0 &&
	    rb->drd_len >= sizeof(struct dirent))
		return (EINVAL);
	recs = (const char *)(rr + 1);
	for (off = 0; off < rr->drdr_len; off += reclen) {
		rem = rr->drdr_len - off;
		if (rem < offsetof(struct dirent, d_name))
			return (EINVAL);
		dp = (const struct dirent *)(recs + off);
		reclen = dp->d_reclen;
		namlen = dp->d_namlen;
		if (reclen == 0 || (reclen & 7) != 0 || reclen > rem ||
		    namlen == 0 || namlen > MAXNAMLEN ||
		    reclen < _GENERIC_DIRLEN(namlen))
			return (EINVAL);
		/* The name, its NUL, no '/' and no inner NUL. */
		if (dp->d_name[namlen] != '\0' ||
		    memchr(dp->d_name, '\0', namlen) != NULL ||
		    memchr(dp->d_name, '/', namlen) != NULL)
			return (EINVAL);
		if (!dq_dirent_type_known(dp->d_type))
			return (EINVAL);
		/* "." and ".." are directories (or of unknown type). */
		if (dp->d_name[0] == '.' && (namlen == 1 ||
		    (namlen == 2 && dp->d_name[1] == '.')) &&
		    dp->d_type != DT_DIR && dp->d_type != DT_UNKNOWN)
			return (EINVAL);
	}
	return (0);
}

/*
 * fo_readdir of a served directory (plan 4.9).  kern_getdirentries holds
 * the offset lock and a reference on fp.  The caller's space is clamped to
 * what one reply may carry; a request too small for one struct dirent is
 * EINVAL without an event (D168).  *basep is the starting cookie and the
 * offset becomes the answered one.
 */
int
dq_dir_readdir(struct file *fp __unused, struct dq_object *o, struct uio *uio,
    off_t *basep, struct thread *td)
{
	struct dq_readdir_body rb;
	const struct dq_readdir_reply *rr;
	struct dq_queue *q;
	struct dq_data *reply;
	struct dirent *dp;
	char *buf;
	size_t len, off;
	off_t start;
	int error, rerror;

	q = o->o_queue;
	/* 15.4: the controller reading its own served directory. */
	if (dq_caller_holds_queue(q, td))
		return (EDEADLK);
	if ((q->q_flags & DQ_Q_CLOSING) != 0)
		return (EIO);
	DQO_LOCK(o);
	error = o->o_state != DQ_OBJ_LIVE ? EIO : 0;
	DQO_UNLOCK(o);
	if (error != 0)
		return (error);
	start = uio->uio_offset;
	if (start < 0)
		return (EINVAL);
	len = MIN((size_t)uio->uio_resid,
	    (size_t)dq_max_io - sizeof(struct dq_readdir_reply));
	if (len < sizeof(struct dirent))
		return (EINVAL);
	bzero(&rb, sizeof(rb));
	rb.drd_cookie = start;
	rb.drd_len = len;
	error = dq_event_post_wait(o, DQ_OP_READDIR, &rb, sizeof(rb), td, 0,
	    &reply, &rerror);
	DQ_LOCK(q);
	q->q_stats.ds2_readdirs++;
	DQ_UNLOCK(q);
	if (error != 0)
		return (error);
	if (rerror != 0) {
		dq_reply_free(reply);
		return (rerror);
	}
	/* Validated by dq_readdir_reply_validate; observers share the bytes. */
	rr = (const struct dq_readdir_reply *)reply->dd_bytes;
	error = 0;
	if (rr->drdr_len != 0) {
		buf = malloc(rr->drdr_len, M_TEMP, M_WAITOK);
		memcpy(buf, rr + 1, rr->drdr_len);
		for (off = 0; off < rr->drdr_len; off += dp->d_reclen) {
			dp = (struct dirent *)(buf + off);
			dp->d_pad0 = 0;
			dp->d_pad1 = 0;
		}
		error = uiomove(buf, rr->drdr_len, uio);
		free(buf, M_TEMP);
	}
	if (error == 0) {
		if (basep != NULL)
			*basep = start;
		uio->uio_offset = rr->drdr_next;
	}
	dq_reply_free(reply);
	return (error);
}
