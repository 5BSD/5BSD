/*-
 * Copyright (c) 2018, Juniper Networks, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/cdefs.h>
#include <sys/limits.h>
#ifndef _STANDALONE
/* Avoid unwanted userlandish components */
#define _KERNEL
#include <sys/errno.h>
#undef _KERNEL
#endif

#ifdef VECTX_DEBUG
static int vectx_debug = VECTX_DEBUG;
# define DEBUG_PRINTF(n, x) if (vectx_debug >= n) printf x
#endif

#include "libsecureboot-priv.h"
#include <verify_file.h>

/**
 * @file vectx.c
 * @brief api to verify file while reading
 *
 * This API allows the hash of a file to be computed as it is read.
 * Key to this is seeking by reading.
 *
 * On close an indication of the verification result is returned.
 */

struct vectx {
	br_hash_compat_context vec_ctx;	/* hash ctx */
	const br_hash_class *vec_md;	/* hash method */
	const char	*vec_path;	/* path we are verifying */
	const char	*vec_want;	/* hash value we want */
	off_t		vec_off;	/* current offset */
	off_t		vec_hashed;	/* where we have hashed to */
	off_t		vec_size;	/* size of path */
	off_t		vec_eof_off;	/* first observed EOF */
	size_t		vec_hashsz;	/* size of hash */
	int		vec_fd;		/* file descriptor */
	int		vec_status;	/* verification status */
	int		vec_closing;	/* we are closing */
	int		vec_eof;	/* consumer observed EOF */
	int		vec_severity;	/* usually VE_MUST */
	unsigned char	*vec_pages;	/* digests of completed first-pass pages */
	size_t		vec_pages_capacity;
	int		vec_sequential; /* monotonic restriction set before reading */
	unsigned char	vec_partial[PAGE_SIZE]; /* first-pass partial page */

};


/* Abandon a failed load without further I/O or a verification success claim. */
void
vectx_discard(struct vectx *ctx)
{

	if (ctx == NULL)
		return;
	free(ctx->vec_pages);
	free(ctx);
}

/* A sequential consumer may avoid replay metadata by irrevocably refusing
 * backward reads. Select this before any verified bytes have been observed. */
int
vectx_set_sequential(struct vectx *ctx)
{

	if (ctx->vec_off != 0 || ctx->vec_hashed != 0 ||
	    ctx->vec_status == VE_FINGERPRINT_WRONG)
		return (EINVAL);
	ctx->vec_sequential = 1;
	return (0);
}

/* Remember the bytes included in the forward digest. Replay compares against
 * these observations; final close still authenticates the whole stream. */
static int
vectx_record(struct vectx *ctx, const unsigned char *data, size_t count)
{
	br_hash_compat_context hash;
	unsigned char *pages;
	size_t offset, take, index, capacity, required;
	off_t position = ctx->vec_hashed;

	while (count != 0) {
		offset = position % PAGE_SIZE;
		take = MIN(count, PAGE_SIZE - offset);
		memcpy(ctx->vec_partial + offset, data, take);
		if (offset + take == PAGE_SIZE) {
			if ((uintmax_t)(position / PAGE_SIZE) >= SIZE_MAX)
				return (ENOMEM);
			index = (size_t)(position / PAGE_SIZE);
			if (index >= SIZE_MAX / ctx->vec_hashsz)
				return (ENOMEM);
			required = (index + 1) * ctx->vec_hashsz;
			if (required > ctx->vec_pages_capacity) {
				capacity = ctx->vec_pages_capacity;
				if (capacity == 0)
					capacity = PAGE_SIZE;
				while (capacity < required) {
					if (capacity > SIZE_MAX / 2)
						return (ENOMEM);
					capacity *= 2;
				}
				pages = realloc(ctx->vec_pages, capacity);
				if (pages == NULL)
					return (ENOMEM);
				ctx->vec_pages = pages;
				ctx->vec_pages_capacity = capacity;
			}
			ctx->vec_md->init(&hash.vtable);
			ctx->vec_md->update(&hash.vtable, ctx->vec_partial, PAGE_SIZE);
			ctx->vec_md->out(&hash.vtable,
			    ctx->vec_pages + index * ctx->vec_hashsz);
		}
		position += take;
		data += take;
		count -= take;
	}
	return (0);
}

/* Only reread the touched page (or the observed prefix of its final page).
 * Copy to the caller after comparison, then restore the logical fd position. */
static ssize_t
vectx_replay(struct vectx *ctx, unsigned char *data, size_t count)
{
	unsigned char page[PAGE_SIZE], digest[64];
	br_hash_compat_context hash;
	off_t start;
	size_t length, have, offset, take, index;
	ssize_t n;

	start = ctx->vec_off - ctx->vec_off % PAGE_SIZE;
	offset = ctx->vec_off - start;
	length = MIN((off_t)PAGE_SIZE, ctx->vec_hashed - start);
	if (lseek(ctx->vec_fd, start, SEEK_SET) != start)
		return (-1);
	for (have = 0; have < length; have += n) {
		n = read(ctx->vec_fd, page + have, length - have);
		if (n <= 0)
			return (-1);
	}
	if (length == PAGE_SIZE) {
		index = start / PAGE_SIZE;
		ctx->vec_md->init(&hash.vtable);
		ctx->vec_md->update(&hash.vtable, page, length);
		ctx->vec_md->out(&hash.vtable, digest);
		if (memcmp(digest, ctx->vec_pages + index * ctx->vec_hashsz,
		    ctx->vec_hashsz) != 0)
			return (-1);
	} else if (memcmp(page, ctx->vec_partial, length) != 0)
		return (-1);
	take = MIN(count, length - offset);
	if (lseek(ctx->vec_fd, ctx->vec_off + take, SEEK_SET) !=
	    ctx->vec_off + (off_t)take)
		return (-1);
	memcpy(data, page + offset, take);
	return (take);
}


/**
 * @brief
 * verify an open file as we read it
 *
 * If the file has no fingerprint to match, we will still return a
 * verification context containing little more than the file
 * descriptor, and an error code in @c error.
 *
 * @param[in] fd
 *	open descriptor
 *
 * @param[in] path
 *	pathname to open
 *
 * @param[in] off
 *	current offset
 *
 * @param[in] stp
 *	pointer to struct stat
 *
 * @param[out] error
 *	@li 0 all is good
 *	@li ENOMEM out of memory
 *	@li VE_FINGERPRINT_NONE	no entry found
 *	@li VE_FINGERPRINT_UNKNOWN no fingerprint in entry
 *
 * @return ctx or NULL on error.
 *	NULL is only returned for non-files or out-of-memory.
 */
struct vectx *
vectx_open(int fd, const char *path, int severity,
    off_t off, struct stat *stp,
    int *error, const char *caller)
{
	struct vectx *ctx;
	struct stat st;
	size_t hashsz;
	char *cp;
	int rc;

	if (!stp)
	    stp = &st;

	if (verify_required())
		(void)verify_file(fd, path, off, VE_MUST, caller);
	rc = verify_prep(fd, path, off, stp, __func__);
	if (severity == VE_GUESS)
		severity = severity_guess(path);

	DEBUG_PRINTF(2,
	    ("vectx_open: caller=%s,fd=%d,name='%s',prep_rc=%d,severity=%d\n",
		caller, fd, path, rc, severity));

	switch (rc) {
	case VE_FINGERPRINT_NONE:
	case VE_FINGERPRINT_UNKNOWN:
		if (severity < VE_MUST)
			break;
		/* FALLTHROUGH */
	case VE_FINGERPRINT_WRONG:
		*error = rc;
		return (NULL);
	}
	ctx = malloc(sizeof(struct vectx));
	if (!ctx)
		goto enomem;
	ctx->vec_fd = fd;
	ctx->vec_path = path;
	ctx->vec_size = stp->st_size;
	ctx->vec_off = 0;
	ctx->vec_hashed = 0;
	ctx->vec_want = NULL;
	ctx->vec_severity = severity;
	ctx->vec_status = 0;
	ctx->vec_hashsz = hashsz = 0;
	ctx->vec_closing = 0;
	ctx->vec_eof = 0;
	ctx->vec_eof_off = 0;
	ctx->vec_pages = NULL;
	ctx->vec_pages_capacity = 0;
	ctx->vec_sequential = 0;

	if (rc == VE_UNVERIFIED_OK) {
		/* we are not verifying this */
		*error = 0;
		return (ctx);
	}
	cp = fingerprint_info_lookup(fd, path);
	if (!cp) {
		if (severity < VE_MUST)
			ctx->vec_status = VE_UNVERIFIED_OK;
		else {
			ctx->vec_status = VE_FINGERPRINT_NONE;
			ve_error_set("%s: no entry", path);
		}
	} else {
		if (strncmp(cp, "no_hash", 7) == 0) {
			ctx->vec_status = VE_FINGERPRINT_IGNORE;
			hashsz = 0;
		} else if (strncmp(cp, "sha256=", 7) == 0) {
			ctx->vec_md = &br_sha256_vtable;
			hashsz = br_sha256_SIZE;
			cp += 7;
#ifdef VE_SHA1_SUPPORT
		} else if (strncmp(cp, "sha1=", 5) == 0) {
			ctx->vec_md = &br_sha1_vtable;
			hashsz = br_sha1_SIZE;
			cp += 5;
#endif
#ifdef VE_SHA384_SUPPORT
		} else if (strncmp(cp, "sha384=", 7) == 0) {
		    ctx->vec_md = &br_sha384_vtable;
		    hashsz = br_sha384_SIZE;
		    cp += 7;
#endif
#ifdef VE_SHA512_SUPPORT
		} else if (strncmp(cp, "sha512=", 7) == 0) {
		    ctx->vec_md = &br_sha512_vtable;
		    hashsz = br_sha512_SIZE;
		    cp += 7;
#endif
		} else {
			if (severity < VE_MUST)
				ctx->vec_status = VE_UNVERIFIED_OK;
			else {
				ctx->vec_status = VE_FINGERPRINT_UNKNOWN;
				ve_error_set("%s: no supported fingerprint", path);
			}
		}
	}
	*error = ctx->vec_status;
	ctx->vec_hashsz = hashsz;
	ctx->vec_want = cp;
	if (hashsz > 0) {
		ctx->vec_md->init(&ctx->vec_ctx.vtable);

		if (off < 0 || (off > 0 &&
		    (lseek(fd, 0, SEEK_SET) != 0 ||
		    vectx_lseek(ctx, off, SEEK_SET) != off))) {
			ve_error_set("%s: cannot initialize verified offset", path);
			*error = VE_FINGERPRINT_WRONG;
			vectx_discard(ctx);
			return (NULL);
		}
	}
	DEBUG_PRINTF(2,
	    ("vectx_open: caller=%s,name='%s',hashsz=%lu,severity=%d,status=%d\n",
		caller, path, (unsigned long)ctx->vec_hashsz,
		severity, ctx->vec_status));
	return (ctx);

enomem:					/* unlikely */
	*error = ENOMEM;
	free(ctx);
	return (NULL);
}

/**
 * @brief
 * read bytes from file and update hash
 *
 * It is critical that all file I/O comes through here.
 * We keep track of current offset.
 * We also track what offset we have hashed to,
 * and compare replayed pages against their first-pass bytes.
 *
 * @param[in] pctx
 *	pointer to ctx
 *
 * @param[in] buf
 *
 * @param[in] nbytes
 *
 * @return bytes read or error.
 */
ssize_t
vectx_read(struct vectx *ctx, void *buf, size_t nbytes)
{
	unsigned char *bp = buf;
	int d;
	int n;
	int x, error;
	size_t off;

	/* A successful byte count must fit the public return type. */
	if (nbytes > SSIZE_MAX) {
		errno = EINVAL;
		return (-1);
	}

	if (ctx->vec_hashsz == 0)	/* nothing to do */
		return (read(ctx->vec_fd, buf, nbytes));

	if (ctx->vec_status == VE_FINGERPRINT_WRONG) {
		errno = EAUTH;
		return (-1);
	}
	if (nbytes == 0)
		return (0);

	off = 0;
	do {
		if (ctx->vec_off < ctx->vec_hashed) {
			if (ctx->vec_sequential) {
				ctx->vec_status = VE_FINGERPRINT_WRONG;
				errno = EAUTH;
				return (-1);
			}
			n = vectx_replay(ctx, bp + off, nbytes - off);
			if (n < 0) {
				ctx->vec_status = VE_FINGERPRINT_WRONG;
				errno = EAUTH;
				return (-1);
			}
			off += n;
			ctx->vec_off += n;
			continue;
		}
		/*
		 * Do this in reasonable chunks so
		 * we don't timeout if doing tftp
		 */
		x = MIN((size_t)PAGE_SIZE, nbytes - off);
		d = n = read(ctx->vec_fd, &bp[off], x);
		if (ctx->vec_closing && n < x) {
			DEBUG_PRINTF(3,
			    ("%s: read %d off=%ld hashed=%ld size=%ld\n",
			     __func__, n, (long)ctx->vec_off,
			     (long)ctx->vec_hashed, (long)ctx->vec_size));
		}
		if (n < 0 || (n == 0 && ctx->vec_size >= 0 &&
		    ctx->vec_off < ctx->vec_size)) {
			/* A consumer may treat failure as EOF and retain a prefix.
			 * Completing the hash later must never authenticate that prefix.
			 */
			ctx->vec_status = VE_FINGERPRINT_WRONG;
			if (n == 0)
				errno = EIO;
			return (-1);
		}
		if (n == 0 && !ctx->vec_eof) {
			ctx->vec_eof = 1;
			ctx->vec_eof_off = ctx->vec_off;
		}
		if (d > 0) {
			if (ctx->vec_closing && d < PAGE_SIZE) {
				DEBUG_PRINTF(3,
				    ("%s: update %ld + %d\n",
					__func__,
					(long)ctx->vec_hashed, d));
			}
			error = ctx->vec_sequential ? 0 : vectx_record(ctx, &bp[off], d);
			if (error != 0) {
				ctx->vec_status = VE_FINGERPRINT_WRONG;
				errno = error;
				return (-1);
			}
			ctx->vec_md->update(&ctx->vec_ctx.vtable, &bp[off], d);
			off += d;
			ctx->vec_off += d;
			ctx->vec_hashed += d;
		}
	} while (n > 0 && off < nbytes);
	return (off);
}

/**
 * @brief
 * vectx equivalent of lseek
 *
 * When seeking forwards we actually call vectx_read
 * to reach the desired offset.
 *
 * We support seeking backwards.
 *
 * @param[in] pctx
 *	pointer to ctx
 *
 * @param[in] off
 *	desired offset
 *
 * @param[in] whence
 * 	We try to convert whence to ``SEEK_SET``.
 *	We do not support ``SEEK_DATA`` or ``SEEK_HOLE``.
 *
 * @return offset or error.
 */
off_t
vectx_lseek(struct vectx *ctx, off_t off, int whence)
{
	unsigned char buf[PAGE_SIZE];
	size_t delta;
	ssize_t n;
	off_t position;

	if (ctx->vec_hashsz == 0)	/* nothing to do */
		return (lseek(ctx->vec_fd, off, whence));

	/*
	 * Convert whence to SEEK_SET
	 */
	DEBUG_PRINTF(3,
	    ("%s(%s, %ld, %d)\n", __func__, ctx->vec_path, (long)off, whence));
	if (whence == SEEK_END && off <= 0) {
		if (ctx->vec_size < 0) {
			if (ctx->vec_closing && off == 0) {
				/* size unknown - read until EOF */
				do {
					n = vectx_read(ctx, buf, PAGE_SIZE);
					if (n < 0)
						return (n);
				} while (n > 0);
				return (ctx->vec_off);
			}
		} else {
			if (ctx->vec_closing && ctx->vec_hashed < ctx->vec_size) {
				DEBUG_PRINTF(3, ("%s: SEEK_END %ld\n",
					__func__,
					(long)(ctx->vec_size - ctx->vec_hashed)));
			}
			whence = SEEK_SET;
			if (__builtin_add_overflow(off, ctx->vec_size, &off))
				return (-1);
		}
	} else if (whence == SEEK_CUR) {
		whence = SEEK_SET;
		if (__builtin_add_overflow(off, ctx->vec_off, &off))
			return (-1);
	}
	if (whence != SEEK_SET || off < 0 ||
	    (off > ctx->vec_size && ctx->vec_size >= 0)) {
		printf("ERROR: %s: unsupported operation: whence=%d off=%ld -> %ld\n",
		    __func__, whence, (long)ctx->vec_off, (long)off);
		return (-1);
	}
	if (off < ctx->vec_hashed) {
		if (ctx->vec_sequential) {
			ctx->vec_status = VE_FINGERPRINT_WRONG;
			errno = EAUTH;
			return (-1);
		}
#ifdef _STANDALONE
		struct open_file *f = fd2open_file(ctx->vec_fd);

		if (f != NULL &&
		    strncmp(f->f_ops->fs_name, "tftp", 4) == 0) {
			/* we cannot rewind if we've hashed much of the file */
			if (ctx->vec_hashed > ctx->vec_size / 5)
				return (-1);	/* refuse! */
		}
#endif
		/* seeking backwards! just do it */
		position = lseek(ctx->vec_fd, off, whence);
		if (position >= 0)
			ctx->vec_off = position;
		return (position);
	}
	n = 0;
	do {
		delta = off - ctx->vec_off;
		if (delta > 0) {
			delta = MIN(PAGE_SIZE, delta);
			n = vectx_read(ctx, buf, delta);
			if (n < 0)
				return (n);
		}
	} while (ctx->vec_off < off && n > 0);
	return (ctx->vec_off);
}

/**
 * @brief
 * check that hashes match and cleanup
 *
 * We have finished reading file, compare the hash with what
 * we wanted.
 *
 * Be sure to call this before closing the file, since we may
 * need to seek to the end to ensure hashing is complete.
 *
 * @param[in] pctx
 *	pointer to ctx
 *
 * @return 0 or an error.
 */
int
vectx_close(struct vectx *ctx, const char *caller)
{
	int rc;
	off_t end;

	ctx->vec_closing = 1;
	if (ctx->vec_status == VE_FINGERPRINT_WRONG) {
		ve_error_set("%s: failed verified read", ctx->vec_path);
		rc = VE_FINGERPRINT_WRONG;
	} else if (ctx->vec_hashsz == 0) {
		rc = ctx->vec_status;
	} else {
#ifdef VE_PCR_SUPPORT
		/*
		 * Only update pcr with things that must verify
		 * these tend to be processed in a more deterministic
		 * order, which makes our pseudo pcr more useful.
		 */
		ve_pcr_updating_set((ctx->vec_severity == VE_MUST));
#endif
		/*
		 * Preserve the stream boundary already seen by the consumer.
		 * In particular, an unknown-size stream must not grow at close
		 * and authenticate bytes the consumer never received.
		 */
		if (ctx->vec_eof)
			end = ctx->vec_eof_off;
		else if (ctx->vec_size >= 0 && ctx->vec_hashed == ctx->vec_size)
			end = ctx->vec_hashed;
		else if (ctx->vec_off < ctx->vec_hashed &&
		    lseek(ctx->vec_fd, ctx->vec_hashed, SEEK_SET) != ctx->vec_hashed)
			end = -1;
		else {
			/* Replayed bytes have already been compared. Complete only
			 * the previously unobserved suffix, not the replayed prefix. */
			ctx->vec_off = ctx->vec_hashed;
			end = vectx_lseek(ctx, 0, SEEK_END);
		}
		if (end < 0 || (ctx->vec_eof &&
		    ctx->vec_hashed != ctx->vec_eof_off) ||
		    (ctx->vec_size >= 0 &&
		    (end != ctx->vec_size || ctx->vec_hashed != ctx->vec_size))) {
			ve_error_set("%s: incomplete verified read", ctx->vec_path);
			rc = VE_FINGERPRINT_WRONG;
		} else {
			rc = ve_check_hash(&ctx->vec_ctx, ctx->vec_md,
			    ctx->vec_path, ctx->vec_want, ctx->vec_hashsz);
		}
	}
	DEBUG_PRINTF(2,
	    ("vectx_close: caller=%s,name='%s',severity=%d,rc=%d\n",
		caller,ctx->vec_path, ctx->vec_severity, rc));
	verify_report(ctx->vec_path, ctx->vec_severity, rc, NULL);
	if (rc == VE_FINGERPRINT_WRONG) {
#if !defined(UNIT_TEST) && !defined(DEBUG_VECTX)
		/* we are generally called with VE_MUST */
		if (ctx->vec_severity > VE_WANT)
			panic("cannot continue");
#endif
	}
	vectx_discard(ctx);
	return ((rc < 0) ? rc : 0);
}
