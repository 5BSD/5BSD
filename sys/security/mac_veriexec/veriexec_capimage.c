/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Embedded signature integrity for ordinary exec, independent of the enrolled
 * veriexec fingerprint database.  The embedded public key proves consistency;
 * it does not establish signer trust or grant capability authority.  Trusted
 * signer selection and authenticated policy interpretation remain in userland.
 */
#include "opt_veriexec.h"
#ifdef MAC_VERIEXEC_CAPIMAGE
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capimage.h>
#include <sys/capsicum.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <security/mac/mac_framework.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/sdt.h>
#include <sys/uio.h>
#include <sys/unistd.h>
#include <sys/vnode.h>
#include <crypto/sha2/sha256.h>
#include <opencrypto/cryptodesc_ed25519.h>
#include "mac_veriexec.h"
#include "mac_veriexec_internal.h"

FEATURE(veriexec_capimage, "Embedded ELF signature integrity on exec");
FEATURE(veriexec_capimage_handle, "Explicit pinned integrity handles");
FEATURE(veriexec_capimage_mmap, "Embedded signature mmap integrity and lifetime");

SDT_PROVIDER_DEFINE(capimage);
SDT_PROBE_DEFINE3(capimage, , verify, start, "int", "int64_t", "bool");
SDT_PROBE_DEFINE4(capimage, , verify, done, "int", "int", "bool", "uint64_t");

static int
capimage_read(struct vnode *vp, void *buf, size_t size, off_t offset,
    struct ucred *cred)
{
	ssize_t resid;
	int error;

	error = vn_rdwr(UIO_READ, vp, buf, size, offset, UIO_SYSSPACE,
	    IO_NODELOCKED, cred, NOCRED, &resid, curthread);
	return (error != 0 ? error : resid != 0 ? EAUTH : 0);
}

/* Caller holds the vnode locked through verification and exec text pinning. */
static int
capimage_check(struct ucred *cred, struct vnode *vp, off_t size,
    bool required, bool *signedp, enum capimage_check_source source,
    struct capimage_info *info, bool raw_digest)
{
	struct capimage_footer footer;
	struct capimage_header header;
	SHA256_CTX ctx, raw_ctx, policy_ctx;
	uint8_t digest[SHA256_DIGEST_LENGTH], *buffer;
	uint64_t offset, container_size, hashed_bytes = 0;
	bool recognized = false;
	off_t pos, zero, first, last;
	size_t take;
	int error, close_error;

	if (signedp != NULL)
		*signedp = false;
	ASSERT_VOP_LOCKED(vp, "mac_veriexec_capimage_check");
	SDT_PROBE3(capimage, , verify, start, source, size, required);
	if (vp->v_type != VREG || size < (off_t)sizeof(footer)) {
		error = required ? EAUTH : 0;
		goto done;
	}
	error = VOP_OPEN(vp, FREAD, cred, curthread, NULL);
	if (error != 0)
		goto done;
	buffer = NULL;
	error = capimage_read(vp, &footer, sizeof(footer), size - sizeof(footer),
	    cred);
	if (error != 0)
		goto out;
	/* No canonical EOF marker means no embedded signature.  Requiring an
	 * identity to remain signed is a separate enrollment/bundle policy. */
	if (memcmp(footer.magic, "5BSDEND", sizeof(footer.magic)) != 0) {
		error = required ? EAUTH : 0;
		goto out;
	}
	recognized = true;
	if (vp->v_writecount > 0) {
		error = ETXTBSY;
		goto out;
	}
	offset = le64toh(footer.offset);
	container_size = le64toh(footer.size);
	if ((uint64_t)size > CAPIMAGE_FILE_MAX ||
	    le32toh(footer.version) != CAPIMAGE_VERSION || footer.reserved != 0 ||
	    offset < 64 || offset > (uint64_t)size - sizeof(footer) ||
	    container_size < sizeof(header) + 1 ||
	    container_size > sizeof(header) + CAPIMAGE_POLICY_MAX ||
	    container_size != (uint64_t)size - sizeof(footer) - offset) {
		error = EAUTH;
		goto out;
	}
	error = capimage_read(vp, &header, sizeof(header), offset, cred);
	if (error != 0)
		goto out;
	if (memcmp(header.magic, "5BSDSIG", sizeof(header.magic)) != 0 ||
	    le32toh(header.version) != CAPIMAGE_VERSION ||
	    le32toh(header.policy_size) != container_size - sizeof(header)) {
		error = EAUTH;
		goto out;
	}
	buffer = malloc(PAGE_SIZE, M_VERIEXEC, M_WAITOK);
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, CAPIMAGE_DOMAIN, sizeof(CAPIMAGE_DOMAIN));
	if (info != NULL)
		SHA256_Init(&policy_ctx);
	if (raw_digest)
		SHA256_Init(&raw_ctx);
	zero = offset + offsetof(struct capimage_header, signature);
	for (pos = 0; pos < size; pos += take) {
		take = MIN((off_t)PAGE_SIZE, size - pos);
		error = capimage_read(vp, buffer, take, pos, cred);
		if (error != 0)
			goto out;
		if (raw_digest)
			SHA256_Update(&raw_ctx, buffer, take);
		if (info != NULL) {
			first = MAX(pos, (off_t)(offset + sizeof(header)));
			last = MIN(pos + (off_t)take, (off_t)(offset + container_size));
			if (first < last)
				SHA256_Update(&policy_ctx, buffer + first - pos, last - first);
		}
		/* Only the signature bytes themselves are excluded from the hash. */
		first = MAX(pos, zero);
		last = MIN(pos + (off_t)take, zero + CAPIMAGE_SIGNATURE_SIZE);
		if (first < last)
			memset(buffer + first - pos, 0, last - first);
		SHA256_Update(&ctx, buffer, take);
		hashed_bytes += take;
	}
	SHA256_Final(digest, &ctx);
	if (cryptodesc_ed25519_verify(header.signature, digest, sizeof(digest),
	    header.key) != 0)
		error = EAUTH;
	else {
		if (signedp != NULL)
			*signedp = true;
		if (info != NULL) {
			memset(info, 0, sizeof(*info));
			info->version = CAPIMAGE_HANDLE_VERSION;
			info->struct_size = sizeof(*info);
			info->container_version = CAPIMAGE_VERSION;
			info->file_size = size;
			info->policy_offset = offset + sizeof(header);
			info->policy_size = le32toh(header.policy_size);
			memcpy(info->image_digest, digest, sizeof(digest));
			memcpy(info->key, header.key, sizeof(info->key));
			SHA256_Final(info->policy_digest, &policy_ctx);
			if (raw_digest) {
				SHA256_Final(info->raw_digest, &raw_ctx);
				info->available |= CAPIMAGE_INFO_RAW_DIGEST;
			}
		}
	}
out:
	free(buffer, M_VERIEXEC);
	close_error = VOP_CLOSE(vp, FREAD, cred, curthread);
	if (error == 0)
		error = close_error;
done:
	SDT_PROBE4(capimage, , verify, done, source, error, recognized,
	    hashed_bytes);
	return (error);
}
int
mac_veriexec_capimage_check(struct ucred *cred, struct vnode *vp, off_t size,
    bool required, enum capimage_check_source source)
{

	return (capimage_check(cred, vp, size, required, NULL, source, NULL, false));
}

int
mac_veriexec_capimage_mmap_check(struct ucred *cred, struct vnode *vp,
    struct label *label __unused, bool *pin)
{
	struct vattr va;
	bool signed_image;
	int error;

	error = VOP_GETATTR(vp, &va, cred);
	if (error == 0) {
		error = capimage_check(cred, vp, va.va_size, false, &signed_image,
		    CAPIMAGE_CHECK_MMAP, NULL, false);
		if (error == 0 && signed_image)
			*pin = true;
	}
	return (error);
}

/* Each handle owns one text reference; no global result cache or policy copy. */
struct capimage_handle {
	struct file *backing;
	struct capimage_info info;
};
_Static_assert(sizeof(struct capimage_handle) <= 256, "bounded handle metadata");

static bool
capimage_handle_live(struct capimage_handle *h)
{
	struct vnode *vp = h->backing->f_vnode;
	bool live;

	vn_lock(vp, LK_SHARED | LK_RETRY);
	live = vp->v_type == VREG && !VN_IS_DOOMED(vp);
	VOP_UNLOCK(vp);
	return (live);
}

static int
capimage_handle_close(struct file *fp, struct thread *td)
{
	struct capimage_handle *h = fp->f_data;
	struct vnode *vp = h->backing->f_vnode;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	VOP_UNSET_TEXT_CHECKED(vp);
	VOP_UNLOCK(vp);
	fdrop(h->backing, td);
	free(h, M_VERIEXEC);
	return (0);
}

static int
capimage_handle_read(struct file *fp, struct uio *uio,
    struct ucred *cred, int flags, struct thread *td)
{
	struct capimage_handle *h = fp->f_data;
	struct iovec iov;
	struct uio input;
	char *buffer;
	size_t take;
	int error = 0;

	if (!capimage_handle_live(h))
		return (ESTALE);
	foffset_lock_uio(fp, uio, flags);
	if (uio->uio_offset < 0) {
		error = EINVAL;
		goto out_offset;
	}
	if ((uint64_t)uio->uio_offset >= h->info.policy_size || uio->uio_resid == 0)
		goto out_offset;
	buffer = malloc(PAGE_SIZE, M_VERIEXEC, M_WAITOK);
	while (uio->uio_resid > 0 &&
	    (uint64_t)uio->uio_offset < h->info.policy_size) {
		take = MIN((size_t)uio->uio_resid, PAGE_SIZE);
		take = MIN(take, h->info.policy_size - (uint64_t)uio->uio_offset);
		iov = (struct iovec){ .iov_base = buffer, .iov_len = take };
		input = (struct uio){ .uio_iov = &iov, .uio_iovcnt = 1,
		    .uio_offset = h->info.policy_offset + uio->uio_offset,
		    .uio_resid = take, .uio_segflg = UIO_SYSSPACE,
		    .uio_rw = UIO_READ, .uio_td = td };
		/* Keep filesystem per-open state and do not move its file offset. */
		error = fo_read(h->backing, &input, cred, FOF_OFFSET, td);
		if (error != 0 || input.uio_resid != 0) {
			if (error == 0)
				error = EAUTH;
			break;
		}
		error = uiomove(buffer, take, uio);
		if (error != 0)
			break;
	}
	free(buffer, M_VERIEXEC);
out_offset:
	foffset_unlock_uio(fp, uio, flags);
	return (error);
}

static int
capimage_handle_seek(struct file *fp, off_t offset, int whence,
    struct thread *td)
{
	struct capimage_handle *h = fp->f_data;
	off_t position, base;
	int error = 0;

	position = foffset_lock(fp, 0);
	switch (whence) {
	case SEEK_SET: base = 0; break;
	case SEEK_CUR: base = position; break;
	case SEEK_END: base = h->info.policy_size; break;
	default: error = EINVAL; goto out;
	}
	if (offset < -base || offset > OFF_MAX - base)
		error = EINVAL;
	else
		position = base + offset;
out:
	foffset_unlock(fp, position, 0);
	if (error == 0)
		td->td_uretoff.tdu_off = position;
	return (error);
}

static int
capimage_handle_stat(struct file *fp, struct stat *st,
    struct ucred *cred __unused)
{
	struct capimage_handle *h = fp->f_data;

	if (!capimage_handle_live(h))
		return (ESTALE);
	memset(st, 0, sizeof(*st));
	st->st_mode = S_IFREG | S_IRUSR;
	st->st_size = h->info.policy_size;
	st->st_blksize = PAGE_SIZE;
	return (0);
}

static int
capimage_handle_kinfo(struct file *fp, struct kinfo_file *kif,
    struct filedesc *fdp)
{
	struct capimage_handle *h = fp->f_data;

	return (fo_fill_kinfo(h->backing, kif, fdp));
}

static struct fileops capimage_handle_ops = {
	.fo_read = capimage_handle_read, .fo_write = invfo_rdwr,
	.fo_truncate = invfo_truncate, .fo_ioctl = invfo_ioctl,
	.fo_poll = invfo_poll, .fo_kqfilter = invfo_kqfilter,
	.fo_stat = capimage_handle_stat, .fo_close = capimage_handle_close,
	.fo_chmod = invfo_chmod, .fo_chown = invfo_chown,
	.fo_sendfile = invfo_sendfile, .fo_seek = capimage_handle_seek,
	.fo_fill_kinfo = capimage_handle_kinfo,
	.fo_flags = DFLAG_PASSABLE | DFLAG_SEEKABLE,
};

/* A command number alone is not descriptor authentication: userspace-backed
 * devices may implement arbitrary ioctls. Check our exact immutable fileops. */
int
mac_veriexec_capimage_info(struct thread *td, void *arg)
{
	struct capimage_info_request request;
	struct capimage_handle *h;
	struct file *fp;
	cap_rights_t rights;
	int error;

	error = copyin(arg, &request, offsetof(struct capimage_info_request, info));
	if (error != 0)
		return (error);
	if (request.version != CAPIMAGE_HANDLE_VERSION ||
	    request.struct_size != sizeof(request) || request.reserved != 0)
		return (EINVAL);
	error = fget(td, request.handle_fd,
	    cap_rights_init_one(&rights, CAP_READ), &fp);
	if (error != 0)
		return (error);
	if (fp->f_ops != &capimage_handle_ops) {
		error = EINVAL;
		goto out;
	}
	h = fp->f_data;
	if (!capimage_handle_live(h)) {
		error = ESTALE;
		goto out;
	}
	error = copyout(&h->info,
	    (char *)arg + offsetof(struct capimage_info_request, info), sizeof(h->info));
out:
	fdrop(fp, td);
	return (error);
}

/* Only audited vnode text/write exclusion backends are eligible. Tmpfs
 * writable shared mappings use swp.writemappings, not v_writecount, so its
 * VOP_SET_TEXT does not exclude an existing mutable mapping. Keep it disabled
 * until a filesystem-specific pin protects the entire handle lifetime.
 * Stacked, remote and userspace backends also need a separate audit. */
static bool
capimage_handle_backend(struct vnode *vp)
{
	const char *name;

	if (vp->v_mount == NULL)
		return (false);
	name = vp->v_mount->mnt_vfc->vfc_name;
	return (strcmp(name, "ufs") == 0 || strcmp(name, "zfs") == 0);
}

int
mac_veriexec_capimage_prepare(struct thread *td, void *arg)
{
	struct capimage_prepare request;
	struct capimage_footer footer;
	struct capimage_handle *h = NULL;
	struct file *backing = NULL, *fresh = NULL;
	struct vnode *vp;
	struct vattr va;
	cap_rights_t rights;
	bool pinned = false;
	int error, fd;

	error = copyin(arg, &request, sizeof(request));
	if (error != 0)
		return (error);
	if (request.version != CAPIMAGE_HANDLE_VERSION ||
	    request.struct_size != sizeof(request) ||
	    (request.flags & ~(CAPIMAGE_PREPARE_REQUIRED |
	    CAPIMAGE_PREPARE_RAW_DIGEST | CAPIMAGE_PREPARE_VVERIFY)) != 0)
		return (EINVAL);
	for (unsigned i = 0; i < nitems(request.reserved); i++)
		if (request.reserved[i] != 0)
			return (EINVAL);
	error = getvnode(td, request.source_fd,
	    cap_rights_init_one(&rights, CAP_PREAD), &backing);
	if (error != 0)
		return (error);
	if ((backing->f_flag & FREAD) == 0 || backing->f_vnode->v_type != VREG) {
		error = EBADF;
		goto out;
	}
	vp = backing->f_vnode;
	/* Allocate before vnode lock; no policy-sized allocation. */
	h = malloc(sizeof(*h), M_VERIEXEC, M_WAITOK | M_ZERO);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_GETATTR(vp, &va, td->td_ucred);
	if (error != 0)
		goto unlock;
	memset(&footer, 0, sizeof(footer));
	if (va.va_size >= (off_t)sizeof(footer)) {
		error = capimage_read(vp, &footer, sizeof(footer),
		    va.va_size - sizeof(footer), td->td_ucred);
		if (error != 0)
			goto unlock;
	}
	/* Unsigned introspection must not pin, or fail because writers exist. */
	if (memcmp(footer.magic, "5BSDEND", sizeof(footer.magic)) != 0) {
		error = (request.flags & CAPIMAGE_PREPARE_REQUIRED) != 0 ? ENOATTR : 0;
		if (error == 0 && (request.flags & CAPIMAGE_PREPARE_VVERIFY) != 0)
			error = mac_veriexec_capimage_open_policy(td->td_ucred, vp);
		td->td_retval[0] = 0;
		goto unlock;
	}
	if (!capimage_handle_backend(vp)) {
		error = EOPNOTSUPP;
		goto unlock;
	}
	error = VOP_SET_TEXT(vp);
	if (error != 0)
		goto unlock;
	pinned = true;
	/* Reread and authenticate the complete now-pinned representation. */
	error = capimage_check(td->td_ucred, vp, va.va_size, true, NULL,
	    CAPIMAGE_CHECK_PREPARE, &h->info,
	    (request.flags & CAPIMAGE_PREPARE_RAW_DIGEST) != 0);
	if (error == 0 && (request.flags & CAPIMAGE_PREPARE_VVERIFY) != 0)
		error = mac_veriexec_capimage_open_policy(td->td_ucred, vp);
unlock:
	VOP_UNLOCK(vp);
	if (error != 0 || !pinned)
		goto out;
	error = falloc_noinstall(td, &fresh);
	if (error != 0)
		goto out;
	h->backing = backing;
	finit(fresh, FREAD, DTYPE_DEV, h, &capimage_handle_ops);
	/* Fresh file now owns both backing reference and text pin. */
	backing = NULL;
	h = NULL;
	pinned = false;
	error = finstall(td, fresh, &fd, O_CLOEXEC, NULL);
	if (error == 0)
		td->td_retval[0] = fd + 1;
out:
	if (pinned) {
		vn_lock(backing->f_vnode, LK_EXCLUSIVE | LK_RETRY);
		VOP_UNSET_TEXT_CHECKED(backing->f_vnode);
		VOP_UNLOCK(backing->f_vnode);
	}
	if (fresh != NULL)
		fdrop(fresh, td);
	if (backing != NULL)
		fdrop(backing, td);
	free(h, M_VERIEXEC);
	return (error);
}

#endif /* MAC_VERIEXEC_CAPIMAGE */
