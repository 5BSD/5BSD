/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux64 quota ABI.  Filesystem accounting and enforcement remain native. */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/vnode.h>

#include <machine/../linux/linux.h>
#include <machine/../linux/linux_proto.h>

#define L_Q_SYNC       0x800001
#define L_Q_GETQUOTA   0x800007
#define L_Q_SETQUOTA   0x800008
#define L_QIF_BLIMITS  1
#define L_QIF_ALL      0x3f

struct linux_if_dqblk {
	uint64_t bhardlimit, bsoftlimit, curspace;
	uint64_t ihardlimit, isoftlimit, curinodes;
	uint64_t btime, itime;
	l_uint valid;
	l_uint pad;
};
CTASSERT(sizeof(struct linux_if_dqblk) == 72);

int
linux_quotactl(struct thread *td, struct linux_quotactl_args *args)
{
	struct nameidata nd;
	int error;

	if ((args->cmd & 0xff) >= 3)
		return (EINVAL);
	if (args->special == NULL) {
		if ((args->cmd >> 8) == L_Q_SYNC)
			return ((args->cmd & 0xff) == 2 ? 0 :
			    vfs_quota_sync_all(args->cmd & 0xff));
		return (ENODEV);
	}
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_USERSPACE, args->special);
	error = namei(&nd);
	if (error != 0)
		return (error);
	NDFREE_PNBUF(&nd);
	/* A pathname is a block-device selector, not a dataset pathname. */
	error = vn_isdisk(nd.ni_vp) ? EOPNOTSUPP : ENOTBLK;
	vput(nd.ni_vp);
	return (error);
}

int
linux_quotactl_fd64(struct thread *td, struct linux_quotactl_fd64_args *args)
{
	struct linux_if_dqblk dq;
	struct vfs_quota quota = { 0 };
	struct file *fp;
	struct mount *mp;
	struct vnode *vp;
	int cmd, type, op, error;

	/* Resolve the descriptor before validating the quota type, as Linux does. */
	error = fget(td, args->fd, &cap_fstatfs_rights, &fp);
	if (error != 0)
		return (error);
	type = args->cmd & 0xff;
	cmd = args->cmd >> 8;
	if (type >= 3) {
		fdrop(fp, td);
		return (EINVAL);
	}
	vp = fp->f_vnode;
	if (vp == NULL) {
		fdrop(fp, td);
		return (ENOSYS);
	}
	vref(vp);
	fdrop(fp, td);
	mp = vp->v_mount;
	error = vfs_busy(mp, 0);
	vrele(vp);
	if (error != 0)
		return (error);
	if (!vfs_quota_supported(mp)) {
		error = ENOSYS;
		goto out;
	}
	if (type == 2) {
		error = EINVAL;
		goto out;
	}
	if (cmd == L_Q_SYNC) {
		error = vfs_quota(mp, VFS_QUOTA_SYNC, type, 0, NULL);
		if (error == EOPNOTSUPP)
			error = ENOSYS;
		goto out;
	}
	if (cmd != L_Q_GETQUOTA && cmd != L_Q_SETQUOTA) {
		error = EOPNOTSUPP;
		goto out;
	}
	/* Linux GETQUOTA also requires a writable mount. */
	if ((mp->mnt_flag & MNT_RDONLY) != 0) {
		error = EROFS;
		goto out;
	}
	op = cmd == L_Q_GETQUOTA ? VFS_QUOTA_GET : VFS_QUOTA_SET_BYTES;
	error = vfs_quota_check(td, op, type, args->id);
	if (error != 0)
		goto out;
	if (cmd == L_Q_SETQUOTA) {
		error = copyin(args->addr, &dq, sizeof(dq));
		if (error != 0)
			goto out;
		if ((dq.valid & ~L_QIF_BLIMITS) != 0 ||
		    ((dq.valid & L_QIF_BLIMITS) != 0 && dq.bsoftlimit != 0)) {
			error = EOPNOTSUPP;
			goto out;
		}
		if (dq.valid != 0 && dq.bhardlimit > (UINT64_MAX >> 10)) {
			error = EOVERFLOW;
			goto out;
		}
		quota.bytes_limit = dq.bhardlimit << 10;
	}
	if (args->id == (l_uint)-1) {
		error = EINVAL;
		goto out;
	}
	if (cmd == L_Q_SETQUOTA && dq.valid == 0) {
		/* Check backend support even for an empty update. */
		op = VFS_QUOTA_GET;
	}
	error = vfs_quota(mp, op, type, args->id, &quota);
	if (error == EOPNOTSUPP)
		error = ENOSYS;
	if (error == 0 && cmd == L_Q_GETQUOTA) {
		bzero(&dq, sizeof(dq));
		dq.bhardlimit = (quota.bytes_limit >> 10) +
		    ((quota.bytes_limit & 1023) != 0);
		dq.curspace = quota.bytes_used;
		dq.ihardlimit = quota.objects_limit;
		dq.curinodes = quota.objects_used;
		dq.valid = L_QIF_ALL;
		error = copyout(&dq, args->addr, sizeof(dq));
	}
out:
	vfs_unbusy(mp);
	return (error);
}
