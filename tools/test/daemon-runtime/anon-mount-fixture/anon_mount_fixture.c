/* SPDX-License-Identifier: BSD-2-Clause */
/* Fault injection and observations for anonymous mount admission only. */
#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/file.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>
#include <sys/vnode.h>
#include <machine/atomic.h>
#include <security/mac/mac_policy.h>

static int slot, deny = 1, deny_open, deny_unmount;
static u_int created, destroyed, checked, actor_uid, filesystem_uid;
SYSCTL_NODE(_security_mac, OID_AUTO, anon_mount_test, CTLFLAG_RW, 0,
    "Disposable anonymous mount admission fixture");
SYSCTL_INT(_security_mac_anon_mount_test, OID_AUTO, deny, CTLFLAG_RW,
    &deny, 0, "Reject anonymous mount admission");
SYSCTL_UINT(_security_mac_anon_mount_test, OID_AUTO, created, CTLFLAG_RD,
    &created, 0, "Mount labels allocated");
SYSCTL_UINT(_security_mac_anon_mount_test, OID_AUTO, destroyed, CTLFLAG_RD,
    &destroyed, 0, "Mount labels destroyed");
SYSCTL_UINT(_security_mac_anon_mount_test, OID_AUTO, checked, CTLFLAG_RD,
    &checked, 0, "Admission calls");
SYSCTL_UINT(_security_mac_anon_mount_test, OID_AUTO, actor_uid, CTLFLAG_RD,
    &actor_uid, 0, "Original caller uid");
SYSCTL_UINT(_security_mac_anon_mount_test, OID_AUTO, filesystem_uid, CTLFLAG_RD,
    &filesystem_uid, 0, "Credential substituted for filesystem mounting");

SYSCTL_INT(_security_mac_anon_mount_test, OID_AUTO, deny_open, CTLFLAG_RW,
    &deny_open, 0, "Reject access to anonymous mount roots");
SYSCTL_INT(_security_mac_anon_mount_test, OID_AUTO, deny_unmount, CTLFLAG_RW,
    &deny_unmount, 0, "Leave an orphan on last-anchor release");

/* VM-only fault injection: change the candidate-lookup fsid, not the ZFS
 * objset identity. No retained kernel pointer or production test switch. */
static int
alias_fsid(SYSCTL_HANDLER_ARGS)
{
	struct { int fd; fsid_t fsid; } input;
	cap_rights_t rights;
	struct vnode *vp;
	struct mount *mp;
	int error;

	if (req->newptr == NULL || req->newlen != sizeof(input))
		return (EINVAL);
	error = SYSCTL_IN(req, &input, sizeof(input));
	if (error != 0)
		return (error);
	error = fgetvp(req->td, input.fd,
	    cap_rights_init(&rights, CAP_FSTATFS), &vp);
	if (error != 0)
		return (error);
	error = vn_lock(vp, LK_SHARED | LK_RETRY);
	if (error != 0) {
		vrele(vp);
		return (error);
	}
	mp = vp->v_mount;
	if (mp == NULL) {
		vput(vp);
		return (ESTALE);
	}
	error = vfs_busy(mp, MBF_NOWAIT);
	vput(vp);
	if (error != 0)
		return (error);
	if ((mp->mnt_kern_flag & MNTK_ANON) == 0 ||
	    strcmp(mp->mnt_stat.f_fstypename, "zfs") != 0) {
		error = EINVAL;
	} else {
		MNT_ILOCK(mp);
		mp->mnt_stat.f_fsid = input.fsid;
		MNT_IUNLOCK(mp);
	}
	vfs_unbusy(mp);
	return (error);
}
SYSCTL_PROC(_security_mac_anon_mount_test, OID_AUTO, alias_fsid,
    CTLTYPE_OPAQUE | CTLFLAG_WR | CTLFLAG_MPSAFE, NULL, 0, alias_fsid,
    "S", "VM-only anonymous ZFS mount fsid collision injection");

static int
root_open(struct ucred *cred __unused, struct vnode *vp,
    struct label *label __unused, accmode_t mode __unused)
{
	return (deny_open && vp->v_mount != NULL &&
	    (vp->v_mount->mnt_kern_flag & MNTK_ANON) != 0 ? EACCES : 0);
}

static int
unmount_check(struct ucred *cred __unused, struct mount *mp,
    struct label *label __unused, uint64_t flags __unused)
{
	return (deny_unmount && (mp->mnt_kern_flag & MNTK_ANON) != 0 ? EBUSY : 0);
}

static void
label_init(struct label *label)
{
	mac_label_set(label, slot, 0);
	atomic_add_int(&created, 1);
}

static void
label_destroy(struct label *label __unused)
{
	atomic_add_int(&destroyed, 1);
}

static int
admission(struct ucred *cred, struct mount *mp, struct label *label __unused)
{
	KASSERT((mp->mnt_kern_flag & MNTK_ANON) != 0,
	    ("anonymous admission without anonymous flag"));
	KASSERT(mp->mnt_vnodecovered == NULL && mp->mnt_optnew != NULL,
	    ("anonymous admission before options or with namespace attachment"));
	atomic_store_int(&actor_uid, cred->cr_uid);
	atomic_store_int(&filesystem_uid, curthread->td_ucred->cr_uid);
	atomic_add_int(&checked, 1);
	return (deny ? EACCES : 0);
}

static struct mac_policy_ops ops = {
	.mpo_vnode_check_open = root_open,
	.mpo_mount_check_unmount = unmount_check,
	.mpo_mount_init_label = label_init,
	.mpo_mount_destroy_label = label_destroy,
	.mpo_mount_check_mount_anon = admission,
};
MAC_POLICY_SET(&ops, mac_anon_mount_test, "Anonymous mount admission test",
    MPC_LOADTIME_FLAG_UNLOADOK, &slot);
