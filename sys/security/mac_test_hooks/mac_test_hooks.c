/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026
 * All rights reserved.
 */

#include <sys/param.h>
#include <sys/acl.h>
#include <sys/file.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>

#include <security/mac/mac_policy.h>

static SYSCTL_NODE(_security_mac, OID_AUTO, test_hooks,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0, "MAC test hook policy controls");
static SYSCTL_NODE(_security_mac_test_hooks, OID_AUTO, counter,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0, "Per-hook invocation counters");
static SYSCTL_NODE(_security_mac_test_hooks, OID_AUTO, deny,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0, "Per-hook deny toggles");

#define	HOOK_CHECK_DECL(name)						\
	static int counter_##name;					\
	static int deny_##name;						\
	SYSCTL_INT(_security_mac_test_hooks_counter, OID_AUTO, name,	\
	    CTLFLAG_RD, &counter_##name, 0, #name);			\
	SYSCTL_INT(_security_mac_test_hooks_deny, OID_AUTO, name,	\
	    CTLFLAG_RW, &deny_##name, 0, #name)

#define	HOOK_CHECK_IMPL(name, ...)					\
	HOOK_CHECK_DECL(name);						\
	static int							\
	test_##name(__VA_ARGS__)					\
	{								\
		atomic_add_int(&counter_##name, 1);			\
		return (deny_##name);					\
	}

#define	HOOK_NOTIFY_DECL(name)						\
	static int counter_##name;					\
	SYSCTL_INT(_security_mac_test_hooks_counter, OID_AUTO, name,	\
	    CTLFLAG_RD, &counter_##name, 0, #name)

#define	HOOK_NOTIFY_IMPL(name, ...)					\
	HOOK_NOTIFY_DECL(name);						\
	static void							\
	test_##name(__VA_ARGS__)					\
	{								\
		atomic_add_int(&counter_##name, 1);			\
	}

HOOK_CHECK_IMPL(proc_check_fork, struct ucred *cred __unused,
    int flags __unused)
HOOK_CHECK_IMPL(proc_check_core, struct ucred *cred __unused,
    struct proc *p __unused)
HOOK_CHECK_IMPL(proc_check_syscall, struct ucred *cred __unused,
    int syscall_num __unused)
HOOK_CHECK_IMPL(proc_check_mmap_anon, struct ucred *cred __unused,
    vm_offset_t addr __unused, vm_size_t len __unused, int prot __unused,
    int flags __unused)
HOOK_CHECK_IMPL(proc_check_mprotect, struct ucred *cred __unused,
    vm_offset_t addr __unused, vm_size_t len __unused, int prot __unused)
HOOK_NOTIFY_IMPL(proc_notify_exec_complete, struct proc *p __unused)
HOOK_NOTIFY_IMPL(proc_notify_exit, struct proc *p __unused)
HOOK_CHECK_IMPL(file_check_receive, struct ucred *cred __unused,
    struct file *fp __unused)
HOOK_CHECK_IMPL(file_check_inherit, struct ucred *cred __unused,
    struct ucred *newcred __unused, struct file *fp __unused,
    int fd __unused)
HOOK_CHECK_IMPL(file_check_dup, struct ucred *cred __unused,
    struct file *fp __unused, int fd __unused)
HOOK_CHECK_IMPL(file_check_ioctl, struct ucred *cred __unused,
    struct file *fp __unused, int fd __unused, u_long cmd __unused)
HOOK_CHECK_IMPL(file_check_mmap, struct ucred *cred __unused,
    struct file *fp __unused, int fd __unused, int prot __unused,
    int flags __unused, vm_offset_t addr __unused, vm_size_t size __unused)
HOOK_NOTIFY_IMPL(file_notify_close, struct ucred *cred __unused,
    struct file *fp __unused, int fd __unused)
HOOK_CHECK_IMPL(mount_check_mount, struct ucred *cred __unused,
    const char *fspath __unused, const char *fstype __unused,
    int flags __unused)
HOOK_CHECK_IMPL(mount_check_umount, struct ucred *cred __unused,
    struct mount *mp __unused, struct label *mplabel __unused)
HOOK_CHECK_IMPL(mount_check_remount, struct ucred *cred __unused,
    struct mount *mp __unused, struct label *mplabel __unused,
    int flags __unused)
HOOK_CHECK_IMPL(mount_check_snapshot_create, struct ucred *cred __unused,
    const char *snapname __unused)
HOOK_CHECK_IMPL(mount_check_snapshot_delete, struct ucred *cred __unused,
    const char *snapname __unused)
HOOK_CHECK_IMPL(mount_check_snapshot_revert, struct ucred *cred __unused,
    const char *snapname __unused)
HOOK_CHECK_IMPL(system_check_kas_info, struct ucred *cred __unused,
    struct proc *p __unused)
HOOK_CHECK_IMPL(vmm_check_create, struct ucred *cred __unused,
    const char *vmname __unused)
HOOK_NOTIFY_IMPL(vnode_notify_create, struct ucred *cred __unused,
    struct vnode *dvp __unused, struct vnode *vp __unused,
    struct componentname *cnp __unused)
HOOK_NOTIFY_IMPL(vnode_notify_open, struct ucred *cred __unused,
    struct vnode *vp __unused, int fmode __unused)
HOOK_NOTIFY_IMPL(vnode_notify_rename, struct ucred *cred __unused,
    struct componentname *fromcnp __unused,
    struct componentname *tocnp __unused)
HOOK_NOTIFY_IMPL(vnode_notify_unlink, struct ucred *cred __unused,
    struct vnode *dvp __unused, struct vnode *vp __unused,
    struct componentname *cnp __unused)
HOOK_NOTIFY_IMPL(vnode_notify_link, struct ucred *cred __unused,
    struct vnode *dvp __unused, struct vnode *vp __unused,
    struct componentname *cnp __unused)
HOOK_NOTIFY_IMPL(vnode_notify_truncate, struct ucred *cred __unused,
    struct vnode *vp __unused)
HOOK_NOTIFY_IMPL(vnode_notify_setmode, struct ucred *cred __unused,
    struct vnode *vp __unused, mode_t mode __unused)
HOOK_NOTIFY_IMPL(vnode_notify_setowner, struct ucred *cred __unused,
    struct vnode *vp __unused, uid_t uid __unused, gid_t gid __unused)
HOOK_NOTIFY_IMPL(vnode_notify_setflags, struct ucred *cred __unused,
    struct vnode *vp __unused, u_long flags __unused)
HOOK_NOTIFY_IMPL(vnode_notify_setextattr, struct ucred *cred __unused,
    struct vnode *vp __unused, int attrnamespace __unused,
    const char *name __unused)
HOOK_NOTIFY_IMPL(vnode_notify_deleteextattr, struct ucred *cred __unused,
    struct vnode *vp __unused, int attrnamespace __unused,
    const char *name __unused)
HOOK_NOTIFY_IMPL(vnode_notify_setacl, struct ucred *cred __unused,
    struct vnode *vp __unused, acl_type_t type __unused)
HOOK_NOTIFY_IMPL(vnode_notify_setutimes, struct ucred *cred __unused,
    struct vnode *vp __unused)
HOOK_CHECK_IMPL(vnode_check_truncate, struct ucred *cred __unused,
    struct vnode *vp __unused, struct label *vplabel __unused)
HOOK_CHECK_IMPL(vnode_check_uipc_bind, struct ucred *cred __unused,
    struct vnode *dvp __unused, struct label *dvplabel __unused,
    struct componentname *cnp __unused, struct vattr *vap __unused)
HOOK_CHECK_IMPL(vnode_check_uipc_connect, struct ucred *cred __unused,
    struct vnode *vp __unused, struct label *vplabel __unused)
HOOK_CHECK_IMPL(socket_check_setsockopt, struct ucred *cred __unused,
    struct socket *so __unused, struct label *solabel __unused,
    int level __unused, int optname __unused)
HOOK_CHECK_IMPL(kld_check_unload, struct ucred *cred __unused)
HOOK_CHECK_IMPL(pts_check_open, struct ucred *cred __unused,
    int flags __unused)

static struct mac_policy_ops test_hooks_ops = {
	.mpo_proc_check_fork = test_proc_check_fork,
	.mpo_proc_check_core = test_proc_check_core,
	.mpo_proc_check_syscall = test_proc_check_syscall,
	.mpo_proc_check_mmap_anon = test_proc_check_mmap_anon,
	.mpo_proc_check_mprotect = test_proc_check_mprotect,
	.mpo_proc_notify_exec_complete = test_proc_notify_exec_complete,
	.mpo_proc_notify_exit = test_proc_notify_exit,
	.mpo_file_check_receive = test_file_check_receive,
	.mpo_file_check_inherit = test_file_check_inherit,
	.mpo_file_check_dup = test_file_check_dup,
	.mpo_file_check_ioctl = test_file_check_ioctl,
	.mpo_file_check_mmap = test_file_check_mmap,
	.mpo_file_notify_close = test_file_notify_close,
	.mpo_mount_check_mount = test_mount_check_mount,
	.mpo_mount_check_umount = test_mount_check_umount,
	.mpo_mount_check_remount = test_mount_check_remount,
	.mpo_mount_check_snapshot_create = test_mount_check_snapshot_create,
	.mpo_mount_check_snapshot_delete = test_mount_check_snapshot_delete,
	.mpo_mount_check_snapshot_revert = test_mount_check_snapshot_revert,
	.mpo_system_check_kas_info = test_system_check_kas_info,
	.mpo_vmm_check_create = test_vmm_check_create,
	.mpo_vnode_notify_create = test_vnode_notify_create,
	.mpo_vnode_notify_open = test_vnode_notify_open,
	.mpo_vnode_notify_rename = test_vnode_notify_rename,
	.mpo_vnode_notify_unlink = test_vnode_notify_unlink,
	.mpo_vnode_notify_link = test_vnode_notify_link,
	.mpo_vnode_notify_truncate = test_vnode_notify_truncate,
	.mpo_vnode_notify_setmode = test_vnode_notify_setmode,
	.mpo_vnode_notify_setowner = test_vnode_notify_setowner,
	.mpo_vnode_notify_setflags = test_vnode_notify_setflags,
	.mpo_vnode_notify_setextattr = test_vnode_notify_setextattr,
	.mpo_vnode_notify_deleteextattr = test_vnode_notify_deleteextattr,
	.mpo_vnode_notify_setacl = test_vnode_notify_setacl,
	.mpo_vnode_notify_setutimes = test_vnode_notify_setutimes,
	.mpo_vnode_check_truncate = test_vnode_check_truncate,
	.mpo_vnode_check_uipc_bind = test_vnode_check_uipc_bind,
	.mpo_vnode_check_uipc_connect = test_vnode_check_uipc_connect,
	.mpo_socket_check_setsockopt = test_socket_check_setsockopt,
	.mpo_kld_check_unload = test_kld_check_unload,
	.mpo_pts_check_open = test_pts_check_open,
};

MAC_POLICY_SET(&test_hooks_ops, mac_test_hooks, "TrustedBSD MAC/Test Hooks",
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);
