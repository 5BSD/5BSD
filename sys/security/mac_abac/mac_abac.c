/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 ABAC Project
 * All rights reserved.
 *
 * ABAC MAC Policy Module
 *
 * A label-based Mandatory Access Control policy for FreeBSD that stores
 * security labels in extended attributes and enforces access control
 * based on configurable rules.
 *
 * This file contains module registration, initialization, syscall handler,
 * and the mac_policy_ops structure. Implementation is split across:
 *   - abac_cred.c   - Credential label lifecycle and checks
 *   - abac_vnode.c  - Vnode label lifecycle and access checks
 *   - abac_proc.c   - Process checks and privilege grant
 *   - abac_label.c  - Label parsing and matching
 *   - abac_rules.c  - Rule engine
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/sbuf.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/ucred.h>
#include <sys/vnode.h>
#include <sys/extattr.h>
#include <sys/imgact.h>
#include <sys/acl.h>

#include <security/mac/mac_policy.h>

#include "mac_abac.h"
#include "abac_dtrace.h"

/*
 * DTrace provider and probe definitions
 *
 * Provider: abac
 * Usage: dtrace -n 'abac:::check-deny { printf("%s", stringof(arg0)); }'
 */
SDT_PROVIDER_DEFINE(abac);

/* Access check probes */
SDT_PROBE_DEFINE3(abac, rules, check, entry,
    "char *",		/* subject label string */
    "char *",		/* object label string */
    "uint32_t");	/* operation bitmask */

SDT_PROBE_DEFINE2(abac, rules, check, return,
    "int",		/* result (0=allow, EACCES=deny) */
    "uint32_t");	/* operation bitmask */

SDT_PROBE_DEFINE4(abac, rules, check, allow,
    "char *",		/* subject label string */
    "char *",		/* object label string */
    "uint32_t",		/* operation bitmask */
    "uint32_t");	/* matching rule ID (0=default policy) */

SDT_PROBE_DEFINE4(abac, rules, check, deny,
    "char *",		/* subject label string */
    "char *",		/* object label string */
    "uint32_t",		/* operation bitmask */
    "uint32_t");	/* matching rule ID (0=default policy) */

/* Rule matching probes */
SDT_PROBE_DEFINE3(abac, rules, rule, match,
    "uint32_t",		/* rule ID */
    "uint8_t",		/* action (0=allow, 1=deny, 2=transition) */
    "uint32_t");	/* operation bitmask */

SDT_PROBE_DEFINE2(abac, rules, rule, nomatch,
    "int",		/* default policy (0=allow, 1=deny) */
    "uint32_t");	/* operation bitmask */

/* Label transition probes */
SDT_PROBE_DEFINE4(abac, cred, transition, exec,
    "char *",		/* old label string */
    "char *",		/* new label string */
    "char *",		/* executable label string */
    "pid_t");		/* pid */

/* Label read probes */
SDT_PROBE_DEFINE2(abac, label, extattr, read,
    "char *",		/* label string */
    "struct vnode *");	/* vnode pointer */

SDT_PROBE_DEFINE1(abac, label, extattr, default,
    "int");		/* is_subject (1=process, 0=file) */

/* Rule management probes */
SDT_PROBE_DEFINE3(abac, rules, rule, add,
    "uint32_t",		/* rule ID */
    "uint8_t",		/* action */
    "uint32_t");	/* operations bitmask */

SDT_PROBE_DEFINE1(abac, rules, rule, remove,
    "uint32_t");	/* rule ID */

SDT_PROBE_DEFINE1(abac, rules, rule, clear,
    "uint32_t");	/* count of rules cleared */

/* Mode change probes */
SDT_PROBE_DEFINE2(abac, policy, mode, change,
    "int",		/* old mode */
    "int");		/* new mode */

/* Default policy change probe */
SDT_PROBE_DEFINE2(abac, policy, default, change,
    "int",		/* old default (0=allow, 1=deny) */
    "int");		/* new default */

/* Policy lock probe */
SDT_PROBE_DEFINE2(abac, policy, lock, set,
    "pid_t",		/* pid that locked */
    "uid_t");		/* uid that locked */

/* Log level change probe */
SDT_PROBE_DEFINE2(abac, policy, loglevel, change,
    "int",		/* old level */
    "int");		/* new level */

/* Set management probes */
SDT_PROBE_DEFINE2(abac, sets, set, enable,
    "uint16_t",		/* start set */
    "uint16_t");	/* end set */

SDT_PROBE_DEFINE2(abac, sets, set, disable,
    "uint16_t",		/* start set */
    "uint16_t");	/* end set */

SDT_PROBE_DEFINE2(abac, sets, set, swap,
    "uint16_t",		/* set_a */
    "uint16_t");	/* set_b */

SDT_PROBE_DEFINE2(abac, sets, set, move,
    "uint16_t",		/* from_set */
    "uint16_t");	/* to_set */

SDT_PROBE_DEFINE2(abac, sets, set, clear,
    "uint16_t",		/* set number */
    "uint32_t");	/* rules cleared */

/* Label management probe */
SDT_PROBE_DEFINE2(abac, label, file, set,
    "char *",		/* path */
    "char *");		/* label string */

/*
 * Global slot for storing our labels in MAC label structures
 */
int abac_slot;

/*
 * Configuration variables (exposed via sysctl)
 *
 * Note: These are accessed via sysctl which provides appropriate
 * synchronization. For check paths, stale reads are acceptable
 * as the mode change will eventually be visible.
 */
int abac_enabled = 1;
int abac_mode = ABAC_MODE_PERMISSIVE;	/* Start permissive for safety */

/*
 * Configurable extended attribute name.
 *
 * Default is "mac_abac" but can be changed to match other tools like
 * FreeBSDKit's maclabel tool (e.g., "mac_labels", "mac_policy").
 *
 * Note: Changing this while labels are in use may cause access issues.
 * Only change at boot via loader.conf or before loading policy rules.
 */
char abac_extattr_name[64] = ABAC_EXTATTR_NAME;

/*
 * Initialization flag - set only after all subsystems are ready.
 * This prevents hooks from being called before locks are initialized.
 */
int abac_initialized = 0;

/*
 * Default labels for unlabeled objects/subjects
 */
struct abac_label abac_default_object;
struct abac_label abac_default_subject;

/*
 * Statistics - accessed atomically via atomic_add_64()
 */
uint64_t abac_labels_read;
uint64_t abac_labels_default;

/*
 * Policy protection - locked mode
 *
 * Once locked, the policy cannot be modified until reboot.
 * This provides tamper resistance for production deployments.
 * The lock is one-way and resets only on module reload (reboot).
 */
int abac_locked = 0;

/*
 * Audit log level
 *
 * Controls what gets logged to the kernel message buffer.
 * Default: ABAC_LOG_ADMIN (log policy changes, not access checks)
 */
int abac_log_level = ABAC_LOG_ADMIN;

/*
 * SYSCTL tree: security.mac.mac_abac.*
 */
SYSCTL_DECL(_security_mac);
SYSCTL_NODE(_security_mac, OID_AUTO, mac_abac, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "ABAC MAC policy");

SYSCTL_INT(_security_mac_mac_abac, OID_AUTO, enabled, CTLFLAG_RW,
    &abac_enabled, 0, "Enable ABAC MAC policy");

SYSCTL_INT(_security_mac_mac_abac, OID_AUTO, mode, CTLFLAG_RW,
    &abac_mode, 0, "Enforcement mode (0=disabled, 1=permissive, 2=enforcing)");

SYSCTL_UQUAD(_security_mac_mac_abac, OID_AUTO, labels_read, CTLFLAG_RD,
    &abac_labels_read, 0, "Labels read from extended attributes");

SYSCTL_UQUAD(_security_mac_mac_abac, OID_AUTO, labels_default, CTLFLAG_RD,
    &abac_labels_default, 0, "Default labels assigned");

SYSCTL_STRING(_security_mac_mac_abac, OID_AUTO, extattr_name, CTLFLAG_RW,
    abac_extattr_name, sizeof(abac_extattr_name),
    "Extended attribute name for labels (default: mac_abac)");

SYSCTL_INT(_security_mac_mac_abac, OID_AUTO, locked, CTLFLAG_RD,
    &abac_locked, 0, "Policy locked (1=locked until reboot, 0=unlocked)");

SYSCTL_INT(_security_mac_mac_abac, OID_AUTO, log_level, CTLFLAG_RW,
    &abac_log_level, 0,
    "Audit log level (0=none, 1=error, 2=admin, 3=deny, 4=all)");

/*
 * Policy lifecycle
 */
static void abac_destroy(struct mac_policy_conf *mpc);
static void abac_init(struct mac_policy_conf *mpc);
static int abac_syscall(struct thread *td, int call, void *arg);

/*
 * MAC policy operations structure
 */
static struct mac_policy_ops abac_ops = {
	/* Policy lifecycle */
	.mpo_destroy = abac_destroy,
	.mpo_init = abac_init,
	.mpo_syscall = abac_syscall,

	/* Credential label lifecycle */
	.mpo_cred_init_label = abac_cred_init_label,
	.mpo_cred_destroy_label = abac_cred_destroy_label,
	.mpo_cred_copy_label = abac_cred_copy_label,
	.mpo_cred_relabel = abac_cred_relabel,
	.mpo_cred_externalize_label = abac_cred_externalize_label,
	.mpo_cred_internalize_label = abac_cred_internalize_label,

	/* Credential checks */
	.mpo_cred_check_relabel = abac_cred_check_relabel,
	.mpo_cred_check_setuid = abac_cred_check_setuid,
	.mpo_cred_check_seteuid = abac_cred_check_seteuid,
	.mpo_cred_check_setgid = abac_cred_check_setgid,
	.mpo_cred_check_setegid = abac_cred_check_setegid,
	.mpo_cred_check_setgroups = abac_cred_check_setgroups,
	.mpo_cred_check_setreuid = abac_cred_check_setreuid,
	.mpo_cred_check_setregid = abac_cred_check_setregid,
	.mpo_cred_check_setresuid = abac_cred_check_setresuid,
	.mpo_cred_check_setresgid = abac_cred_check_setresgid,
	.mpo_cred_check_setcred = abac_cred_check_setcred,
	.mpo_cred_check_setaudit = abac_cred_check_setaudit,
	.mpo_cred_check_setaudit_addr = abac_cred_check_setaudit_addr,
	.mpo_cred_check_setauid = abac_cred_check_setauid,

	/* Process exec transition */
	.mpo_vnode_execve_transition = abac_execve_transition,
	.mpo_vnode_execve_will_transition = abac_execve_will_transition,

	/* Vnode label lifecycle */
	.mpo_vnode_init_label = abac_vnode_init_label,
	.mpo_vnode_destroy_label = abac_vnode_destroy_label,
	.mpo_vnode_copy_label = abac_vnode_copy_label,
	.mpo_vnode_associate_extattr = abac_vnode_associate_extattr,
	.mpo_vnode_associate_singlelabel = abac_vnode_associate_singlelabel,
	.mpo_vnode_create_extattr = abac_vnode_create_extattr,

	/* Vnode access checks */
	.mpo_vnode_check_access = abac_vnode_check_access,
	.mpo_vnode_check_chdir = abac_vnode_check_chdir,
	.mpo_vnode_check_chroot = abac_vnode_check_chroot,
	.mpo_vnode_check_create = abac_vnode_check_create,
	.mpo_vnode_check_deleteacl = abac_vnode_check_deleteacl,
	.mpo_vnode_check_deleteextattr = abac_vnode_check_deleteextattr,
	.mpo_vnode_check_exec = abac_vnode_check_exec,
	.mpo_vnode_check_getacl = abac_vnode_check_getacl,
	.mpo_vnode_check_getextattr = abac_vnode_check_getextattr,
	.mpo_vnode_check_link = abac_vnode_check_link,
	.mpo_vnode_check_listextattr = abac_vnode_check_listextattr,
	.mpo_vnode_check_lookup = abac_vnode_check_lookup,
	.mpo_vnode_check_mmap = abac_vnode_check_mmap,
	.mpo_vnode_check_mprotect = abac_vnode_check_mprotect,
	.mpo_vnode_check_open = abac_vnode_check_open,
	.mpo_vnode_check_poll = abac_vnode_check_poll,
	.mpo_vnode_check_read = abac_vnode_check_read,
	.mpo_vnode_check_readdir = abac_vnode_check_readdir,
	.mpo_vnode_check_readlink = abac_vnode_check_readlink,
	.mpo_vnode_check_relabel = abac_vnode_check_relabel,
	.mpo_vnode_check_rename_from = abac_vnode_check_rename_from,
	.mpo_vnode_check_rename_to = abac_vnode_check_rename_to,
	.mpo_vnode_check_revoke = abac_vnode_check_revoke,
	.mpo_vnode_check_setacl = abac_vnode_check_setacl,
	.mpo_vnode_check_setextattr = abac_vnode_check_setextattr,
	.mpo_vnode_check_setflags = abac_vnode_check_setflags,
	.mpo_vnode_check_setmode = abac_vnode_check_setmode,
	.mpo_vnode_check_setowner = abac_vnode_check_setowner,
	.mpo_vnode_check_setutimes = abac_vnode_check_setutimes,
	.mpo_vnode_check_stat = abac_vnode_check_stat,
	.mpo_vnode_check_unlink = abac_vnode_check_unlink,
	.mpo_vnode_check_write = abac_vnode_check_write,
	.mpo_vnode_check_mmap_downgrade = abac_vnode_check_mmap_downgrade,
	.mpo_vnode_setlabel_extattr = abac_vnode_setlabel_extattr,

	/* Mount label lifecycle */
	.mpo_mount_init_label = abac_mount_init_label,
	.mpo_mount_destroy_label = abac_mount_destroy_label,

	/* Process checks */
	.mpo_proc_check_debug = abac_proc_check_debug,
	.mpo_proc_check_sched = abac_proc_check_sched,
	.mpo_proc_check_signal = abac_proc_check_signal,
	.mpo_proc_check_wait = abac_proc_check_wait,

	/* Socket label lifecycle */
	.mpo_socket_init_label = abac_socket_init_label,
	.mpo_socket_destroy_label = abac_socket_destroy_label,
	.mpo_socket_copy_label = abac_socket_copy_label,
	.mpo_socket_create = abac_socket_create,
	.mpo_socket_newconn = abac_socket_newconn,

	/* Socket checks */
	.mpo_socket_check_accept = abac_socket_check_accept,
	.mpo_socket_check_bind = abac_socket_check_bind,
	.mpo_socket_check_connect = abac_socket_check_connect,
	.mpo_socket_check_create = abac_socket_check_create,
	.mpo_socket_check_listen = abac_socket_check_listen,
	.mpo_socket_check_poll = abac_socket_check_poll,
	.mpo_socket_check_receive = abac_socket_check_receive,
	.mpo_socket_check_send = abac_socket_check_send,
	.mpo_socket_check_stat = abac_socket_check_stat,
	.mpo_socket_check_visible = abac_socket_check_visible,
	.mpo_socket_check_deliver = abac_socket_check_deliver,

	/* Socketpeer label lifecycle */
	.mpo_socketpeer_init_label = abac_socketpeer_init_label,
	.mpo_socketpeer_destroy_label = abac_socketpeer_destroy_label,
	.mpo_socketpeer_set_from_mbuf = abac_socketpeer_set_from_mbuf,
	.mpo_socketpeer_set_from_socket = abac_socketpeer_set_from_socket,

	/* Pipe label lifecycle */
	.mpo_pipe_init_label = abac_pipe_init_label,
	.mpo_pipe_destroy_label = abac_pipe_destroy_label,
	.mpo_pipe_copy_label = abac_pipe_copy_label,
	.mpo_pipe_create = abac_pipe_create,

	/* Pipe checks */
	.mpo_pipe_check_ioctl = abac_pipe_check_ioctl,
	.mpo_pipe_check_poll = abac_pipe_check_poll,
	.mpo_pipe_check_read = abac_pipe_check_read,
	.mpo_pipe_check_relabel = abac_pipe_check_relabel,
	.mpo_pipe_check_stat = abac_pipe_check_stat,
	.mpo_pipe_check_write = abac_pipe_check_write,

	/* POSIX shm label lifecycle */
	.mpo_posixshm_init_label = abac_posixshm_init_label,
	.mpo_posixshm_destroy_label = abac_posixshm_destroy_label,
	.mpo_posixshm_create = abac_posixshm_create,

	/* POSIX shm checks */
	.mpo_posixshm_check_create = abac_posixshm_check_create,
	.mpo_posixshm_check_mmap = abac_posixshm_check_mmap,
	.mpo_posixshm_check_open = abac_posixshm_check_open,
	.mpo_posixshm_check_read = abac_posixshm_check_read,
	.mpo_posixshm_check_setmode = abac_posixshm_check_setmode,
	.mpo_posixshm_check_setowner = abac_posixshm_check_setowner,
	.mpo_posixshm_check_stat = abac_posixshm_check_stat,
	.mpo_posixshm_check_truncate = abac_posixshm_check_truncate,
	.mpo_posixshm_check_unlink = abac_posixshm_check_unlink,
	.mpo_posixshm_check_write = abac_posixshm_check_write,

	/* Privilege hooks */
	.mpo_priv_check = abac_priv_check,
	.mpo_priv_grant = abac_priv_grant,

	/* System-level checks */
	.mpo_kld_check_load = abac_kld_check_load,
	.mpo_kld_check_stat = abac_kld_check_stat,
	.mpo_system_check_reboot = abac_system_check_reboot,
	.mpo_system_check_sysctl = abac_system_check_sysctl,
	.mpo_system_check_acct = abac_system_check_acct,
	.mpo_system_check_swapon = abac_system_check_swapon,
	.mpo_system_check_swapoff = abac_system_check_swapoff,
	.mpo_system_check_audit = abac_system_check_audit,
	.mpo_system_check_auditctl = abac_system_check_auditctl,
	.mpo_system_check_auditon = abac_system_check_auditon,
	.mpo_mount_check_stat = abac_mount_check_stat,

	/* Kernel environment (kenv) checks */
	.mpo_kenv_check_dump = abac_kenv_check_dump,
	.mpo_kenv_check_get = abac_kenv_check_get,
	.mpo_kenv_check_set = abac_kenv_check_set,
	.mpo_kenv_check_unset = abac_kenv_check_unset,

	/* POSIX semaphore lifecycle */
	.mpo_posixsem_init_label = abac_posixsem_init_label,
	.mpo_posixsem_destroy_label = abac_posixsem_destroy_label,
	.mpo_posixsem_create = abac_posixsem_create,

	/* POSIX semaphore checks */
	.mpo_posixsem_check_getvalue = abac_posixsem_check_getvalue,
	.mpo_posixsem_check_open = abac_posixsem_check_open,
	.mpo_posixsem_check_post = abac_posixsem_check_post,
	.mpo_posixsem_check_setmode = abac_posixsem_check_setmode,
	.mpo_posixsem_check_setowner = abac_posixsem_check_setowner,
	.mpo_posixsem_check_stat = abac_posixsem_check_stat,
	.mpo_posixsem_check_unlink = abac_posixsem_check_unlink,
	.mpo_posixsem_check_wait = abac_posixsem_check_wait,

	/* SysV message queue message lifecycle */
	.mpo_sysvmsg_init_label = abac_sysvmsg_init_label,
	.mpo_sysvmsg_destroy_label = abac_sysvmsg_destroy_label,
	.mpo_sysvmsg_cleanup = abac_sysvmsg_cleanup,
	.mpo_sysvmsg_create = abac_sysvmsg_create,

	/* SysV message queue lifecycle */
	.mpo_sysvmsq_init_label = abac_sysvmsq_init_label,
	.mpo_sysvmsq_destroy_label = abac_sysvmsq_destroy_label,
	.mpo_sysvmsq_cleanup = abac_sysvmsq_cleanup,
	.mpo_sysvmsq_create = abac_sysvmsq_create,

	/* SysV message queue checks */
	.mpo_sysvmsq_check_msgmsq = abac_sysvmsq_check_msgmsq,
	.mpo_sysvmsq_check_msgrcv = abac_sysvmsq_check_msgrcv,
	.mpo_sysvmsq_check_msgrmid = abac_sysvmsq_check_msgrmid,
	.mpo_sysvmsq_check_msqget = abac_sysvmsq_check_msqget,
	.mpo_sysvmsq_check_msqctl = abac_sysvmsq_check_msqctl,
	.mpo_sysvmsq_check_msqrcv = abac_sysvmsq_check_msqrcv,
	.mpo_sysvmsq_check_msqsnd = abac_sysvmsq_check_msqsnd,

	/* SysV semaphore lifecycle */
	.mpo_sysvsem_init_label = abac_sysvsem_init_label,
	.mpo_sysvsem_destroy_label = abac_sysvsem_destroy_label,
	.mpo_sysvsem_cleanup = abac_sysvsem_cleanup,
	.mpo_sysvsem_create = abac_sysvsem_create,

	/* SysV semaphore checks */
	.mpo_sysvsem_check_semctl = abac_sysvsem_check_semctl,
	.mpo_sysvsem_check_semget = abac_sysvsem_check_semget,
	.mpo_sysvsem_check_semop = abac_sysvsem_check_semop,

	/* SysV shared memory lifecycle */
	.mpo_sysvshm_init_label = abac_sysvshm_init_label,
	.mpo_sysvshm_destroy_label = abac_sysvshm_destroy_label,
	.mpo_sysvshm_cleanup = abac_sysvshm_cleanup,
	.mpo_sysvshm_create = abac_sysvshm_create,

	/* SysV shared memory checks */
	.mpo_sysvshm_check_shmat = abac_sysvshm_check_shmat,
	.mpo_sysvshm_check_shmctl = abac_sysvshm_check_shmctl,
	.mpo_sysvshm_check_shmdt = abac_sysvshm_check_shmdt,
	.mpo_sysvshm_check_shmget = abac_sysvshm_check_shmget,
};

/*
 * Policy lifecycle implementation
 */

static void
abac_init(struct mac_policy_conf *mpc)
{


	/* Initialize label subsystem (UMA zone) */
	abac_label_init();

	/* Initialize rule engine */
	abac_rules_init();

	/* Initialize default labels */
	abac_label_set_default(&abac_default_object, false);
	abac_label_set_default(&abac_default_subject, true);

	/* Mark as initialized - hooks can now safely run */
	abac_initialized = 1;

}

static void
abac_destroy(struct mac_policy_conf *mpc)
{


	/* Destroy rule engine */
	abac_rules_destroy();

	/* Destroy label subsystem (UMA zone) */
	abac_label_destroy();

}

/*
 * mac_syscall handler - main control interface
 *
 * Called via: mac_syscall("mac_abac", cmd, arg)
 * All commands require root.
 */
static int
abac_syscall(struct thread *td, int call, void *arg)
{
	int error, val;
	uint32_t rule_id;
	struct abac_stats stats;
	struct abac_rule_arg rule_arg;
	struct abac_rule_list_arg list_arg;
	struct abac_test_arg test_arg;
	char *data;
	size_t data_len;

	/* All commands require root */
	error = priv_check(td, PRIV_MAC_PARTITION);
	if (error)
		return (error);

	switch (call) {
	case ABAC_SYS_GETMODE:
		error = copyout(&abac_mode, arg, sizeof(int));
		break;

	case ABAC_SYS_SETMODE:
		if (abac_locked) {
			error = EPERM;
			if (abac_log_level >= ABAC_LOG_ADMIN)
				log(LOG_WARNING, "abac: SETMODE denied - policy locked\n");
			break;
		}
		error = copyin(arg, &val, sizeof(int));
		if (error)
			break;
		if (val < ABAC_MODE_DISABLED || val > ABAC_MODE_ENFORCING) {
			error = EINVAL;
			break;
		}
		SDT_PROBE2(abac, policy, mode, change, abac_mode, val);
		if (abac_log_level >= ABAC_LOG_ADMIN)
			log(LOG_NOTICE, "abac: mode changed %d -> %d by pid %d uid %d\n",
			    abac_mode, val, td->td_proc->p_pid, td->td_ucred->cr_uid);
		abac_mode = val;
		break;

	case ABAC_SYS_GETSTATS:
		abac_rules_get_stats(&stats);
		error = copyout(&stats, arg, sizeof(stats));
		break;

	case ABAC_SYS_GETDEFPOL:
		error = copyout(&abac_default_policy, arg, sizeof(int));
		break;

	case ABAC_SYS_SETDEFPOL:
		if (abac_locked) {
			error = EPERM;
			if (abac_log_level >= ABAC_LOG_ADMIN)
				log(LOG_WARNING, "abac: SETDEFPOL denied - policy locked\n");
			break;
		}
		error = copyin(arg, &val, sizeof(int));
		if (error)
			break;
		SDT_PROBE2(abac, policy, default, change,
		    abac_default_policy, val);
		if (abac_log_level >= ABAC_LOG_ADMIN)
			log(LOG_NOTICE, "abac: default policy changed %d -> %d by pid %d uid %d\n",
			    abac_default_policy, val, td->td_proc->p_pid, td->td_ucred->cr_uid);
		abac_default_policy = val;
		break;

	case ABAC_SYS_RULE_ADD:
		if (abac_locked) {
			error = EPERM;
			if (abac_log_level >= ABAC_LOG_ADMIN)
				log(LOG_WARNING, "abac: RULE_ADD denied - policy locked\n");
			break;
		}
		/* Copyin the header */
		error = copyin(arg, &rule_arg, sizeof(rule_arg));
		if (error)
			break;

		/*
		 * Validate individual lengths before summing to prevent
		 * integer overflow attacks.
		 */
		if (rule_arg.vr_subject_len > ABAC_MAX_LABEL_LEN ||
		    rule_arg.vr_object_len > ABAC_MAX_LABEL_LEN ||
		    rule_arg.vr_newlabel_len > ABAC_MAX_LABEL_LEN) {
			error = EINVAL;
			break;
		}

		/* Calculate and copyin variable data */
		data_len = rule_arg.vr_subject_len + rule_arg.vr_object_len +
		    rule_arg.vr_newlabel_len;

		data = malloc(data_len, M_TEMP, M_WAITOK);
		error = copyin((char *)arg + sizeof(rule_arg), data, data_len);
		if (error) {
			free(data, M_TEMP);
			break;
		}

		error = abac_rule_add_from_arg(&rule_arg, data);
		free(data, M_TEMP);
		if (error == 0) {
			/* Copyout the updated arg with assigned rule ID */
			error = copyout(&rule_arg, arg, sizeof(rule_arg));
			if (abac_log_level >= ABAC_LOG_ADMIN)
				log(LOG_NOTICE, "abac: rule %u added (set %u) by pid %d uid %d\n",
				    rule_arg.vr_id, rule_arg.vr_set,
				    td->td_proc->p_pid, td->td_ucred->cr_uid);
		}
		break;

	case ABAC_SYS_RULE_REMOVE:
		if (abac_locked) {
			error = EPERM;
			if (abac_log_level >= ABAC_LOG_ADMIN)
				log(LOG_WARNING, "abac: RULE_REMOVE denied - policy locked\n");
			break;
		}
		error = copyin(arg, &rule_id, sizeof(uint32_t));
		if (error)
			break;
		error = abac_rule_remove(rule_id);
		if (error == 0 && abac_log_level >= ABAC_LOG_ADMIN)
			log(LOG_NOTICE, "abac: rule %u removed by pid %d uid %d\n",
			    rule_id, td->td_proc->p_pid, td->td_ucred->cr_uid);
		break;

	case ABAC_SYS_RULE_CLEAR:
		if (abac_locked) {
			error = EPERM;
			if (abac_log_level >= ABAC_LOG_ADMIN)
				log(LOG_WARNING, "abac: RULE_CLEAR denied - policy locked\n");
			break;
		}
		if (abac_log_level >= ABAC_LOG_ADMIN)
			log(LOG_NOTICE, "abac: all rules cleared by pid %d uid %d\n",
			    td->td_proc->p_pid, td->td_ucred->cr_uid);
		abac_rules_clear();
		error = 0;
		break;

	case ABAC_SYS_RULE_LOAD:
		{
			struct abac_rule_load_arg load_arg;

			if (abac_locked) {
				error = EPERM;
				if (abac_log_level >= ABAC_LOG_ADMIN)
					log(LOG_WARNING, "abac: RULE_LOAD denied - policy locked\n");
				break;
			}
			error = copyin(arg, &load_arg, sizeof(load_arg));
			if (error)
				break;
			error = abac_rules_load(&load_arg);
			if (error == 0) {
				error = copyout(&load_arg, arg, sizeof(load_arg));
				if (abac_log_level >= ABAC_LOG_ADMIN)
					log(LOG_NOTICE, "abac: %u rules loaded by pid %d uid %d\n",
					    load_arg.vrl_count, td->td_proc->p_pid, td->td_ucred->cr_uid);
			}
		}
		break;

	case ABAC_SYS_RULE_LIST:
		error = copyin(arg, &list_arg, sizeof(list_arg));
		if (error)
			break;
		error = abac_rules_list(&list_arg);
		if (error == 0)
			error = copyout(&list_arg, arg, sizeof(list_arg));
		break;

	case ABAC_SYS_TEST:
		error = copyin(arg, &test_arg, sizeof(test_arg));
		if (error)
			break;

		/*
		 * Validate individual lengths before summing to prevent
		 * integer overflow attacks.
		 */
		if (test_arg.vt_subject_len > ABAC_MAX_LABEL_LEN ||
		    test_arg.vt_object_len > ABAC_MAX_LABEL_LEN) {
			error = EINVAL;
			break;
		}

		/* Copyin variable data */
		data_len = test_arg.vt_subject_len + test_arg.vt_object_len;

		data = malloc(data_len, M_TEMP, M_WAITOK);
		error = copyin((char *)arg + sizeof(test_arg), data, data_len);
		if (error) {
			free(data, M_TEMP);
			break;
		}

		error = abac_rules_test_access(
		    data, test_arg.vt_subject_len,
		    data + test_arg.vt_subject_len, test_arg.vt_object_len,
		    test_arg.vt_operation,
		    &test_arg.vt_result, &test_arg.vt_rule_id);
		free(data, M_TEMP);

		if (error == 0)
			error = copyout(&test_arg, arg, sizeof(test_arg));
		break;

	case ABAC_SYS_REFRESH:
		/*
		 * Refresh a file's cached vnode label by re-reading from extattr.
		 * arg is a pointer to a file descriptor.
		 *
		 * This enables live relabeling on filesystems that don't support
		 * MNT_MULTILABEL (like ZFS). After setextattr writes the new
		 * label to disk, this syscall updates the in-memory cached label.
		 */
		error = copyin(arg, &val, sizeof(int));
		if (error)
			break;
		{
			struct file *fp;
			struct vnode *vp;

			error = fget(td, val, &cap_no_rights, &fp);
			if (error)
				break;

			if (fp->f_type != DTYPE_VNODE) {
				fdrop(fp, td);
				error = EINVAL;
				break;
			}

			vp = fp->f_vnode;
			if (vp != NULL && vp->v_label != NULL) {
				vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
				abac_vnode_refresh_label(vp, vp->v_label);
				VOP_UNLOCK(vp);
			}

			fdrop(fp, td);
			error = 0;
		}
		break;

	case ABAC_SYS_SETLABEL:
		/*
		 * Atomically set a file's label: write to extattr AND update
		 * the in-memory cached label in a single syscall.
		 *
		 * This is the preferred method for relabeling on ZFS and other
		 * filesystems that don't support MNT_MULTILABEL. It avoids the
		 * race condition of separate setextattr + ABAC_SYS_REFRESH.
		 *
		 * Layout: struct abac_setlabel_arg + label string
		 */
		{
			struct abac_setlabel_arg setlabel_arg;
			struct file *fp;
			struct vnode *vp;
			struct abac_label *vl;
			char *label_buf;
			int label_len;

			error = copyin(arg, &setlabel_arg, sizeof(setlabel_arg));
			if (error)
				break;

			/* Validate label length */
			if (setlabel_arg.vsl_label_len == 0 ||
			    setlabel_arg.vsl_label_len > ABAC_MAX_LABEL_LEN) {
				error = EINVAL;
				break;
			}

			/* Copyin the label string */
			label_buf = malloc(setlabel_arg.vsl_label_len, M_TEMP, M_WAITOK);
			error = copyin((char *)arg + sizeof(setlabel_arg),
			    label_buf, setlabel_arg.vsl_label_len);
			if (error) {
				free(label_buf, M_TEMP);
				break;
			}

			/* Ensure null termination */
			label_buf[setlabel_arg.vsl_label_len - 1] = '\0';
			label_len = strlen(label_buf);

			/* Get the vnode from the file descriptor */
			error = fget(td, setlabel_arg.vsl_fd, &cap_no_rights, &fp);
			if (error) {
				free(label_buf, M_TEMP);
				break;
			}

			if (fp->f_type != DTYPE_VNODE) {
				fdrop(fp, td);
				free(label_buf, M_TEMP);
				error = EINVAL;
				break;
			}

			vp = fp->f_vnode;
			if (vp == NULL) {
				fdrop(fp, td);
				free(label_buf, M_TEMP);
				error = EINVAL;
				break;
			}

			/* Lock vnode for exclusive access */
			vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);

			/* Step 1: Write to extended attribute */
			error = vn_extattr_set(vp, IO_NODELOCKED,
			    ABAC_EXTATTR_NAMESPACE, abac_extattr_name,
			    label_len, label_buf, td);

			if (error == 0 && vp->v_label != NULL) {
				/* Step 2: Update in-memory label */
				vl = SLOT(vp->v_label);
				if (vl != NULL) {
					error = abac_label_parse(label_buf,
					    label_len, vl);
				}
			}

			if (error == 0)
				SDT_PROBE2(abac, label, file, set,
				    "(fd-based)", label_buf);

			VOP_UNLOCK(vp);
			fdrop(fp, td);
			free(label_buf, M_TEMP);
		}
		break;

	case ABAC_SYS_SET_ENABLE:
		{
			struct abac_set_range range;

			if (abac_locked) {
				error = EPERM;
				if (abac_log_level >= ABAC_LOG_ADMIN)
					log(LOG_WARNING, "abac: SET_ENABLE denied - policy locked\n");
				break;
			}
			error = copyin(arg, &range, sizeof(range));
			if (error)
				break;
			if (range.vsr_end < range.vsr_start) {
				error = EINVAL;
				break;
			}
			abac_set_enable_range(range.vsr_start, range.vsr_end);
			SDT_PROBE2(abac, sets, set, enable,
			    range.vsr_start, range.vsr_end);
			if (abac_log_level >= ABAC_LOG_ADMIN)
				log(LOG_NOTICE, "abac: sets %u-%u enabled by pid %d uid %d\n",
				    range.vsr_start, range.vsr_end,
				    td->td_proc->p_pid, td->td_ucred->cr_uid);
			error = 0;
		}
		break;

	case ABAC_SYS_SET_DISABLE:
		{
			struct abac_set_range range;

			if (abac_locked) {
				error = EPERM;
				if (abac_log_level >= ABAC_LOG_ADMIN)
					log(LOG_WARNING, "abac: SET_DISABLE denied - policy locked\n");
				break;
			}
			error = copyin(arg, &range, sizeof(range));
			if (error)
				break;
			if (range.vsr_end < range.vsr_start) {
				error = EINVAL;
				break;
			}
			abac_set_disable_range(range.vsr_start, range.vsr_end);
			SDT_PROBE2(abac, sets, set, disable,
			    range.vsr_start, range.vsr_end);
			if (abac_log_level >= ABAC_LOG_ADMIN)
				log(LOG_NOTICE, "abac: sets %u-%u disabled by pid %d uid %d\n",
				    range.vsr_start, range.vsr_end,
				    td->td_proc->p_pid, td->td_ucred->cr_uid);
			error = 0;
		}
		break;

	case ABAC_SYS_SET_SWAP:
		{
			uint16_t sets[2];

			if (abac_locked) {
				error = EPERM;
				if (abac_log_level >= ABAC_LOG_ADMIN)
					log(LOG_WARNING, "abac: SET_SWAP denied - policy locked\n");
				break;
			}
			error = copyin(arg, sets, sizeof(sets));
			if (error)
				break;
			error = abac_set_swap(sets[0], sets[1]);
			if (error == 0) {
				SDT_PROBE2(abac, sets, set, swap, sets[0], sets[1]);
				if (abac_log_level >= ABAC_LOG_ADMIN)
					log(LOG_NOTICE, "abac: sets %u <-> %u swapped by pid %d uid %d\n",
					    sets[0], sets[1], td->td_proc->p_pid, td->td_ucred->cr_uid);
			}
		}
		break;

	case ABAC_SYS_SET_MOVE:
		{
			uint16_t sets[2];

			if (abac_locked) {
				error = EPERM;
				if (abac_log_level >= ABAC_LOG_ADMIN)
					log(LOG_WARNING, "abac: SET_MOVE denied - policy locked\n");
				break;
			}
			error = copyin(arg, sets, sizeof(sets));
			if (error)
				break;
			error = abac_set_move(sets[0], sets[1]);
			if (error == 0) {
				SDT_PROBE2(abac, sets, set, move, sets[0], sets[1]);
				if (abac_log_level >= ABAC_LOG_ADMIN)
					log(LOG_NOTICE, "abac: set %u -> %u moved by pid %d uid %d\n",
					    sets[0], sets[1], td->td_proc->p_pid, td->td_ucred->cr_uid);
			}
		}
		break;

	case ABAC_SYS_SET_CLEAR:
		{
			uint16_t set;

			if (abac_locked) {
				error = EPERM;
				if (abac_log_level >= ABAC_LOG_ADMIN)
					log(LOG_WARNING, "abac: SET_CLEAR denied - policy locked\n");
				break;
			}
			error = copyin(arg, &set, sizeof(set));
			if (error)
				break;
			abac_set_clear(set);
			SDT_PROBE2(abac, sets, set, clear, set, (uint32_t)0);
			if (abac_log_level >= ABAC_LOG_ADMIN)
				log(LOG_NOTICE, "abac: set %u cleared by pid %d uid %d\n",
				    set, td->td_proc->p_pid, td->td_ucred->cr_uid);
			error = 0;
		}
		break;

	case ABAC_SYS_SET_LIST:
		{
			struct abac_set_list_arg set_list_arg;

			error = copyin(arg, &set_list_arg, sizeof(set_list_arg));
			if (error)
				break;
			abac_set_get_info(&set_list_arg);
			error = copyout(&set_list_arg, arg, sizeof(set_list_arg));
		}
		break;

	case ABAC_SYS_LOCK:
		/* One-way lock - once locked, stays locked until reboot */
		if (abac_locked) {
			/* Already locked, treat as success */
			error = 0;
		} else {
			abac_locked = 1;
			SDT_PROBE2(abac, policy, lock, set,
			    td->td_proc->p_pid, td->td_ucred->cr_uid);
			if (abac_log_level >= ABAC_LOG_ADMIN)
				log(LOG_NOTICE, "abac: policy LOCKED by pid %d uid %d\n",
				    td->td_proc->p_pid, td->td_ucred->cr_uid);
			error = 0;
		}
		break;

	case ABAC_SYS_GETLOCKED:
		error = copyout(&abac_locked, arg, sizeof(int));
		break;

	case ABAC_SYS_GETLOGLEVEL:
		error = copyout(&abac_log_level, arg, sizeof(int));
		break;

	case ABAC_SYS_SETLOGLEVEL:
		error = copyin(arg, &val, sizeof(int));
		if (error)
			break;
		if (val < ABAC_LOG_NONE || val > ABAC_LOG_ALL) {
			error = EINVAL;
			break;
		}
		SDT_PROBE2(abac, policy, loglevel, change,
		    abac_log_level, val);
		if (abac_log_level >= ABAC_LOG_ADMIN)
			log(LOG_NOTICE, "abac: log level changed %d -> %d by pid %d uid %d\n",
			    abac_log_level, val, td->td_proc->p_pid, td->td_ucred->cr_uid);
		abac_log_level = val;
		break;

	default:
		error = EINVAL;
		break;
	}

	return (error);
}

/*
 * Module registration
 *
 * We use no loadtime flags (0) because:
 * 1. We want to allow loading after boot for development/testing
 * 2. We do NOT allow unloading (no UNLOADOK flag) because MAC modules
 *    with UMA zones cannot safely unload - labels may still be attached
 *    to kernel objects (vnodes, creds) when mpo_destroy is called
 *
 * Flag behavior:
 *   - MPC_LOADTIME_FLAG_NOTLATE: Cannot load after boot
 *   - MPC_LOADTIME_FLAG_UNLOADOK: Can unload at runtime
 *   - 0 (no flags): Can load after boot, cannot unload
 *
 * This follows the pattern of MAC modules that allocate per-object labels.
 * To update the module during development, reboot the VM first.
 */
MAC_POLICY_SET(&abac_ops, mac_abac, "ABAC MAC Policy",
    0, &abac_slot);
