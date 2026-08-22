/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard <koryheard@icloud.com>
 * All rights reserved.
 *
 * Open Endpoint Security (OES) - Public Header
 *
 * This header defines the userspace API for the oes(4) framework.
 * The framework provides capability-based security event monitoring
 * and authorization, inspired by Apple's Endpoint Security but
 * designed around FreeBSD's Capsicum model.
 */

#ifndef _SYS_OES_H_
#define _SYS_OES_H_

#include <sys/types.h>
#include <sys/ioccom.h>
#include <sys/param.h>

#include "oes_event_table.h"

#ifndef __LP64__
#error "OpenEndpointSecurity requires a 64-bit kernel and userspace"
#endif

/*
 * API Version - increment when the public API or ioctl contract changes
 */
#define OES_API_VERSION		1

/*
 * Event Types
 *
 * AUTH events (0x0001-0x0FFF): Sleepable hooks that can block for response.
 * NOTIFY events (0x1001-0x1FFF): Informational, never block.
 */
typedef enum {
#define OES_ENUM_EVENT(name, value)	name = value,
	OES_AUTH_EVENT_LIST(OES_ENUM_EVENT)
	OES_NOTIFY_EVENT_LIST(OES_ENUM_EVENT)
#undef OES_ENUM_EVENT
} oes_event_type_t;

#define OES_EVENT_IS_AUTH(e)	(((e) & 0x1000) == 0)
#define OES_EVENT_IS_NOTIFY(e)	(((e) & 0x1000) != 0)

/*
 * Canonical subscription bitmaps for all currently defined event types.
 * Bit positions are (event & 0x0FFF), split into low/high 64-bit words.
 */
#define OES_AUTH_EVENT_MASK_LO		0x607FFFFFFFEULL
#define OES_AUTH_EVENT_MASK_HI		0x0ULL
#define OES_NOTIFY_EVENT_MASK_LO	0xFFFFFFFFFFFFEBFEULL
#define OES_NOTIFY_EVENT_MASK_HI	0x7ULL

/*
 * Event coverage notes:
 *
 * - NOTIFY_CLOSE: implemented via the mac_vnode_check_close hook added to the
 *   MAC framework.  A close cannot be denied, so this event is NOTIFY-only.
 *
 * - AUTH_TRUNCATE/NOTIFY_TRUNCATE, AUTH_UNMOUNT, AUTH_KLDUNLOAD: the required
 *   MAC hooks now exist in the framework (mac_vnode_check_truncate,
 *   mac_mount_check_unmount, mac_kld_check_unload); wiring these AUTH events to
 *   them is pending.  NOTIFY_UNMOUNT and NOTIFY_KLDUNLOAD are already delivered
 *   via the vfs_unmounted and kld_unload eventhandlers.
 *
 * NOSLEEP limitation (NOTIFY-only events):
 *
 * The following events use NOSLEEP MAC hooks or eventhandlers that
 * cannot block the calling thread. They are available as NOTIFY events
 * only; subscribing to AUTH versions of these will have no effect:
 *
 *   socket_connect, socket_bind, socket_listen, socket_create,
 *   socket_accept, socket_send, socket_receive, socket_stat,
 *   socket_poll, pipe_read, pipe_write, pipe_stat, pipe_poll,
 *   pipe_ioctl, reboot, sysctl, kenv, signal, setuid, setgid,
 *   mount_stat, priv_check, proc_sched, unmount, kldunload,
 *   fork, exit.
 */

/*
 * Action type - does event require a response?
 */
typedef enum {
	OES_ACTION_AUTH		= 0,	/* Requires response */
	OES_ACTION_NOTIFY	= 1,	/* Informational only */
} oes_action_t;

/*
 * AUTH response values
 */
typedef enum {
	OES_AUTH_ALLOW	= 0,
	OES_AUTH_DENY	= 1,
} oes_auth_result_t;

/* Fixed-width timestamp for the userspace wire ABI. */
typedef struct {
	int64_t		tv_sec;
	int64_t		tv_nsec;
} oes_timespec_t;

/* Thread information for the thread that triggered the event. */
typedef struct {
	uint64_t	et_id;		/* FreeBSD thread ID; 0 if unavailable */
	uint32_t	et_flags;	/* OES_THREAD_META_* */
	uint32_t	et_reserved;	/* Must be zero */
	char		et_name[MAXCOMLEN + 1]; /* Thread name, if assigned */
} oes_thread_t;

#define OES_THREAD_META_PRESENT	0x00000001

/*
 * Client operating modes
 */
#define OES_MODE_NOTIFY		0x0000	/* Notify-only, never blocks kernel */
#define OES_MODE_AUTH		0x0001	/* Can respond to AUTH events */
#define OES_MODE_PASSIVE	0x0002	/* Receive AUTH as NOTIFY (no block) */

/*
 * Process token - unique process identity
 *
 * Contains pid plus generation counter to detect pid reuse.
 * Used with OES_IOC_MUTE_PROCESS to identify processes.
 */
typedef struct {
	uint64_t	ept_id;		/* Process ID (pid) */
	uint64_t	ept_genid;	/* Generation (detects pid reuse) */
} oes_proc_token_t;

/*
 * File token - unique file identity
 *
 * Contains inode plus device identity.  Inspect ef_generation separately
 * when a filesystem supplies it.
 */
typedef struct {
	uint64_t	eft_id;		/* Inode number */
	uint64_t	eft_dev;	/* Device ID */
} oes_file_token_t;

/*
 * Process information
 *
 * Analogous to Apple's es_process_t. Contains snapshot of process
 * state at time of event.
 *
 * Path fields (ep_path, ep_cwd, ep_jailname) are stored in the
 * message's trailing string table as NUL-terminated strings.
 * Use oes_msg_string(msg, offset) to access them.
 * An offset of 0 means the string is empty.
 * ep_path is cached during exec and inherited across fork and credential
 * changes, avoiding path resolution from inside MAC hooks.  Processes that
 * predate OES activation may report it unavailable until their next exec.
 * Check ep_meta_flags before treating an empty offset as authoritative.
 */
typedef struct {
	oes_proc_token_t ep_token;	/* Token for muting/identity */
	uint64_t	ep_exec_id;	/* Execution ID: same on fork, new on exec */
	pid_t		ep_pid;		/* Process ID */
	pid_t		ep_ppid;	/* Parent PID */
	char		ep_pcomm[MAXCOMLEN + 1]; /* Parent command name */
	pid_t		ep_pgid;	/* Process group ID */
	pid_t		ep_sid;		/* Session ID */
	pid_t		ep_original_ppid; /* FreeBSD real parent PID (p_oppid) */
	pid_t		ep_reaper_pid;	/* FreeBSD process reaper PID */
	uid_t		ep_uid;		/* Effective UID */
	uid_t		ep_ruid;	/* Real UID */
	uid_t		ep_suid;	/* Saved UID */
	gid_t		ep_gid;		/* Effective GID */
	gid_t		ep_rgid;	/* Real GID */
	gid_t		ep_sgid;	/* Saved GID */
	int		ep_jid;		/* Jail ID (0 if not jailed) */
	uint32_t	ep_flags;	/* EP_FLAG_* below */
	uint32_t	ep_state;	/* OES_PROC_STATE_* */
	uint32_t	ep_num_threads;	/* Number of threads in process */
	int32_t		ep_nice;	/* Scheduling nice value */
	uint32_t	ep_osrel;	/* Binary OS release value */
	uint32_t	ep_fibnum;	/* Routing table/FIB number */
	uint32_t	ep_cred_flags;	/* OES_CRED_FLAG_* */

	/* ABI/Binary type - detect Linux vs FreeBSD binaries */
	uint8_t		ep_abi;		/* EP_ABI_FREEBSD, EP_ABI_LINUX, etc. */
	uint8_t		ep_pad[3];

	/* Timing */
	int64_t		ep_start_sec;	/* Process start time (seconds) */
	int64_t		ep_start_usec;	/* Process start time (microseconds) */

	/* Credential groups (effective GID is element zero on FreeBSD). */
	uint16_t	ep_ngroups;	/* Total credential groups (may exceed 16) */
	gid_t		ep_groups[16];	/* First 16 credential groups */

	/* Audit info */
	uid_t		ep_auid;	/* Audit user ID */
	uint32_t	ep_asid;	/* Audit session ID */
	uint32_t	ep_audit_mask_success;
	uint32_t	ep_audit_mask_failure;
	uint32_t	ep_audit_term_port;
	uint32_t	ep_audit_term_type;
	uint32_t	ep_audit_term_addr[4];
	uint64_t	ep_audit_flags;

	/* Names (small, always populated - kept inline) */
	char		ep_comm[MAXCOMLEN + 1];	/* Command name */
	char		ep_tty[32];	/* Controlling TTY name */
	char		ep_login[MAXLOGNAME];	/* Login name */
	char		ep_loginclass[MAXLOGNAME]; /* Login class */

	/* Paths (variable-length, in string table) */
	uint32_t	ep_path_off;	/* Executable path (string table offset) */
	uint32_t	ep_cwd_off;	/* Current working directory */
	uint32_t	ep_jailname_off; /* Jail name if jailed */
	uint32_t	ep_pad2;	/* Alignment */
	uint32_t	ep_meta_flags;	/* OES_PROC_META_* */
	uint32_t	ep_reserved;	/* Must be zero */
} oes_process_t;

/* Process flags */
#define EP_FLAG_SETUID		0x0001	/* Running setuid */
#define EP_FLAG_SETGID		0x0002	/* Running setgid */
#define EP_FLAG_JAILED		0x0004	/* In a jail */
#define EP_FLAG_CAPMODE		0x0008	/* In capability mode */
#define EP_FLAG_LINUX		0x0200	/* Linux binary (via Linuxulator) */
#define EP_FLAG_TRACED		0x0010	/* Being ptraced */
#define EP_FLAG_SYSTEM		0x0020	/* System process */
#define EP_FLAG_WEXIT		0x0040	/* Process is exiting */
#define EP_FLAG_EXEC		0x0080	/* Process did exec */
#define EP_FLAG_CONTROLT	0x0100	/* Has controlling terminal */
#define EP_FLAG_OES_CLIENT	0x0400	/* Owns an active OES client */

#define OES_PROC_STATE_NEW	1
#define OES_PROC_STATE_NORMAL	2
#define OES_PROC_STATE_ZOMBIE	3

#define OES_CRED_FLAG_CAPMODE	0x00000001

/* ABI types for ep_abi (matches SV_ABI_* from sys/sysent.h) */
#define EP_ABI_FREEBSD		9	/* Native FreeBSD binary */
#define EP_ABI_LINUX		3	/* Linux binary (Linuxulator) */
#define EP_ABI_UNDEF		255	/* Unknown/undefined */

/*
 * File information
 *
 * Path is stored in the message's trailing string table.  Attribute and path
 * availability are reported independently in ef_meta_flags.
 * Use oes_msg_string(msg, ef_path_off) to access it.
 */
typedef struct {
	oes_file_token_t ef_token;	/* Token for fd retrieval */
	uint64_t	ef_ino;		/* Inode number */
	uint64_t	ef_dev;		/* Device ID */
	uint64_t	ef_size;	/* File size in bytes */
	uint64_t	ef_blocks;	/* Blocks allocated */
	uint64_t	ef_allocated_bytes; /* Exact allocated byte count */
	uint64_t	ef_block_size;	/* Preferred I/O block size */
	uint64_t	ef_generation;	/* Filesystem generation number */
	uint64_t	ef_rdev;	/* Device ID for special files */
	uint64_t	ef_filerev;	/* Filesystem modification revision */
	mode_t		ef_mode;	/* File mode */
	uid_t		ef_uid;		/* Owner UID */
	gid_t		ef_gid;		/* Owner GID */
	uint32_t	ef_flags;	/* File flags (chflags) */
	uint32_t	ef_nlink;	/* Link count */
	uint8_t		ef_type;	/* File type: EF_TYPE_* below */
	uint8_t		ef_pad[3];

	/* Timestamps (seconds since epoch) */
	int64_t		ef_atime;	/* Access time */
	int64_t		ef_mtime;	/* Modification time */
	int64_t		ef_ctime;	/* Change time */
	int64_t		ef_birthtime;	/* Creation time */
	int64_t		ef_atime_nsec;	/* Access timestamp nanoseconds */
	int64_t		ef_mtime_nsec;	/* Modification timestamp nanoseconds */
	int64_t		ef_ctime_nsec;	/* Change timestamp nanoseconds */
	int64_t		ef_birthtime_nsec; /* Creation timestamp nanoseconds */

	/* Filesystem info */
	char		ef_fstype[16];	/* Filesystem type (ufs, zfs, etc.) */
	uint32_t	ef_path_off;	/* Path (string table offset, 0 = empty) */
	uint32_t	ef_meta_flags;	/* OES_FILE_META_* */
	uint32_t	ef_vaflags;	/* Snapshot of va_vaflags */
	uint32_t	ef_reserved;	/* Must be zero */
} oes_file_t;

/* File types */
#define EF_TYPE_UNKNOWN		0
#define EF_TYPE_REG		1	/* Regular file */
#define EF_TYPE_DIR		2	/* Directory */
#define EF_TYPE_LNK		3	/* Symbolic link */
#define EF_TYPE_CHR		4	/* Character device */
#define EF_TYPE_BLK		5	/* Block device */
#define EF_TYPE_FIFO		6	/* Named pipe */
#define EF_TYPE_SOCK		7	/* Socket */

/*
 * Event-specific data structures
 */

/*
 * Maximum exec argument data in string table.
 * Argv and envp are stored as NUL-separated strings.
 */
#define OES_EXEC_ARGS_MAX	4096

/* OES_EVENT_*_EXEC */
typedef struct {
	oes_process_t	target;		/* Process with new executable path */
	oes_file_t	executable;	/* Executable being run */
	uint32_t	argc;		/* Argument count */
	uint32_t	envc;		/* Environment count */
	uint32_t	argv_off;	/* NUL-separated argv (string table offset) */
	uint32_t	argv_len;	/* Length of argv data in string table */
	uint32_t	envp_off;	/* NUL-separated envp (string table offset) */
	uint32_t	envp_len;	/* Length of envp data in string table */
	uint32_t	flags;		/* EE_FLAG_* */
	uint32_t	reserved;
} oes_event_exec_t;

/* Exec event flags */
#define EE_FLAG_ARGV_TRUNCATED	0x0001	/* argv was truncated */
#define EE_FLAG_ENVP_TRUNCATED	0x0002	/* envp was truncated */

/* OES_EVENT_*_OPEN */
typedef struct {
	oes_file_t	file;		/* File being opened */
	int		flags;		/* Open flags (O_RDONLY, etc.) */
	mode_t		mode;		/* Reserved (creation mode unavailable from MAC hook) */
	uint32_t	access;		/* OES_ACCESS_* requested by the kernel */
} oes_event_open_t;

/* Unambiguous access bits used by OPEN flags responses. */
#define OES_ACCESS_READ		0x00000001
#define OES_ACCESS_WRITE	0x00000002
#define OES_ACCESS_EXEC		0x00000004

/* OES_EVENT_*_ACCESS */
typedef struct {
	oes_file_t	file;		/* File being checked */
	int		accmode;	/* VREAD/VWRITE/VEXEC */
} oes_event_access_t;

/* OES_EVENT_*_READ / OES_EVENT_*_WRITE */
typedef struct {
	oes_file_t	file;		/* File being read/written */
} oes_event_rw_t;

/* Generic file event */
typedef struct {
	oes_file_t	file;		/* File */
} oes_event_file_t;

/* OES_EVENT_*_READDIR */
typedef struct {
	oes_file_t	dir;		/* Directory being read */
} oes_event_readdir_t;

/* OES_EVENT_*_LOOKUP */
typedef struct {
	oes_file_t	dir;		/* Directory being searched */
	uint32_t	name_off;	/* Lookup name (string table offset) */
} oes_event_lookup_t;

/* OES_EVENT_*_CREATE */
typedef struct {
	oes_file_t	dir;		/* Parent directory */
	oes_file_t	file;		/* New file/dir being created */
	mode_t		mode;		/* Creation mode */
} oes_event_create_t;

/* OES_EVENT_*_UNLINK */
typedef struct {
	oes_file_t	dir;		/* Parent directory */
	oes_file_t	file;		/* File being removed */
} oes_event_unlink_t;

/* OES_EVENT_*_RENAME */
typedef struct {
	oes_file_t	src_dir;	/* Source directory */
	oes_file_t	src_file;	/* Source file */
	oes_file_t	dst_dir;	/* Destination directory */
	uint32_t	dst_name_off;	/* New name (string table offset) */
} oes_event_rename_t;

/* OES_EVENT_*_LINK */
typedef struct {
	oes_file_t	target;		/* Target of the new link */
	oes_file_t	dir;		/* Directory containing link */
	uint32_t	name_off;	/* Link name (string table offset) */
} oes_event_link_t;

/* OES_EVENT_NOTIFY_FORK */
typedef struct {
	oes_process_t	child;		/* Newly created child */
} oes_event_fork_t;

/* OES_EVENT_NOTIFY_EXIT */
typedef struct {
	int		status;		/* Exit status (wait-style) */
} oes_event_exit_t;

/* OES_EVENT_*_MOUNT */
typedef struct {
	oes_file_t	mountpoint;	/* Mount point */
	char		fstype[16];	/* Filesystem type */
	uint32_t	source_off;	/* Source device/path (string table offset) */
	uint32_t	pad;
	uint64_t	flags;		/* Mount flags */
} oes_event_mount_t;

/* OES_EVENT_*_KLDLOAD */
typedef struct {
	oes_file_t	file;		/* Module file */
	char		name[64];	/* Module name */
} oes_event_kldload_t;

/* OES_EVENT_*_MMAP */
typedef struct {
	oes_file_t	file;		/* File being mapped (if any) */
	uint64_t	addr;		/* Reserved (addr unavailable from MAC hook) */
	uint64_t	len;		/* Reserved (len unavailable from MAC hook) */
	int		prot;		/* Protection flags */
	int		flags;		/* Mmap flags */
} oes_event_mmap_t;

/* OES_EVENT_*_SETMODE */
typedef struct {
	oes_file_t	file;		/* File being changed */
	mode_t		mode;		/* New mode */
} oes_event_setmode_t;

/* OES_EVENT_*_SETOWNER */
typedef struct {
	oes_file_t	file;		/* File being changed */
	uid_t		uid;		/* New owner uid */
	gid_t		gid;		/* New owner gid */
} oes_event_setowner_t;

/* OES_EVENT_*_SETFLAGS */
typedef struct {
	oes_file_t	file;		/* File being changed */
	uint64_t	flags;		/* New file flags */
} oes_event_setflags_t;

/* OES_EVENT_*_SETUTIMES */
typedef struct {
	oes_file_t	file;		/* File being changed */
	oes_timespec_t	atime;		/* New access time */
	oes_timespec_t	mtime;		/* New modification time */
} oes_event_setutimes_t;

/* OES_EVENT_*_MPROTECT */
typedef struct {
	oes_file_t	file;		/* File backing mapping (if any) */
	int		prot;		/* Protection flags */
} oes_event_mprotect_t;

/* OES_EVENT_*_CHDIR */
typedef struct {
	oes_file_t	dir;		/* New working directory */
} oes_event_chdir_t;

/* OES_EVENT_*_CHROOT */
typedef struct {
	oes_file_t	dir;		/* New root directory */
} oes_event_chroot_t;

/* OES_EVENT_*_SETEXTATTR */
typedef struct {
	oes_file_t	file;		/* Target file */
	int		attrnamespace;	/* EXTATTR_NAMESPACE_* */
	uint32_t	name_off;	/* Attr name (string table offset) */
} oes_event_setextattr_t;

/* OES_EVENT_*_{GET,DELETE,LIST}EXTATTR */
typedef struct {
	oes_file_t	file;		/* Target file */
	int		attrnamespace;	/* EXTATTR_NAMESPACE_* */
	uint32_t	name_off;	/* Attr name (string table offset, 0 for list) */
} oes_event_extattr_t;

/* OES_EVENT_*_{GET,SET,DELETE}ACL */
typedef struct {
	oes_file_t	file;		/* Target file */
	int		type;		/* ACL_TYPE_* */
} oes_event_acl_t;

/* OES_EVENT_NOTIFY_SIGNAL */
typedef struct {
	oes_process_t	target;		/* Target process */
	int		signum;		/* Signal number */
} oes_event_signal_t;

/* OES_EVENT_*_PTRACE */
typedef struct {
	oes_process_t	target;		/* Target process */
	int		request;	/* Reserved (request type unavailable from MAC hook) */
} oes_event_ptrace_t;

/* OES_EVENT_NOTIFY_SETUID */
typedef struct {
	uid_t		uid;		/* New UID */
} oes_event_setuid_t;

/* OES_EVENT_NOTIFY_SETGID */
typedef struct {
	gid_t		gid;		/* New GID */
} oes_event_setgid_t;

/* Socket address (for socket events) */
typedef struct {
	uint8_t		esa_family;	/* AF_INET, AF_INET6, AF_UNIX, etc. */
	uint8_t		esa_pad[3];
	uint16_t	esa_port;	/* Port (network byte order, AF_INET/6) */
	uint16_t	esa_pad2;
	union {
		uint32_t	v4;		/* IPv4 address */
		uint8_t		v6[16];		/* IPv6 address */
		char		path[104];	/* Unix socket path */
	} esa_addr;
} oes_sockaddr_t;

/* Socket information */
typedef struct {
	int		es_domain;	/* AF_INET, AF_INET6, AF_UNIX */
	int		es_type;	/* SOCK_STREAM, SOCK_DGRAM, etc. */
	int		es_protocol;	/* Protocol number */
	int		es_pad;
} oes_socket_t;

/* OES_EVENT_*_SOCKET_CONNECT / OES_EVENT_*_SOCKET_BIND */
typedef struct {
	oes_socket_t	socket;		/* Socket info */
	oes_sockaddr_t	address;	/* Remote/local address */
} oes_event_socket_addr_t;

/* OES_EVENT_*_SOCKET_LISTEN */
typedef struct {
	oes_socket_t	socket;		/* Socket info */
} oes_event_socket_t;

/* OES_EVENT_*_REBOOT */
typedef struct {
	int		howto;		/* Reboot flags (RB_HALT, etc.) */
} oes_event_reboot_t;

/* OES_EVENT_*_SYSCTL */
typedef struct {
	uint32_t	name_off;	/* Sysctl name (string table offset) */
	int		op;		/* Operation: 0=read, 1=write */
} oes_event_sysctl_t;

/*
 * Kenv (kernel environment) event
 */
typedef struct {
	uint32_t	name_off;	/* Environment variable name (string table offset) */
	int		op;		/* Operation: 0=get, 1=set, 2=unset */
} oes_event_kenv_t;

/*
 * Swapon event
 */
typedef struct {
	oes_file_t	file;		/* Swap device/file */
} oes_event_swapon_t;

/*
 * Swapoff event
 */
typedef struct {
	oes_file_t	file;		/* Swap device/file */
} oes_event_swapoff_t;

/*
 * Socket create event
 */
typedef struct {
	int		domain;		/* AF_INET, AF_INET6, AF_UNIX, etc. */
	int		type;		/* SOCK_STREAM, SOCK_DGRAM, etc. */
	int		protocol;	/* Protocol number */
	int		pad;
} oes_event_socket_create_t;

/*
 * Pipe event (read/write/stat/poll/ioctl)
 */
typedef struct {
	uint64_t	pipe_id;	/* Opaque pipe identifier; 0 if unavailable */
	uint64_t	ioctl_cmd;	/* For ioctl events */
} oes_event_pipe_t;

/*
 * Mount stat event
 */
typedef struct {
	char		fstype[16];	/* Filesystem type */
	uint32_t	fspath_off;	/* Mount point (string table offset) */
} oes_event_mount_stat_t;

/*
 * Privilege check event
 */
typedef struct {
	int		priv;		/* Privilege number (PRIV_*) */
} oes_event_priv_t;

/*
 * Process scheduling event
 */
typedef struct {
	oes_process_t	target;		/* Target process */
} oes_event_proc_sched_t;

/*
 * Main message structure
 *
 * Clients read these from the oes fd. Messages are variable-length:
 * a fixed header (sizeof(oes_message_t)) followed by a string table
 * containing NUL-terminated path/name strings referenced by _off fields.
 * em_size gives the total size including the string table.
 * Existing field offsets must remain stable in later ABI versions.  Additive
 * versions may consume em_event_data._reserved or append fixed data before the
 * string table, update em_struct_size, and leave older fields untouched.
 *
 * Use oes_msg_string(msg, offset) to access strings by offset.
 * Allocate OES_MSG_MAX_SIZE for read buffers.
 */
typedef struct {
	uint32_t	em_version;	/* OES_MESSAGE_VERSION */
	uint32_t	em_size;	/* Total message size (header + strings) */
	uint32_t	em_struct_size;	/* Fixed structure size for this version */
	uint32_t	em_flags;	/* OES_MSG_FLAG_* */
	uint64_t	em_id;		/* Unique message ID (for response) */
	uint64_t	em_seq_num;	/* Per-client, per-event sequence number */
	uint64_t	em_global_seq_num; /* Per-client sequence across all events */
	uint32_t	em_event;	/* oes_event_type_t */
	uint32_t	em_action;	/* oes_action_t: AUTH or NOTIFY */
	uint32_t	em_result;	/* Applied oes_auth_result_t when flag is set */
	uint32_t	em_reserved;	/* Reserved, must be 0 */
	oes_timespec_t	em_time;	/* Event timestamp (CLOCK_MONOTONIC) */
	oes_timespec_t	em_deadline;	/* AUTH deadline (CLOCK_MONOTONIC) */
	oes_timespec_t	em_wall_time;	/* Event timestamp (CLOCK_REALTIME) */
	oes_thread_t	em_thread;	/* Triggering thread */
	oes_process_t	em_process;	/* Process that triggered event */

	union {
		oes_event_exec_t	exec;
		oes_event_open_t	open;
		oes_event_access_t	access;
		oes_event_rw_t		rw;
		oes_event_file_t	stat;
		oes_event_file_t	poll;
		oes_event_file_t	revoke;
		oes_event_readdir_t	readdir;
		oes_event_file_t	readlink;
		oes_event_extattr_t	getextattr;
		oes_event_extattr_t	deleteextattr;
		oes_event_extattr_t	listextattr;
		oes_event_acl_t	getacl;
		oes_event_acl_t	setacl;
		oes_event_acl_t	deleteacl;
		oes_event_file_t	relabel;
		oes_event_lookup_t	lookup;
		oes_event_create_t	create;
		oes_event_unlink_t	unlink;
		oes_event_rename_t	rename;
		oes_event_link_t	link;
		oes_event_fork_t	fork;
		oes_event_exit_t	exit;
		oes_event_mount_t	mount;
		oes_event_kldload_t	kldload;
		oes_event_mmap_t	mmap;
		oes_event_setmode_t	setmode;
		oes_event_setowner_t	setowner;
		oes_event_setflags_t	setflags;
		oes_event_setutimes_t	setutimes;
		oes_event_mprotect_t	mprotect;
		oes_event_chdir_t	chdir;
		oes_event_chroot_t	chroot;
		oes_event_setextattr_t	setextattr;
		oes_event_signal_t	signal;
		oes_event_ptrace_t	ptrace;
		oes_event_setuid_t	setuid;
		oes_event_setgid_t	setgid;
		oes_event_socket_addr_t	socket_connect;
		oes_event_socket_addr_t	socket_bind;
		oes_event_socket_t	socket_listen;
		oes_event_reboot_t	reboot;
		oes_event_sysctl_t	sysctl;
		oes_event_kenv_t	kenv;
		oes_event_swapon_t	swapon;
		oes_event_swapoff_t	swapoff;
		oes_event_mount_t	unmount;
		oes_event_kldload_t	kldunload;
		oes_event_socket_create_t socket_create;
		oes_event_socket_t	socket_accept;
		oes_event_socket_t	socket_send;
		oes_event_socket_t	socket_receive;
		oes_event_socket_t	socket_stat;
		oes_event_socket_t	socket_poll;
		oes_event_pipe_t	pipe;
		oes_event_mount_stat_t	mount_stat;
		oes_event_priv_t	priv;
		oes_event_proc_sched_t	proc_sched;
		uint8_t			_reserved[128]; /* Future expansion */
	} em_event_data;
} oes_message_t;

#define OES_MESSAGE_VERSION	1

/* Message flags */
#define OES_MSG_FLAG_STRINGS_TRUNCATED	0x00000001
#define OES_MSG_FLAG_PATH_UNAVAILABLE	0x00000002
#define OES_MSG_FLAG_AUTH_RESULT		0x00000004

/* Object metadata flags */
#define OES_PROC_META_PATH_UNAVAILABLE	0x00000001
#define OES_PROC_META_PATH_TRUNCATED	0x00000002
#define OES_PROC_META_CWD_UNAVAILABLE	0x00000004
#define OES_PROC_META_PARENT_UNAVAILABLE 0x00000008
#define OES_PROC_META_SESSION_UNAVAILABLE 0x00000010
#define OES_PROC_META_GROUPS_TRUNCATED	0x00000020
#define OES_PROC_META_CREDENTIALS_UNAVAILABLE 0x00000040
#define OES_FILE_META_PATH_UNAVAILABLE	0x00000001
#define OES_FILE_META_PATH_REQUESTED	0x00000002
#define OES_FILE_META_PATH_TRUNCATED	0x00000004
#define OES_FILE_META_ATTR_UNAVAILABLE	0x00000008
#define OES_FILE_META_FSTYPE_UNAVAILABLE 0x00000010
#define OES_FILE_META_PROPOSED_ATTRS	0x00000020

static inline void
oes_message_mark_path_unavailable(oes_message_t *msg)
{

	if (msg != NULL)
		msg->em_flags |= OES_MSG_FLAG_PATH_UNAVAILABLE;
}

static inline void
oes_process_mark_path_unavailable(oes_message_t *msg, oes_process_t *proc)
{

	oes_message_mark_path_unavailable(msg);
	if (proc != NULL)
		proc->ep_meta_flags |= OES_PROC_META_PATH_UNAVAILABLE;
}

static inline void
oes_file_mark_path_unavailable(oes_message_t *msg, oes_file_t *file)
{

	oes_message_mark_path_unavailable(msg);
	if (file != NULL)
		file->ef_meta_flags |= OES_FILE_META_PATH_UNAVAILABLE;
}

static inline void
oes_file_mark_path_requested(oes_file_t *file)
{

	if (file != NULL)
		file->ef_meta_flags |= OES_FILE_META_PATH_REQUESTED;
}

/*
 * Maximum message size including string table.  Use this to size read
 * buffers.  Batched messages are laid out back-to-back in raw byte buffers,
 * so OES_MSG_ALIGN must satisfy the natural alignment of oes_message_t.
 */
#define OES_MSG_MAX_SIZE	8192
#define OES_MSG_ALIGN		8	/* Message size alignment for batching */
#define OES_MSG_ALIGNED(sz)	(((sz) + OES_MSG_ALIGN - 1) & ~(OES_MSG_ALIGN - 1))

static inline int
oes_message_is_compatible(const oes_message_t *msg)
{

	return (msg != NULL &&
	    msg->em_version >= OES_MESSAGE_VERSION &&
	    msg->em_size <= OES_MSG_MAX_SIZE &&
	    (msg->em_size & (OES_MSG_ALIGN - 1)) == 0 &&
	    msg->em_struct_size >= sizeof(oes_message_t) &&
	    msg->em_struct_size <= msg->em_size &&
	    msg->em_reserved == 0 &&
	    (((msg->em_flags & OES_MSG_FLAG_AUTH_RESULT) == 0) ||
	    msg->em_result == OES_AUTH_ALLOW ||
	    msg->em_result == OES_AUTH_DENY));
}

static inline int
oes_message_has_auth_result(const oes_message_t *msg)
{

	return (oes_message_is_compatible(msg) &&
	    (msg->em_flags & OES_MSG_FLAG_AUTH_RESULT) != 0 &&
	    (msg->em_result == OES_AUTH_ALLOW ||
	    msg->em_result == OES_AUTH_DENY));
}

/*
 * Access a string from the message's string table by offset.
 * Returns "" for offset 0, out-of-bounds offsets, or strings that are not
 * NUL-terminated within the message.
 */
static inline const char *
oes_msg_string(const oes_message_t *msg, uint32_t off)
{
	const char *bytes;
	uint32_t i;

	if (!oes_message_is_compatible(msg) || off < msg->em_struct_size ||
	    off >= msg->em_size)
		return ("");
	bytes = (const char *)msg;
	for (i = off; i < msg->em_size; i++) {
		if (bytes[i] == '\0')
			return (bytes + off);
	}
	return ("");
}

/*
 * Response structure
 *
 * Clients write these to respond to AUTH events.
 */
typedef struct {
	uint64_t	er_id;		/* Message ID being responded to */
	uint32_t	er_result;	/* oes_auth_result_t: ALLOW or DENY */
	uint32_t	er_flags;	/* Reserved, must be 0 */
} oes_response_t;

/*
 * Flags-based response for partial authorization
 * (AUTH_OPEN, AUTH_MMAP, AUTH_MPROTECT).
 * AUTH_OPEN uses OES_ACCESS_* rather than O_* values because O_RDONLY is 0.
 * No downgrade: operations are fully allowed or fully denied.
 */
typedef struct {
	uint64_t	erf_id;		/* Message ID being responded to */
	uint32_t	erf_result;	/* oes_auth_result_t: ALLOW or DENY */
	uint32_t	erf_reserved;	/* Padding */
	uint32_t	erf_allowed_flags; /* Flags to allow (event-specific) */
	uint32_t	erf_denied_flags;  /* Flags explicitly denied */
} oes_response_flags_t;

/*
 * IOCTL definitions
 */

/* Subscribe to event types */
struct oes_subscribe_args {
	const oes_event_type_t *esa_events; /* Array of event types */
	size_t		esa_count;	/* Number of events */
	uint32_t	esa_flags;	/* OES_SUB_* flags */
	uint32_t	esa_reserved;	/* Must be zero */
};
#define OES_SUB_ADD		0x0000	/* Add to existing subscriptions */
#define OES_SUB_REPLACE		0x0001	/* Replace all subscriptions */
#define OES_SUB_REMOVE		0x0002	/* Remove listed subscriptions */

#define OES_IOC_SUBSCRIBE	_IOW('E', 1, struct oes_subscribe_args)

/* Subscribe using 128-bit bitmaps (no event count limit). */
struct oes_subscribe_bitmap_args {
	uint64_t	esba_auth[2];	/* AUTH event bitmap (128 bits) */
	uint64_t	esba_notify[2];	/* NOTIFY event bitmap (128 bits) */
	uint32_t	esba_flags;	/* OES_SUB_* flags */
	uint32_t	esba_reserved;
};

#define OES_IOC_SUBSCRIBE_BITMAP	_IOW('E', 34, struct oes_subscribe_bitmap_args)
#define OES_IOC_GET_SUBSCRIPTIONS \
	_IOR('E', 35, struct oes_subscribe_bitmap_args)

/*
 * Client visibility scope.
 *
 * A descendants-scoped client receives NOTIFY events for its opener and
 * AUTH+NOTIFY events for processes in the opener's descendant subtree.  It
 * cannot observe processes outside that subtree.  The scope must be selected
 * before setting the mode or adding subscriptions and cannot later be
 * widened.  This mirrors Apple's es_new_descendants_client() visibility
 * contract while retaining the OES fd-based API.
 */
#define OES_SCOPE_GLOBAL		0
#define OES_SCOPE_DESCENDANTS	1

struct oes_scope_args {
	uint32_t	esa_scope;	/* OES_SCOPE_* */
	uint32_t	esa_reserved;	/* Must be zero */
};

#define OES_IOC_SET_SCOPE	_IOW('E', 37, struct oes_scope_args)
#define OES_IOC_GET_SCOPE	_IOR('E', 38, struct oes_scope_args)

/* Set client mode and parameters */
struct oes_mode_args {
	uint32_t	ema_mode;	/* OES_MODE_* */
	uint32_t	ema_default_deadline_ms; /* AUTH deadline (0 = default) */
	uint32_t	ema_queue_size;	/* Max queued events (0 = default) */
	uint32_t	ema_flags;	/* Reserved */
};

#define OES_IOC_SET_MODE	_IOW('E', 2, struct oes_mode_args)
#define OES_IOC_GET_MODE	_IOR('E', 31, struct oes_mode_args)

/*
 * Set/get deadline bounds for one AUTH event type.  A zero value passed to a
 * SET operation removes that event's override.  Maximums are available to
 * every client.  Minimums are restricted to descendants-scoped clients,
 * matching the safety boundary of Apple's corresponding API.
 */
struct oes_event_deadline_args {
	uint32_t	oeda_event;		/* oes_event_type_t (AUTH only) */
	uint32_t	oeda_milliseconds;	/* Bound, or zero to reset on SET */
	uint32_t	oeda_reserved[2];	/* Must be zero */
};

#define OES_IOC_SET_DEADLINE_MAX \
	_IOW('E', 39, struct oes_event_deadline_args)
#define OES_IOC_GET_DEADLINE_MAX \
	_IOWR('E', 40, struct oes_event_deadline_args)
#define OES_IOC_SET_DEADLINE_MIN \
	_IOW('E', 41, struct oes_event_deadline_args)
#define OES_IOC_GET_DEADLINE_MIN \
	_IOWR('E', 42, struct oes_event_deadline_args)

/* Mute events from a process */
struct oes_mute_args {
	oes_proc_token_t emu_token;	/* Process to mute (ignored if SELF) */
	uint32_t	emu_flags;	/* OES_MUTE_* flags */
};
#define OES_MUTE_SELF		0x0001	/* Mute calling process */

#define OES_IOC_MUTE_PROCESS	_IOW('E', 3, struct oes_mute_args)
#define OES_IOC_UNMUTE_PROCESS	_IOW('E', 4, struct oes_mute_args)

/*
 * Mute events by path
 */
struct oes_mute_path_args {
	char		emp_path[MAXPATHLEN]; /* Path to mute */
	uint32_t	emp_type;	/* OES_MUTE_PATH_* */
	uint32_t	emp_flags;	/* OES_MUTE_PATH_FLAG_* */
};

#define OES_MUTE_PATH_LITERAL	0x0001	/* Exact match */
#define OES_MUTE_PATH_PREFIX	0x0002	/* Prefix match */

#define OES_MUTE_PATH_FLAG_TARGET	0x0001	/* Target path list */

#define OES_IOC_MUTE_PATH	_IOW('E', 9, struct oes_mute_path_args)
#define OES_IOC_UNMUTE_PATH	_IOW('E', 10, struct oes_mute_path_args)

/*
 * Mute inversion
 */
typedef enum {
	OES_MUTE_INVERT_PROCESS		= 1,
	OES_MUTE_INVERT_PATH		= 2,
	OES_MUTE_INVERT_TARGET_PATH	= 3,
} oes_mute_invert_type_t;

struct oes_mute_invert_args {
	uint32_t	emi_type;	/* OES_MUTE_INVERT_* */
	uint32_t	emi_invert;	/* 0 = normal, 1 = inverted */
};

#define OES_IOC_SET_MUTE_INVERT	_IOW('E', 7, struct oes_mute_invert_args)
#define OES_IOC_GET_MUTE_INVERT	_IOWR('E', 8, struct oes_mute_invert_args)

/*
 * Per-event-type muting
 *
 * Mute specific event types for a process or path, rather than all events.
 * Similar to Apple ES es_mute_process_events() and es_mute_path_events().
 */
#define OES_MAX_MUTE_EVENTS	64	/* Max events per mute call */

struct oes_mute_process_events_args {
	oes_proc_token_t empe_token;		/* Process to mute */
	uint32_t	empe_flags;		/* OES_MUTE_SELF, etc. */
	uint32_t	empe_count;		/* Number of events */
	oes_event_type_t empe_events[OES_MAX_MUTE_EVENTS]; /* Events to mute */
};

struct oes_mute_path_events_args {
	char		empae_path[MAXPATHLEN];	/* Path to mute */
	uint32_t	empae_type;		/* OES_MUTE_PATH_* */
	uint32_t	empae_flags;		/* OES_MUTE_PATH_FLAG_* */
	uint32_t	empae_count;		/* Number of events */
	oes_event_type_t empae_events[OES_MAX_MUTE_EVENTS]; /* Events to mute */
};

#define OES_IOC_MUTE_PROCESS_EVENTS	_IOW('E', 16, struct oes_mute_process_events_args)
#define OES_IOC_UNMUTE_PROCESS_EVENTS	_IOW('E', 17, struct oes_mute_process_events_args)
#define OES_IOC_MUTE_PATH_EVENTS	_IOW('E', 18, struct oes_mute_path_events_args)
#define OES_IOC_UNMUTE_PATH_EVENTS	_IOW('E', 19, struct oes_mute_path_events_args)

/*
 * Query muted processes/paths
 *
 * Retrieve list of currently muted processes or paths.
 * Similar to Apple ES es_muted_processes_events() and es_muted_paths_events().
 */
#define OES_MAX_MUTED_ENTRIES	256	/* Max entries returned per call */

struct oes_muted_process_entry {
	oes_proc_token_t emp_token;		/* Muted process */
	uint32_t	emp_event_count;	/* 0 = all events muted */
	oes_event_type_t emp_events[OES_MAX_MUTE_EVENTS]; /* Specific events */
};

struct oes_muted_path_entry {
	char		emp_path[MAXPATHLEN];	/* Muted path */
	uint32_t	emp_type;		/* OES_MUTE_PATH_* */
	uint32_t	emp_flags;		/* OES_MUTE_PATH_FLAG_* */
	uint32_t	emp_event_count;	/* 0 = all events muted */
	oes_event_type_t emp_events[OES_MAX_MUTE_EVENTS]; /* Specific events */
};

struct oes_get_muted_processes_args {
	struct oes_muted_process_entry *egmp_entries; /* OUT: array */
	size_t		egmp_count;		/* IN: array size */
	size_t		egmp_actual;		/* OUT: actual count */
};

struct oes_get_muted_paths_args {
	struct oes_muted_path_entry *egmpa_entries; /* OUT: array */
	size_t		egmpa_count;		/* IN: array size */
	size_t		egmpa_actual;		/* OUT: actual count */
	uint32_t	egmpa_flags;		/* OES_MUTE_PATH_FLAG_TARGET */
	uint32_t	egmpa_reserved;	/* Must be zero */
};

#define OES_IOC_GET_MUTED_PROCESSES	_IOWR('E', 20, struct oes_get_muted_processes_args)
#define OES_IOC_GET_MUTED_PATHS		_IOWR('E', 21, struct oes_get_muted_paths_args)

/*
 * Unmute all
 *
 * Clear all muted processes or paths in one operation.
 * Similar to Apple ES es_unmute_all_paths() (and added for processes).
 */
#define OES_IOC_UNMUTE_ALL_PROCESSES	_IO('E', 22)
#define OES_IOC_UNMUTE_ALL_PATHS	_IO('E', 23)
#define OES_IOC_UNMUTE_ALL_TARGET_PATHS	_IO('E', 24)

/*
 * UID/GID muting
 *
 * Mute events from processes running as specific UIDs or GIDs.
 * Uses effective UID/GID for matching.
 */
#define OES_MUTE_PROC_MAX	1024	/* Max muted processes per client */
#define OES_MUTE_PATH_MAX	256	/* Max muted paths per client */
#define OES_MUTE_UID_MAX	64	/* Max muted UIDs per client */
#define OES_MUTE_GID_MAX	64	/* Max muted GIDs per client */

struct oes_mute_uid_args {
	uid_t		emu_uid;	/* UID to mute */
};

struct oes_mute_gid_args {
	gid_t		emg_gid;	/* GID to mute */
};

#define OES_IOC_MUTE_UID	_IOW('E', 25, struct oes_mute_uid_args)
#define OES_IOC_UNMUTE_UID	_IOW('E', 26, struct oes_mute_uid_args)
#define OES_IOC_MUTE_GID	_IOW('E', 27, struct oes_mute_gid_args)
#define OES_IOC_UNMUTE_GID	_IOW('E', 28, struct oes_mute_gid_args)
#define OES_IOC_UNMUTE_ALL_UIDS	_IO('E', 29)
#define OES_IOC_UNMUTE_ALL_GIDS	_IO('E', 30)

/* Action applied when an AUTH deadline is missed or delivery is dropped. */
typedef enum {
	OES_DEADLINE_MISS_FAIL_OPEN = 0,
	OES_DEADLINE_MISS_FAIL_CLOSED = 1,
} oes_deadline_miss_mode_t;

struct oes_deadline_miss_mode_args {
	uint32_t	edma_mode;	/* oes_deadline_miss_mode_t */
	uint32_t	edma_reserved;	/* Must be zero */
};

#define OES_IOC_SET_DEADLINE_MISS_MODE \
	_IOW('E', 11, struct oes_deadline_miss_mode_args)
#define OES_IOC_GET_DEADLINE_MISS_MODE \
	_IOWR('E', 12, struct oes_deadline_miss_mode_args)

/*
 * Decision cache
 *
 * Cache AUTH decisions using the event, process token, execution identity,
 * operation parameters, and affected object tokens.
 */
#define OES_CACHE_KEY_PROCESS	0x0001
#define OES_CACHE_KEY_FILE	0x0002
#define OES_CACHE_KEY_TARGET	0x0004

#define OES_CACHE_EVENT_ANY	0	/* Wildcard for remove */

typedef struct {
	uint32_t	eck_event;	/* oes_event_type_t: AUTH event or ANY */
	uint32_t	eck_flags;	/* OES_CACHE_KEY_* */
	uint32_t	eck_op_flags;	/* Access/prot/namespace/type, by event */
	uint32_t	eck_op_flags2;	/* MMAP flags; zero for other events */
	oes_proc_token_t eck_process;
	uint64_t	eck_exec_id;	/* Process execution identity */
	oes_file_token_t eck_file;
	oes_file_token_t eck_target;
} oes_cache_key_t;

typedef struct {
	oes_cache_key_t	ece_key;	/* Cache key */
	uint32_t	ece_result;	/* oes_auth_result_t: ALLOW or DENY */
	uint32_t	ece_ttl_ms;	/* Time-to-live in ms */
} oes_cache_entry_t;

#define OES_IOC_CACHE_ADD	_IOW('E', 13, oes_cache_entry_t)
#define OES_IOC_CACHE_REMOVE	_IOW('E', 14, oes_cache_key_t)
#define OES_IOC_CACHE_CLEAR	_IO('E', 15)

/* Get client statistics and configuration */
struct oes_stats {
	/* Counters */
	uint64_t	es_events_received;	/* Total events received */
	uint64_t	es_events_dropped;	/* Events dropped (queue full) */
	uint64_t	es_auth_timeouts;	/* AUTH timeouts */
	uint64_t	es_auth_allowed;	/* AUTH events allowed */
	uint64_t	es_auth_denied;		/* AUTH events denied */
	uint64_t	es_cache_hits;		/* Cache hits */
	uint64_t	es_cache_misses;	/* Cache misses */
	uint64_t	es_cache_evictions;	/* Cache evictions */
	uint64_t	es_cache_expired;	/* Cache expired removals */

	/* Cache state */
	uint32_t	es_cache_entries;	/* Current cache entries */
	uint32_t	es_cache_max;		/* Max cache entries */

	/* Queue state */
	uint32_t	es_queue_current;	/* Current queue depth (events) */
	uint32_t	es_queue_max;		/* Max queue size (events) */
	uint32_t	es_queue_bytes;		/* Current queued bytes */
	uint32_t	es_queue_highwater;	/* Peak queue depth (events) */

	/* Global counters (from softc, shared across clients) */
	uint64_t	es_nosleep_drops;	/* NOSLEEP events dropped */
	uint64_t	es_alloc_failures;	/* Allocation failures */

	/* Current configuration */
	uint32_t	es_mode;		/* OES_MODE_* */
	uint32_t	es_default_deadline_ms; /* Default AUTH deadline in ms */
	uint32_t	es_deadline_miss_mode; /* oes_deadline_miss_mode_t */
	uint32_t	es_reserved;
};

#define OES_IOC_GET_STATS	_IOR('E', 6, struct oes_stats)

/* Capsicum ioctl permission sets for cap_ioctls_limit() */

/* Ioctl arrays for common permission sets */
#ifndef _KERNEL
#define OES_IOCTLS_THIRD_PARTY_INIT \
	{ OES_IOC_SUBSCRIBE, OES_IOC_SUBSCRIBE_BITMAP, \
	  OES_IOC_GET_SUBSCRIPTIONS, \
	  OES_IOC_GET_SCOPE, \
	  OES_IOC_GET_MODE, \
	  OES_IOC_SET_DEADLINE_MAX, OES_IOC_GET_DEADLINE_MAX, \
	  OES_IOC_SET_DEADLINE_MIN, OES_IOC_GET_DEADLINE_MIN, \
	  OES_IOC_MUTE_PROCESS, OES_IOC_UNMUTE_PROCESS, \
	  OES_IOC_MUTE_PATH, OES_IOC_UNMUTE_PATH, OES_IOC_SET_MUTE_INVERT, \
	  OES_IOC_GET_MUTE_INVERT, OES_IOC_SET_DEADLINE_MISS_MODE, \
	  OES_IOC_GET_DEADLINE_MISS_MODE, OES_IOC_GET_STATS, \
	  OES_IOC_MUTE_PROCESS_EVENTS, OES_IOC_UNMUTE_PROCESS_EVENTS, \
	  OES_IOC_MUTE_PATH_EVENTS, OES_IOC_UNMUTE_PATH_EVENTS, \
	  OES_IOC_GET_MUTED_PROCESSES, OES_IOC_GET_MUTED_PATHS, \
	  OES_IOC_UNMUTE_ALL_PROCESSES, OES_IOC_UNMUTE_ALL_PATHS, \
	  OES_IOC_UNMUTE_ALL_TARGET_PATHS, \
	  OES_IOC_MUTE_UID, OES_IOC_UNMUTE_UID, OES_IOC_MUTE_GID, \
	  OES_IOC_UNMUTE_GID, OES_IOC_UNMUTE_ALL_UIDS, OES_IOC_UNMUTE_ALL_GIDS }

#define OES_IOCTLS_ALL_INIT \
	{ OES_IOC_SUBSCRIBE, OES_IOC_SUBSCRIBE_BITMAP, \
	  OES_IOC_GET_SUBSCRIPTIONS, \
	  OES_IOC_SET_SCOPE, OES_IOC_GET_SCOPE, \
	  OES_IOC_SET_MODE, OES_IOC_GET_MODE, \
	  OES_IOC_SET_DEADLINE_MAX, OES_IOC_GET_DEADLINE_MAX, \
	  OES_IOC_SET_DEADLINE_MIN, OES_IOC_GET_DEADLINE_MIN, \
	  OES_IOC_MUTE_PROCESS, OES_IOC_UNMUTE_PROCESS, \
	  OES_IOC_MUTE_PATH, OES_IOC_UNMUTE_PATH, \
	  OES_IOC_SET_MUTE_INVERT, OES_IOC_GET_MUTE_INVERT, \
	  OES_IOC_SET_DEADLINE_MISS_MODE, OES_IOC_GET_DEADLINE_MISS_MODE, \
	  OES_IOC_CACHE_ADD, OES_IOC_CACHE_REMOVE, OES_IOC_CACHE_CLEAR, \
	  OES_IOC_GET_STATS, \
	  OES_IOC_MUTE_PROCESS_EVENTS, OES_IOC_UNMUTE_PROCESS_EVENTS, \
	  OES_IOC_MUTE_PATH_EVENTS, OES_IOC_UNMUTE_PATH_EVENTS, \
	  OES_IOC_GET_MUTED_PROCESSES, OES_IOC_GET_MUTED_PATHS, \
	  OES_IOC_UNMUTE_ALL_PROCESSES, OES_IOC_UNMUTE_ALL_PATHS, \
	  OES_IOC_UNMUTE_ALL_TARGET_PATHS, \
	  OES_IOC_MUTE_UID, OES_IOC_UNMUTE_UID, OES_IOC_MUTE_GID, \
	  OES_IOC_UNMUTE_GID, OES_IOC_UNMUTE_ALL_UIDS, OES_IOC_UNMUTE_ALL_GIDS }
#endif

/*
 * Default values
 */
#define OES_DEFAULT_DEADLINE_MS	30000	/* 30 seconds */
#define OES_DEFAULT_QUEUE_SIZE	1024	/* Events per client */
#define OES_MIN_DEADLINE_MS	1000	/* 1 second minimum */
#define OES_MAX_DEADLINE_MS	300000	/* 5 minutes maximum */
#define OES_MAX_CACHE_TTL_MS	3600000	/* 1 hour maximum */

/*
 * Device path
 */
#define OES_DEVICE_PATH		"/dev/oes"

#endif /* !_SYS_OES_H_ */
