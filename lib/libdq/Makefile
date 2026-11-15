#
# DescriptorQueue controller library (libdq).
#

.include <src.opts.mk>

PACKAGE=	dq
LIB=		dq
SHLIB_MAJOR=	1
SRCS=		libdq.c libdq_serve.c libdq_tree.c
LIBADD=		capability pthread

MAN=		libdq.3
MLINKS+=	libdq.3 dq_open.3 \
		libdq.3 dq_get_stats.3 \
		libdq.3 dq_set_queue_depth.3 \
		libdq.3 dq_policy_default.3 \
		libdq.3 dq_ident_from_stat.3 \
		libdq.3 dq_mint_file.3 \
		libdq.3 dq_mint_observer.3 \
		libdq.3 dq_revoke.3 \
		libdq.3 dq_set_ident.3 \
		libdq.3 dq_set_policy.3 \
		libdq.3 dq_read_events.3 \
		libdq.3 dq_event_first.3 \
		libdq.3 dq_event_next.3 \
		libdq.3 dq_event_body.3 \
		libdq.3 dq_reply.3 \
		libdq.3 dq_dispatch.3 \
		libdq.3 dq_observe_connect.3 \
		libdq.3 dq_observe_list_queues.3 \
		libdq.3 dq_observe_list_objects.3 \
		libdq.3 dq_observe_subscribe.3 \
		libdq.3 dq_get_stats2.3 \
		libdq.3 dq_mint_file_flags.3 \
		libdq.3 dq_push_vnode_note.3 \
		libdq.3 dq_push_invalidate.3 \
		libdq.3 dq_attach.3 \
		libdq.3 dq_attach_starts.3 \
		libdq.3 dq_attach_starts_flags.3 \
		libdq.3 dq_event_resolve_root.3 \
		libdq.3 dq_event_resolve.3 \
		libdq.3 dq_reply_resolve_pass.3 \
		libdq.3 dq_reply_resolve_errno.3 \
		libdq.3 dq_event_read.3 \
		libdq.3 dq_event_write.3 \
		libdq.3 dq_event_setattr.3 \
		libdq.3 dq_event_fsync.3 \
		libdq.3 dq_event_fallocate.3 \
		libdq.3 dq_event_fspacectl.3 \
		libdq.3 dq_event_lock.3 \
		libdq.3 dq_event_unlock_all.3 \
		libdq.3 dq_event_ioctl.3 \
		libdq.3 dq_event_interrupt.3 \
		libdq.3 dq_event_reply_record.3 \
		libdq.3 dq_reply_write.3 \
		libdq.3 dq_reply_fspacectl.3 \
		libdq.3 dq_reply_lock.3 \
		libdq.3 dq_reply_ioctl.3 \
		libdq.3 dq_reply_errno_allowed.3 \
		libdq.3 dq_resolve_errno_allowed.3 \
		libdq.3 dq_serve_state_create.3 \
		libdq.3 dq_serve_state_destroy.3 \
		libdq.3 dq_serve_state_owners.3 \
		libdq.3 dq_serve_file.3 \
		libdq.3 dq_resolve_accepts.3 \
		libdq.3 dq_resolve_errno_allowed_ev.3 \
		libdq.3 dq_event_resolve_ext.3 \
		libdq.3 dq_reply_resolve_fd.3 \
		libdq.3 dq_reply_resolve_attr.3 \
		libdq.3 dq_reply_resolve_link.3 \
		libdq.3 dq_reply_resolve_ok.3 \
		libdq.3 dq_reply_resolve_swap.3 \
		libdq.3 dq_tree_create.3 \
		libdq.3 dq_tree_destroy.3 \
		libdq.3 dq_tree_objects.3 \
		libdq.3 dq_serve_tree.3 \
		libdq.3 dq_tree_root.3 \
		libdq.3 dq_policy_default_dir.3 \
		libdq.3 dq_mint_dir.3 \
		libdq.3 dq_ident_from_lstat.3 \
		libdq.3 dq_reply_resolve_fd_symlink.3 \
		libdq.3 dq_reply_resolve_real.3 \
		libdq.3 dq_event_readdir.3 \
		libdq.3 dq_dirent_add.3 \
		libdq.3 dq_reply_readdir.3

# libdq.h installs to /usr/include.  The kernel ABI headers it includes,
# <dev/dq/dq.h> and <dev/dq/dq_observe_proto.h>, are installed under
# /usr/include/dev/dq by include/Makefile (the DQ INCSGROUP, in the
# clibs-dev package), so they are not installed a second time from here.
INCS=		libdq.h

CFLAGS+=	-I${SRCTOP}/sys -I${SRCTOP}/lib/libcapability

WARNS?=		6

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
