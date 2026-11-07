#
# DescriptorQueue controller library (libdq).
#

.include <src.opts.mk>

PACKAGE=	dq
LIB=		dq
SHLIB_MAJOR=	1
SRCS=		libdq.c
LIBADD=		capability

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
		libdq.3 dq_observe_subscribe.3

# libdq.h installs to /usr/include.  The kernel ABI headers it includes,
# <dev/dq/dq.h> and <dev/dq/dq_observe_proto.h>, are installed under
# /usr/include/dev/dq by include/Makefile (LSUBDIRS lists dev/dq), so they
# are not installed a second time from here.
INCS=		libdq.h

CFLAGS+=	-I${SRCTOP}/sys -I${SRCTOP}/lib/libcapability

WARNS?=		6

.include <bsd.lib.mk>
