# pfctl(8) from OpenBSD (contrib/openbsd-pf/sbin/pfctl), built for 5BSD.
# 5BSD glue lives in sys/netpfil/openbsd-pf/user (force-included header and
# shadow headers that select OpenBSD's net/pfvar.h).

.include <src.opts.mk>

PACKAGE=pf
CONFS=	pf.os
PROG=	pfctl
MAN=	pfctl.8

PFCTL_SRC=	${SRCTOP}/contrib/openbsd-pf/sbin/pfctl
.PATH: ${PFCTL_SRC} ${SRCTOP}/contrib/openbsd-pf/sys/net \
	${SRCTOP}/contrib/openbsd-pf/etc

SRCS=	pfctl.c parse.y pfctl_parser.c pf_print_state.c
SRCS+=	pfctl_osfp.c pfctl_radix.c pfctl_table.c
SRCS+=	pfctl_optimize.c pf_ruleset.c pfctl_queue.c
# 5BSD glue: the "jail" rule option
.PATH: ${SRCTOP}/sys/netpfil/openbsd-pf/user
SRCS+=	pfctl_jail.c

CFLAGS+= -I${SRCTOP}/sys/netpfil/openbsd-pf/user -I${PFCTL_SRC}
CFLAGS+= -include ${SRCTOP}/sys/netpfil/openbsd-pf/user/openbsd_compat.h
WARNS?=	2
# OpenBSD formats 64-bit values with %ll; these are LP64-safe here.
NO_WFORMAT=
CWARNFLAGS+= -Wno-incompatible-pointer-types-discards-qualifiers
YFLAGS=

LIBADD=	jail m md

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
