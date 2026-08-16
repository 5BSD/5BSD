.PATH: ${SRCTOP}/usr.sbin/mac_abacd

.include <src.opts.mk>

PACKAGE=	mac-abac
PROG=		mac_abac_ctl
SRCS=		mac_abac_ctl.c mac_abac_ctl_label.c mac_abac_ctl_rule.c \
		mac_abac_ctl_set.c parse_line.c parse_ucl.c
MAN=

CFLAGS+=	-I${SRCTOP}/sys
CFLAGS+=	-I${SRCTOP}/usr.sbin/mac_abacd
CFLAGS+=	-I${SRCTOP}/contrib/libucl/include
NO_WCAST_ALIGN=
LIBADD=	ucl

# The mac_syscall(2) ABI used by management clients is public.
INCS=		${SRCTOP}/sys/security/mac_abac/mac_abac.h
INCSDIR=	${INCLUDEDIR}/security/mac_abac
# bsd.incs.mk installs headers into an existing directory.  A clean
# DESTDIR (as used by release VM images) does not have this ABI directory.
MAC_ABACINCDIR=	${INCSDIR}
MAC_ABACINCDIRPACKAGE=	mac-abac
DIRS+=		MAC_ABACINCDIR

.include <bsd.prog.mk>
