PACKAGE=	tests

# pfctl_regress: OpenBSD's regress/sbin/pfctl corpus (installed in files/).
# pfctl_5bsd: round trips for the 5BSD pf.conf extensions.
ATF_TESTS_SH=	pfctl_regress pfctl_5bsd macro

# Every corpus case creates the interfaces the corpus names and some load
# rules, so each runs in its own VNET.
TEST_METADATA.pfctl_regress+=	execenv="jail"
TEST_METADATA.pfctl_regress+=	execenv_jail_params="vnet"

# changerule: the DIOCCHANGERULE helper of the corpus (target
# pf-changerule), built from the OpenBSD pfctl sources like pfctl(8).
REGRESS_PFCTL=	${SRCTOP}/contrib/openbsd-pf/regress/sbin/pfctl
PFCTL_SRC=	${SRCTOP}/contrib/openbsd-pf/sbin/pfctl
.PATH: ${REGRESS_PFCTL} ${PFCTL_SRC} ${SRCTOP}/contrib/openbsd-pf/sys/net
.PATH: ${SRCTOP}/sys/netpfil/openbsd-pf/user

PROGS=		changerule
BINDIR=		${TESTSDIR}
MAN.changerule=
SRCS.changerule=	changerule.c parse.y pfctl_parser.c pf_print_state.c \
			pfctl.c pfctl_osfp.c pfctl_radix.c pfctl_table.c \
			pfctl_optimize.c pf_ruleset.c pfctl_queue.c \
			pfctl_jail.c pfctl_ether.c
CFLAGS.changerule+=	-DREGRESS_NOMAIN
CFLAGS.changerule+=	-I${SRCTOP}/sys/netpfil/openbsd-pf/user -I${PFCTL_SRC}
CFLAGS.changerule+=	-include ${SRCTOP}/sys/netpfil/openbsd-pf/user/openbsd_compat.h
LIBADD.changerule=	m md
WARNS=		2
NO_WFORMAT=
CWARNFLAGS+=	-Wno-incompatible-pointer-types-discards-qualifiers
# The OpenBSD regress Makefile builds this with -Wno-unused-variable: with
# REGRESS_NOMAIN, pfctl.c leaves its option tables unused.  -Wall follows
# CWARNFLAGS, so turn it off for that file only.
CWARNFLAGS.pfctl.c+=	-Wno-unused-variable
YFLAGS=

SUBDIR+=	files

.include <bsd.test.mk>
