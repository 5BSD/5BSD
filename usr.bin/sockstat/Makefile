.include <src.opts.mk>

PROG=		sockstat
SRCS=		main.c sockstat.c

LIBADD=		jail xo

.if ${MK_CASPER} != "no"
LIBADD+=	casper
LIBADD+=	cap_net
LIBADD+=	cap_netdb
LIBADD+=	cap_pwd
LIBADD+=	cap_sysctl
CFLAGS+=	-DWITH_CASPER
.endif

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.if ${MK_DTRACE} != "no" && !defined(RESCUE) && !defined(BOOTSTRAPPING)
SRCS+=	socketsnapshot_provider.d
CFLAGS+= -DWITH_COVERAGE_DTRACE
.endif

.include <bsd.prog.mk>
