PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sbin/pfctl/files
BINDIR=		${TESTSDIR}
BINDIRPACKAGE=	${PACKAGE}

# OpenBSD's pfctl regression corpus, installed unchanged.  Its Makefile is
# installed as regress.mk: pfctl_regress reads the test lists from it.
REGRESS_PFCTL=	${SRCTOP}/contrib/openbsd-pf/regress/sbin/pfctl
FILES!=		find ${REGRESS_PFCTL} -maxdepth 1 -type f \
		    ! -name Makefile ! -name changerule.c | sort
FILES+=		${REGRESS_PFCTL}/Makefile
FILESNAME_Makefile=	regress.mk

# The 5BSD extension round trips (pfctl_5bsd).
FILES!=		echo ${FILES} ${.CURDIR}/ext*.in ${.CURDIR}/ext*.ok

.include <bsd.progs.mk>
