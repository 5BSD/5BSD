# 5BSD glue for the OpenBSD PF regress corpus in contrib/openbsd-pf.
# The corpus is installed beneath ${TESTSDIR}/srctree (tests/srctree.mk) so
# installed tests do not depend on the build machine's source tree.

PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/sys/netpfil/pf/openbsd

ATF_TESTS_SH+=	openbsd_regress
TEST_METADATA.openbsd_regress+=	execenv="jail" \
				required_user="root" \
				is_exclusive="true"

SRCTREE_FILES!=	cd ${SRCTOP} && find contrib/openbsd-pf -type f \
		    ! -name README.5BSD | sort

# bmake-adapted copy of OpenBSD's bsd.regress.mk (see bsd.regress.mk.sed).
FILESGROUPS+=	REGRESSMK
REGRESSMK=	bsd.regress.mk
REGRESSMKDIR=	${TESTSDIR}/mk
REGRESSMKPACKAGE=	${PACKAGE}
CLEANFILES+=	bsd.regress.mk
bsd.regress.mk: ${SRCTOP}/contrib/openbsd-pf/share/mk/bsd.regress.mk \
    ${.CURDIR}/bsd.regress.mk.sed
	sed -f ${.CURDIR}/bsd.regress.mk.sed \
	    ${SRCTOP}/contrib/openbsd-pf/share/mk/bsd.regress.mk > ${.TARGET}

.include "${SRCTOP}/tests/srctree.mk"
.include <bsd.test.mk>
