.include <src.opts.mk>

PACKAGE=	libcapbundle-tests
TESTSDIR=	${TESTSBASE}/lib/libcapbundle

# servicectl is a source helper rather than a generated ATF test program.
# Make it available when install is run from the object directory.
.PATH:	${.CURDIR}

ATF_TESTS_SH=	libcapbundle_test
ATF_TESTS_SH_SED_libcapbundle_test+=	-e 's,@OBJTOP@,${OBJTOP},g'
ATF_TESTS_SH_SED_libcapbundle_test+=	-e 's,@SRCTOP@,${SRCTOP},g'

SCRIPTS+=	servicectl
SCRIPTSDIR_servicectl=	${TESTSDIR}

.include <bsd.test.mk>
