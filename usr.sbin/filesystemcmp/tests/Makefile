PACKAGE=	filesystemcmp-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/filesystemcmp

ATF_TESTS_C+=	scratch_test
SRCS.scratch_test=	scratch_test.c scratch.c
CFLAGS.scratch_test+=	-I${.CURDIR}/.. -I${SRCTOP}/lib/libfilesystemcmp
.PATH:		${.CURDIR}/..

ATF_TESTS_SH+=	bundle_test
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@OBJTOP@,${OBJTOP},g'

.include <bsd.test.mk>
