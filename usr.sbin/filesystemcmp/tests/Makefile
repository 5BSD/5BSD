PACKAGE=	filesystemcmp-tests
TESTSDIR=	${TESTSBASE}/usr.sbin/filesystemcmp

CFLAGS+=	-I${.CURDIR}/.. -I${SRCTOP}/lib/libfilesystemcmp
CFLAGS+=	-I${SRCTOP}/lib/libservice

ATF_TESTS_C+=	scratch_test
SRCS.scratch_test=	scratch_test.c scratch.c

ATF_TESTS_C+=	disk_test
SRCS.disk_test=	disk_test.c disk.c

ATF_TESTS_C+=	store_test
SRCS.store_test=	store_test.c disk.c scratch.c store.c
.PATH:		${.CURDIR}/..

ATF_TESTS_SH+=	bundle_test
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@SRCTOP@,${SRCTOP},g'
ATF_TESTS_SH_SED_bundle_test+=	-e 's,@OBJTOP@,${OBJTOP},g'

.include <bsd.test.mk>
