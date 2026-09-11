PACKAGE= tests
TESTSDIR= ${TESTSBASE}/sbin/veriexec
ATF_TESTS_C+= manifest_test
SRCS.manifest_test= manifest_test.c manifest_parser.y manifest_lexer.l
CFLAGS+= -I${.CURDIR}/.. -I${.OBJDIR}
CFLAGS+= -I${SRCTOP}/sys -I${SRCTOP}/lib/libsecureboot/h
CFLAGS+= -I${SRCTOP}/contrib/bearssl/inc
CFLAGS+= -Dioctl=veriexec_test_ioctl
WARNS= 0
NO_SHARED=
.PATH: ${.CURDIR}/..
.include <bsd.test.mk>
