PACKAGE=	logd-tests

ATF_TESTS_SH=	logctl_test

PROGS+=		logctl_test_bin
PROGS+=		logctl_success_bin
BINDIR_logctl_test_bin=	${TESTSDIR}
SRCS.logctl_test_bin=	logctl.c config.c
NO_SHARED.logctl_test_bin=	yes
CFLAGS.logctl_test_bin+=	-I${SRCTOP}/lib/liblogcmp
CFLAGS.logctl_test_bin+=	-I${SRCTOP}/usr.sbin/logd
CFLAGS.logctl_test_bin+=	-I${SRCTOP}/contrib/libucl/include
LIBADD.logctl_test_bin+=	logcmp ucl

BINDIR_logctl_success_bin=	${TESTSDIR}
SRCS.logctl_success_bin=	logctl_success_impl.c \
	logcmp_config_success_impl.c fake_logcmp.c
NO_SHARED.logctl_success_bin=	yes
CFLAGS.logctl_success_bin+=	-I${SRCTOP}/lib/liblogcmp
CFLAGS.logctl_success_bin+=	-I${SRCTOP}/usr.sbin/logd
CFLAGS.logctl_success_bin+=	-I${SRCTOP}/contrib/libucl/include
LIBADD.logctl_success_bin+=	ucl

.PATH:	${SRCTOP}/usr.sbin/logctl ${SRCTOP}/usr.sbin/logd

${PACKAGE}FILES+=	valid.conf
${PACKAGE}FILES+=	invalid.conf

.if ${.OBJDIR} != ${.CURDIR}
.for file in valid.conf invalid.conf
${.OBJDIR}/${file}: ${.CURDIR}/${file}
	${CP} ${.ALLSRC} ${.TARGET}
all: ${.OBJDIR}/${file}
CLEANFILES+=	${file}
.endfor
.endif

.include <bsd.test.mk>
