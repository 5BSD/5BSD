PACKAGE=	bsdnotify-tests

ATF_TESTS_SH=	notifyctl_test

PROGS+=		notifyctl_test_bin
PROGS+=		notifyctl_success_bin
BINDIR_notifyctl_test_bin=	${TESTSDIR}
SRCS.notifyctl_test_bin=	notifyctl.c policy.c
NO_SHARED.notifyctl_test_bin=	yes
CFLAGS.notifyctl_test_bin+=	-I${SRCTOP}/lib/libnotifycmp
CFLAGS.notifyctl_test_bin+=	-I${SRCTOP}/usr.sbin/bsdnotify
CFLAGS.notifyctl_test_bin+=	-I${SRCTOP}/contrib/libucl/include
LIBADD.notifyctl_test_bin+=	notifycmp ucl

BINDIR_notifyctl_success_bin=	${TESTSDIR}
SRCS.notifyctl_success_bin=	notifyctl_success_impl.c \
	notifycmp_policy_success_impl.c fake_notifycmp.c
NO_SHARED.notifyctl_success_bin=	yes
CFLAGS.notifyctl_success_bin+=	-I${SRCTOP}/lib/libnotifycmp
CFLAGS.notifyctl_success_bin+=	-I${SRCTOP}/usr.sbin/bsdnotify
CFLAGS.notifyctl_success_bin+=	-I${SRCTOP}/contrib/libucl/include
LIBADD.notifyctl_success_bin+=	ucl

.PATH:	${SRCTOP}/usr.sbin/notifyctl ${SRCTOP}/usr.sbin/bsdnotify

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
