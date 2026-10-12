.include <src.opts.mk>
PACKAGE= capsign-tests
TESTSDIR= ${TESTSBASE}/usr.sbin/capsign
ATF_TESTS_SH= capsign_test veriexec_test
.PATH: ${SRCTOP}/tools/build/capimage
SCRIPTS+= sign-stage.sh prepare-stage.sh verify-stage.sh
SCRIPTSNAME_sign-stage.sh= sign-stage.sh
SCRIPTSDIR_sign-stage.sh= ${TESTSDIR}
SCRIPTSNAME_prepare-stage.sh= prepare-stage.sh
SCRIPTSDIR_prepare-stage.sh= ${TESTSDIR}
SCRIPTSNAME_verify-stage.sh= verify-stage.sh
SCRIPTSDIR_verify-stage.sh= ${TESTSDIR}
.if ${.OBJDIR} != ${.CURDIR}
${.OBJDIR}/sign-stage.sh: ${SRCTOP}/tools/build/capimage/sign-stage.sh
	${CP} ${.ALLSRC} ${.TARGET}
${.OBJDIR}/prepare-stage.sh: ${SRCTOP}/tools/build/capimage/prepare-stage.sh
	${CP} ${.ALLSRC} ${.TARGET}
${.OBJDIR}/verify-stage.sh: ${SRCTOP}/tools/build/capimage/verify-stage.sh
	${CP} ${.ALLSRC} ${.TARGET}
all: ${.OBJDIR}/sign-stage.sh ${.OBJDIR}/prepare-stage.sh ${.OBJDIR}/verify-stage.sh
CLEANFILES+= sign-stage.sh prepare-stage.sh verify-stage.sh
.endif
.include <bsd.test.mk>
