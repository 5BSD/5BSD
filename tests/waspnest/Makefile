PACKAGE=	waspnest-tests
TESTSDIR=	${TESTSBASE}/waspnest
SCRIPTSDIR=	${TESTSDIR}

.PATH: ${SRCTOP}/docs ${SRCTOP}/tests/sys/kern/vsock_e2e

ATF_TESTS_SH+=	waspnest_package_test

SCRIPTS+=	waspnest-test.sh
SCRIPTSNAME_waspnest-test.sh=	waspnest-test
SCRIPTS+=	validate-nonvirtio-coverage.sh
SCRIPTS+=	validate-package-layout.sh

${PACKAGE}FILES+=	README.md
${PACKAGE}FILES+=	waspnest-suite.tsv
${PACKAGE}FILES+=	waspnest-nonvirtio-coverage.tsv
${PACKAGE}FILES+=	waspnest-completion-matrix.md
${PACKAGE}FILES+=	virtio-lab.lua
# The shell tests resolve the runner and manifest through atf_get_srcdir().
# Copy the installed-file layout into a separate object directory so object
# tree and packaged Kyua runs exercise the same payload.
WASPNEST_OBJECT_FILES=	waspnest-test.sh \
			validate-nonvirtio-coverage.sh \
			validate-package-layout.sh \
			waspnest-suite.tsv \
			waspnest-nonvirtio-coverage.tsv

.if ${.OBJDIR} != ${.CURDIR}
CLEANFILES+=	${WASPNEST_OBJECT_FILES}
CLEANFILES+=	virtio-lab.lua
beforedepend:	${WASPNEST_OBJECT_FILES} virtio-lab.lua
.for _waspnest_object_file in ${WASPNEST_OBJECT_FILES}
${_waspnest_object_file}: ${.CURDIR}/${_waspnest_object_file}
	cp ${.ALLSRC} ${.TARGET}.tmp.${.MAKE.PID}
	mv -f ${.TARGET}.tmp.${.MAKE.PID} ${.TARGET}
.endfor
virtio-lab.lua: ${SRCTOP}/tests/sys/kern/vsock_e2e/virtio-lab.lua
	cp ${.ALLSRC} ${.TARGET}.tmp.${.MAKE.PID}
	mv -f ${.TARGET}.tmp.${.MAKE.PID} ${.TARGET}
.endif

.include <bsd.test.mk>
