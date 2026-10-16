SUBDIR=		dtaudit		\
		dtmalloc	\
		dtnfscl		\
		dtrace		\
		dtraceall	\
		dtrace_test	\
		fbt		\
		profile		\
		prototype	\
		sdt		\
		systrace

.if ${MACHINE_CPUARCH} == "amd64"
SUBDIR+=	fasttrap systrace_linux
.endif
.if ${MACHINE_CPUARCH} == "amd64"
SUBDIR+=	kinst
.endif
.if ${MACHINE_CPUARCH} == "riscv" || ${MACHINE_CPUARCH} == "aarch64"
SUBDIR+=	kinst
.endif
.include <bsd.subdir.mk>
