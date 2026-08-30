PACKAGE=runtime
PROG=	reboot
MAN=	reboot.8 nextboot.8

# reboot(8)/halt(8) delegate a clean shutdown to authorityctl(8) by fork+exec
# (docs/lifecycle-capability-design.md) and fall back to reboot(2); they stay
# self-contained /sbin binaries with no /usr runtime or capability-library
# dependency (the exec failure is handled).
MLINKS=	reboot.8 halt.8 reboot.8 fastboot.8 reboot.8 fasthalt.8

.if exists(${.CURDIR}/boot_${MACHINE}.8)
MAN+=	boot_${MACHINE}.8
MLINKS+= boot_${MACHINE}.8 boot.8
.endif
.if ${MACHINE} == "amd64"
MAN+=	boot_i386.8
MLINKS+= boot_i386.8 boot.8
.endif

LINKS=	${BINDIR}/reboot ${BINDIR}/halt \
	${BINDIR}/reboot ${BINDIR}/fastboot \
	${BINDIR}/reboot ${BINDIR}/fasthalt \
	${BINDIR}/reboot ${BINDIR}/nextboot

.include <bsd.prog.mk>
