# Install the complete native Markdown book with no rendering dependency.
# Keep the chapter list aligned with docs/book/src; the installer test checks
# that every source chapter is installed at the same relative path.

PACKAGE=	runtime
BOOKSRC=	${SRCTOP}/docs/book/src
BOOKDEST=	${SHAREDIR}/doc/5bsd

FILESGROUPS=

FILESGROUPS+=	BOOK_ROOT
BOOK_ROOT=	${BOOKSRC}/SUMMARY.md \
		${BOOKSRC}/introduction.md
BOOK_ROOTDIR=	${BOOKDEST}

FILESGROUPS+=	BOOK_APPENDIX
BOOK_APPENDIX=	${BOOKSRC}/appendix/design-docs.md \
		${BOOKSRC}/appendix/glossary.md \
		${BOOKSRC}/appendix/man-index.md \
		${BOOKSRC}/appendix/syscalls-and-sysctls.md
BOOK_APPENDIXDIR=	${BOOKDEST}/appendix

FILESGROUPS+=	BOOK_CAPABILITY
BOOK_CAPABILITY=	${BOOKSRC}/capability/authority-model.md \
		${BOOKSRC}/capability/capability-mode-and-launch.md \
		${BOOKSRC}/capability/coalitions-and-accounting.md \
		${BOOKSRC}/capability/descriptor-protections.md \
		${BOOKSRC}/capability/mac-abac.md \
		${BOOKSRC}/capability/mac-capability.md \
		${BOOKSRC}/capability/oes.md \
		${BOOKSRC}/capability/policy-points.md \
		${BOOKSRC}/capability/system-gates.md \
		${BOOKSRC}/capability/veriexec.md
BOOK_CAPABILITYDIR=	${BOOKDEST}/capability

FILESGROUPS+=	BOOK_COMPAT
BOOK_COMPAT=	${BOOKSRC}/compat/bsd-side.md \
		${BOOKSRC}/compat/jails.md \
		${BOOKSRC}/compat/packages.md \
		${BOOKSRC}/compat/rc-and-service.md \
		${BOOKSRC}/compat/sessions.md \
		${BOOKSRC}/compat/virtual-machines.md
BOOK_COMPATDIR=	${BOOKDEST}/compat

FILESGROUPS+=	BOOK_COMPAT_LINUX
BOOK_COMPAT_LINUX=	${BOOKSRC}/compat/linux/io-uring.md \
		${BOOKSRC}/compat/linux/overview.md \
		${BOOKSRC}/compat/linux/procfs-sysfs.md \
		${BOOKSRC}/compat/linux/running-apps.md \
		${BOOKSRC}/compat/linux/sandboxing.md \
		${BOOKSRC}/compat/linux/syscalls.md
BOOK_COMPAT_LINUXDIR=	${BOOKDEST}/compat/linux

FILESGROUPS+=	BOOK_DEVELOP
BOOK_DEVELOP=	${BOOKSRC}/develop/choosing.md \
		${BOOKSRC}/develop/consumer-app.md \
		${BOOKSRC}/develop/device-driver-bundle.md \
		${BOOKSRC}/develop/kernel-extension.md \
		${BOOKSRC}/develop/linux-application.md \
		${BOOKSRC}/develop/migrating-an-rc-daemon.md \
		${BOOKSRC}/develop/packaging.md \
		${BOOKSRC}/develop/per-user-agent.md \
		${BOOKSRC}/develop/provider.md \
		${BOOKSRC}/develop/testing.md
BOOK_DEVELOPDIR=	${BOOKDEST}/develop

FILESGROUPS+=	BOOK_OPERATIONS
BOOK_OPERATIONS=	${BOOKSRC}/operations/boot-knobs.md \
		${BOOKSRC}/operations/building.md \
		${BOOKSRC}/operations/installing.md \
		${BOOKSRC}/operations/observability.md \
		${BOOKSRC}/operations/tools.md \
		${BOOKSRC}/operations/troubleshooting.md \
		${BOOKSRC}/operations/upgrading.md
BOOK_OPERATIONSDIR=	${BOOKDEST}/operations

FILESGROUPS+=	BOOK_ORIENTATION
BOOK_ORIENTATION=	${BOOKSRC}/orientation/boot-to-login.md \
		${BOOKSRC}/orientation/how-to-read.md \
		${BOOKSRC}/orientation/what-5bsd-is.md
BOOK_ORIENTATIONDIR=	${BOOKDEST}/orientation

FILESGROUPS+=	BOOK_PLANE
BOOK_PLANE=	${BOOKSRC}/plane/anointments.md \
		${BOOKSRC}/plane/bundles-and-manifests.md \
		${BOOKSRC}/plane/capsule.md \
		${BOOKSRC}/plane/containers-and-storage.md \
		${BOOKSRC}/plane/discovery-and-lookup.md \
		${BOOKSRC}/plane/logging-audit-trace.md \
		${BOOKSRC}/plane/management-model.md \
		${BOOKSRC}/plane/switchboard.md
BOOK_PLANEDIR=	${BOOKDEST}/plane

FILESGROUPS+=	BOOK_PROVIDERS
BOOK_PROVIDERS=	${BOOKSRC}/providers/audit.md \
		${BOOKSRC}/providers/auth.md \
		${BOOKSRC}/providers/bluetooth.md \
		${BOOKSRC}/providers/crypto.md \
		${BOOKSRC}/providers/device.md \
		${BOOKSRC}/providers/extension.md \
		${BOOKSRC}/providers/filesystem.md \
		${BOOKSRC}/providers/log.md \
		${BOOKSRC}/providers/namespace.md \
		${BOOKSRC}/providers/network.md \
		${BOOKSRC}/providers/notify.md \
		${BOOKSRC}/providers/overview.md \
		${BOOKSRC}/providers/power.md \
		${BOOKSRC}/providers/sysctl.md \
		${BOOKSRC}/providers/time.md \
		${BOOKSRC}/providers/trace.md \
		${BOOKSRC}/providers/vm.md
BOOK_PROVIDERSDIR=	${BOOKDEST}/providers

.for group in ${FILESGROUPS}
${group}PACKAGE=	runtime
${group}DIR_OWN=	${SHAREOWN}
${group}DIR_GRP=	${SHAREGRP}
.endfor

.include <bsd.prog.mk>
