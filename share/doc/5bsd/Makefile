# Install the complete native Markdown book with no rendering dependency.
#
# The chapters are listed explicitly, one FILESGROUP per book directory, so
# that what the runtime package installs is a reviewed decision.  The list
# cannot drift silently: a listed chapter that no longer exists stops the
# build when this Makefile is read, and "all" runs check-book-list, which
# fails unless the installed paths are exactly the files under docs/book/src.
# The installed book is compared with the source by the bsdinstall tests.

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
BOOK_COMPAT_LINUX=	${BOOKSRC}/compat/linux/overview.md \
		${BOOKSRC}/compat/linux/procfs-sysfs.md \
		${BOOKSRC}/compat/linux/running-apps.md \
		${BOOKSRC}/compat/linux/sandboxing.md \
		${BOOKSRC}/compat/linux/syscalls.md
BOOK_COMPAT_LINUXDIR=	${BOOKDEST}/compat/linux

FILESGROUPS+=	BOOK_DEVELOP
BOOK_DEVELOP=	${BOOKSRC}/develop/choosing.md \
		${BOOKSRC}/develop/consumer-app.md \
		${BOOKSRC}/develop/device-driver-bundle.md \
		${BOOKSRC}/develop/fidl.md \
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
		${BOOKSRC}/operations/graphics.md \
		${BOOKSRC}/operations/installing.md \
		${BOOKSRC}/operations/observability.md \
		${BOOKSRC}/operations/pf.md \
		${BOOKSRC}/operations/rdomains.md \
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
BOOK_PLANE=	${BOOKSRC}/plane/attributes.md \
		${BOOKSRC}/plane/bundles-and-manifests.md \
		${BOOKSRC}/plane/capsule.md \
		${BOOKSRC}/plane/containers-and-storage.md \
		${BOOKSRC}/plane/discovery-and-lookup.md \
		${BOOKSRC}/plane/logging-audit-trace.md \
		${BOOKSRC}/plane/management-model.md \
		${BOOKSRC}/plane/management-policy.md \
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

# Each listed chapter as the path it is installed at below BOOKDEST.
BOOK_INSTALLED=
.for group in ${FILESGROUPS}
.for f in ${${group}}
.if !exists(${f})
.error ${f:S,^${SRCTOP}/,,} is listed in ${group} of ${.CURDIR:S,^${SRCTOP}/,,}/Makefile but does not exist
.endif
BOOK_INSTALLED+=	${${group}DIR:S,^${BOOKDEST},,:S,^/,,:S,$,/,:S,^/$,,}${f:T}
.endfor
.endfor

all: check-book-list
check-book-list: .PHONY
	@listed=$$(printf '%s\n' ${BOOK_INSTALLED} | LC_ALL=C sort); \
	found=$$(cd ${BOOKSRC} && find . -type f | sed 's,^\./,,' | \
	    LC_ALL=C sort); \
	[ "$$listed" = "$$found" ] && exit 0; \
	echo "${.CURDIR}/Makefile does not match ${BOOKSRC}:" >&2; \
	printf '%s\n' "$$found" | grep -vxF "$$listed" | sed \
	    's|^|  not installed, add it to the group for its directory: |' >&2; \
	printf '%s\n' "$$listed" | grep -vxF "$$found" | sed \
	    's|^|  installed path has no source, wrong group?: |' >&2; \
	exit 1

# Check the book's claims (system calls, constants, sysctls, manual pages
# and links) against this source tree.  Not part of "all": the installed
# bsdinstall tests run the same check (native_book_matches_code).
checkbook: .PHONY
	sh ${SRCTOP}/docs/book/tools/check-book.sh ${SRCTOP}

.include <bsd.prog.mk>
