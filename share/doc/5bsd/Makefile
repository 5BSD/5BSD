# Install the native 5BSD Markdown book with the base system.  It deliberately
# has no mdBook build dependency: every installed machine can read the source
# with standard base tools, while sites may render it to HTML separately.

PACKAGE=	runtime
BOOKSRC=	${SRCTOP}/docs/book/src

FILESGROUPS=	ROOT SECURITY DEVELOPMENT SYSTEM STORAGE VIRTUALIZATION \
		BLUETOOTH OBSERVABILITY OPERATIONS

ROOT=		${BOOKSRC}/SUMMARY.md \
		${BOOKSRC}/architecture.md \
		${BOOKSRC}/introduction.md
ROOTDIR=	${SHAREDIR}/doc/5bsd

SECURITY=	${BOOKSRC}/security/auditbrokerd.md \
		${BOOKSRC}/security/authority-model.md \
		${BOOKSRC}/security/capability-bundles.md \
		${BOOKSRC}/security/crypto.md \
		${BOOKSRC}/security/endpoint-security.md \
		${BOOKSRC}/security/mac-capability.md \
		${BOOKSRC}/security/process-protections.md \
		${BOOKSRC}/security/rootless-hardening.md
SECURITYDIR=	${ROOTDIR}/security

DEVELOPMENT=	${BOOKSRC}/development/hybrid-model.md \
		${BOOKSRC}/development/writing-components.md
DEVELOPMENTDIR=	${ROOTDIR}/development

SYSTEM=		${BOOKSRC}/system/bsdnotify.md \
		${BOOKSRC}/system/capsule.md \
		${BOOKSRC}/system/localdevice.md \
		${BOOKSRC}/system/localnetwork.md \
		${BOOKSRC}/system/localsysctl.md \
		${BOOKSRC}/system/logd.md \
		${BOOKSRC}/system/manifests.md \
		${BOOKSRC}/system/serviced.md
SYSTEMDIR=	${ROOTDIR}/system

STORAGE=	${BOOKSRC}/storage/trustedzfs.md
STORAGEDIR=	${ROOTDIR}/storage

VIRTUALIZATION=	${BOOKSRC}/virtualization/overview.md
VIRTUALIZATIONDIR=${ROOTDIR}/virtualization

BLUETOOTH=	${BOOKSRC}/bluetooth/overview.md
BLUETOOTHDIR=	${ROOTDIR}/bluetooth

OBSERVABILITY=	${BOOKSRC}/observability/observablebsd.md
OBSERVABILITYDIR=${ROOTDIR}/observability

OPERATIONS=	${BOOKSRC}/operations/building.md \
		${BOOKSRC}/operations/tools.md
OPERATIONSDIR=	${ROOTDIR}/operations

.for group in ${FILESGROUPS}
${group}PACKAGE=	runtime
.endfor

.include <bsd.prog.mk>
