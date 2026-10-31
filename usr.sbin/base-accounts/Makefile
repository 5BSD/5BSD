.include <src.opts.mk>

PACKAGE=	runtime
SCRIPTS=	base-accounts.sh
MAN=		base-accounts.8

# A pristine copy of the shipped account files.  /etc/group and
# /etc/master.passwd are configuration files that pkg(8) may leave unmerged
# (.pkgnew); the runtime package's post-install compares the installed files
# against this copy and creates what is missing.
FILESGROUPS=	REFERENCE
REFERENCE=	${SRCTOP}/etc/group ${SRCTOP}/etc/master.passwd
REFERENCEDIR=	/usr/share/base-accounts
REFERENCEMODE=	0444
REFERENCEPACKAGE=	runtime

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.prog.mk>
