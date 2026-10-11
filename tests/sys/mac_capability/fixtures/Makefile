# Deliberately not a SUBDIR of the installed test suite or sys/modules.
SUBDIR= kernelstore keystore
SUBDIR_PARALLEL= yes
.if make(install) || make(realinstall) || make(package)
.error Capability fixtures are built explicitly for isolated tests and are not installed
.endif
.include <bsd.subdir.mk>
