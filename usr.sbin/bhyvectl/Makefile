.include <src.opts.mk>

.PATH: ${.CURDIR}/${MACHINE_CPUARCH}

PROG=	bhyvectl
SRCS=	bhyvectl.c
PACKAGE=	bhyve

.include "${MACHINE_CPUARCH}/Makefile.inc"

MAN=	bhyvectl.8

LIBADD=	vmmapi util

CFLAGS+= -I${.CURDIR} -I${SRCTOP}/sys/amd64/vmm

.if ${MK_BHYVE_SNAPSHOT} != "no"
LIBADD+= nv
CFLAGS+= -DBHYVE_SNAPSHOT

# usr.sbin/bhyve/snapshot.h needs ucl header
CFLAGS+= -I${SRCTOP}/contrib/libucl/include
CFLAGS+= -I${SRCTOP}/usr.sbin/bhyve
.endif

.include <bsd.prog.mk>

#
# Snapshot support changes the preprocessor view of bhyvectl.c, but the normal
# object dependency graph does not include CFLAGS.  Keep the build mode in an
# explicit prerequisite so reusing an object directory for no -> yes (or the
# reverse) cannot leave a stale bhyvectl that disagrees with bhyve.
#
BHYVECTL_SNAPSHOT_MODE_FILE=${.OBJDIR}/.bhyvectl_snapshot_mode
BHYVECTL_SNAPSHOT_MODE=${MK_BHYVE_SNAPSHOT}

.PHONY: bhyvectl_snapshot_mode_force
bhyvectl_snapshot_mode_force:

${BHYVECTL_SNAPSHOT_MODE_FILE}: bhyvectl_snapshot_mode_force
	@if test -r ${.TARGET} && \
	    test "`cat ${.TARGET}`" = "${BHYVECTL_SNAPSHOT_MODE}"; then \
		:; \
	else \
		rm -f ${OBJS} ${PROG}.full; \
		printf '%s\n' "${BHYVECTL_SNAPSHOT_MODE}" >${.TARGET}.tmp && \
		mv ${.TARGET}.tmp ${.TARGET}; \
	fi

.for _bhyvectl_object in ${OBJS}
${_bhyvectl_object}: ${BHYVECTL_SNAPSHOT_MODE_FILE}
.endfor
