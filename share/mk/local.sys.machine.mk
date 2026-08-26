
.-include <site.sys.machine.mk>

PSEUDO_MACHINE_LIST?= common host host32
# 5BSD is 64-bit only: no 32-bit build targets (dropped i386 and arm/armv7).
TARGET_MACHINE_LIST?= amd64 arm64 powerpc riscv

MACHINE_ARCH_host?= ${_HOST_ARCH}
MACHINE_ARCH_host32?= ${_HOST_ARCH32}

MACHINE_ARCH_LIST_arm?= armv7
MACHINE_ARCH_LIST_arm64?= aarch64
MACHINE_ARCH_LIST_powerpc?= powerpc64 powerpc64le ${EXTRA_ARCHES_powerpc}
MACHINE_ARCH_LIST_riscv?= riscv64

.for m in ${TARGET_MACHINE_LIST}
MACHINE_ARCH_LIST_$m?= $m
MACHINE_ARCH_$m?= ${MACHINE_ARCH_LIST_$m:[1]}
# for backwards comatability
MACHINE_ARCH.$m?= ${MACHINE_ARCH_$m}
.endfor

.if empty(MACHINE_ARCH)
MACHINE_ARCH:= ${MACHINE_ARCH_${MACHINE}}
.endif
