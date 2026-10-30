PROGS= mmap_data_test unix_dgram_close_test cron_vm_test cron_job_probe image_vm_test construction_vm_test jail_probe cap_mkdb pwd_mkdb runtime_reader
.PATH: ${SRCTOP}/usr.sbin/switchboard
SRCS.mmap_data_test= mmap_data_test.c
LIBADD.mmap_data_test= atf_c
SRCS.unix_dgram_close_test= unix_dgram_close_test.c
LIBADD.unix_dgram_close_test= atf_c
SRCS.cron_vm_test= cron_vm_test.c
SRCS.cron_job_probe= cron_job_probe.c
LIBADD.cron_vm_test= atf_c
SRCS.image_vm_test= image_vm_test.c
LIBADD.image_vm_test= atf_c
SRCS.construction_vm_test= construction_vm_test.c
SRCS.jail_probe= jail_probe.c
.PATH: ${SRCTOP}/usr.bin/cap_mkdb ${SRCTOP}/usr.sbin/pwd_mkdb \
    ${SRCTOP}/lib/libc/gen ${SRCTOP}/lib/libutil
SRCS.cap_mkdb= cap_mkdb.c
SRCS.pwd_mkdb= pwd_mkdb.c pw_scan.c
CFLAGS.pwd_mkdb+= -I${SRCTOP}/lib/libc/gen -I${SRCTOP}/lib/libutil
SRCS.runtime_reader= runtime_reader.c
LIBADD.construction_vm_test= atf_c
NO_SHARED= yes
MAN=
# Real relocatable ELF metadata fixtures; these must never be loaded as modules.
.if !defined(PROG)
.for case in 0 1 2 3 4 5 6 7 8
all: pnp-${case}.ko
pnp-${case}.ko: ${.CURDIR}/pnp_fixture.c
	${CC} ${CFLAGS} -fno-pic -DPNP_CASE=${case} -c ${.ALLSRC} -o ${.TARGET}
CLEANFILES+= pnp-${case}.ko
.endfor
.endif
# Read-only inventory review tooling; independent of VM fixture compilation.
PYTHON?= /usr/local/bin/python3.12
.PHONY: verity-core-test
verity-core-test: libverity_verify_test.so
	${PYTHON} -B ${.CURDIR}/verity_core_test.py ${.OBJDIR}/libverity_verify_test.so

libverity_verify_test.so: ${SRCTOP}/sys/geom/verity/g_verity_verify.c ${SRCTOP}/sys/geom/verity/g_verity_verify.h
	${CC} -shared -fPIC -Wall -Wextra -Werror -I${SRCTOP}/sys -o ${.TARGET} ${SRCTOP}/sys/geom/verity/g_verity_verify.c -lmd
CLEANFILES+= libverity_verify_test.so

.PHONY: verity-tree-test
verity-tree-test:
	${PYTHON} -B ${.CURDIR}/verity_tree_test.py

.PHONY: inventory-audit-test
inventory-audit-test:
	${PYTHON} -B ${.CURDIR}/inventory_audit_test.py

.PHONY: retained-verification-test
retained-verification-test:
	${PYTHON} -B ${.CURDIR}/fixture_stage_test.py
	${PYTHON} -B ${.CURDIR}/verify_retained_test.py
	${PYTHON} -B ${.CURDIR}/retained_installation_test.py

.PHONY: state-initialization-test
state-initialization-test:
	${PYTHON} -B ${.CURDIR}/state_initialization_test.py
	${PYTHON} -B ${.CURDIR}/state_readback_test.py
	${PYTHON} -B ${.CURDIR}/collect_state_readback_test.py
	${PYTHON} -B ${.CURDIR}/readback_state_vm_test.py

.PHONY: layout-transport-test
layout-transport-test:
	${PYTHON} -B ${.CURDIR}/export_layout_test.py
	${PYTHON} -B ${.CURDIR}/export_image_test.py

.include <bsd.progs.mk>

# Use the real configured kernel flags and generated headers; no kernel install.
.PHONY: verity-kernel-compile
verity-kernel-compile:
.if empty(VERITY_KERNEL_OBJDIR)
	@echo 'VERITY_KERNEL_OBJDIR must name an existing configured kernel object directory' >&2
	@false
.else
	${MAKE} -C "${VERITY_KERNEL_OBJDIR}" -f Makefile -f "${.CURDIR}/verity_kernel.mk" verity-core-compile
.endif

.PHONY: verity-io-test
verity-io-test:
	${PYTHON} -B ${.CURDIR}/verity_io_test.py

# Explicit host-only benchmark; building it does not run workloads.
.PHONY: verity-bench-build
verity-bench-build: verity_bench
verity_bench: ${.CURDIR}/verity_bench.c ${SRCTOP}/sys/geom/verity/g_verity_verify.c ${SRCTOP}/sys/geom/verity/g_verity_verify.h
	${CC} -O2 -Wall -Wextra -Werror -I${SRCTOP}/sys -I${SRCTOP}/sys/geom/verity -o ${.TARGET} ${.CURDIR}/verity_bench.c ${SRCTOP}/sys/geom/verity/g_verity_verify.c -lmd
CLEANFILES+= verity_bench

# Compile the OCF request test only; never load a module on the build host.
.PHONY: verity-crypto-kernel-compile
verity-crypto-kernel-compile:
.if empty(VERITY_KERNEL_OBJDIR)
	@echo 'VERITY_KERNEL_OBJDIR must name an existing configured kernel object directory' >&2
	@false
.else
	${MAKE} -C "${VERITY_KERNEL_OBJDIR}" -f Makefile -f "${.CURDIR}/verity_kernel.mk" verity-crypto-compile
.endif

# Explicit compatibility suite build; execution belongs in the selected test VM.
.PHONY: filesystem-test-build
filesystem-test-build: mmap_data_test
	cp ${.CURDIR}/Kyuafile.filesystem ${.OBJDIR}/Kyuafile.filesystem
CLEANFILES+= Kyuafile.filesystem

# Exercise the actual standalone headers/flags, without changing libsa contents.
.PHONY: verity-standalone-compile
verity-standalone-compile:
	${MAKE} -C ${SRCTOP}/stand/libsa -f Makefile -f ${.CURDIR}/verity_standalone.mk verity-standalone-core-compile

.PHONY: fio-result-check-test
fio-result-check-test:
	${PYTHON} -B ${.CURDIR}/fio_result_check_test.py

.PHONY: verity-provider-test
verity-provider-test:
	${PYTHON} -B ${.CURDIR}/verity_provider_test.py

# Link the real provider/core/adapter as a KLD; never load or install it.
.PHONY: verity-provider-module-build
verity-provider-module-build:
.if empty(VERITY_KERNEL_OBJDIR)
	@echo 'VERITY_KERNEL_OBJDIR must name an existing configured kernel object directory' >&2
	@false
.else
	${MAKE} -C ${SRCTOP}/sys/modules/geom/geom_verity KERNBUILDDIR="${VERITY_KERNEL_OBJDIR}" WERROR=-Werror all
.endif

.PHONY: text-pin-test
text-pin-test:
	${PYTHON} -B ${.CURDIR}/text_pin_test.py

.PHONY: verity-preload-test
verity-preload-test:
	${PYTHON} -B ${.CURDIR}/verity_preload_test.py

.PHONY: image-publication-test
image-publication-test:
	${PYTHON} -B ${.CURDIR}/image_publication_test.py

.PHONY: verity-artifacts-test
verity-artifacts-test:
	${PYTHON} -B ${.CURDIR}/verity_artifacts_test.py

# Builds regular-file UFS images; never mounts or attaches devices.
.PHONY: verity-makefs-test
verity-makefs-test:
.if empty(VERITY_MAKEFS) || empty(VERITY_FSCK) || empty(VERITY_DUMPFS)
	@echo 'VERITY_MAKEFS, VERITY_FSCK and VERITY_DUMPFS must name selected tools' >&2
	@false
.else
	${PYTHON} -B ${.CURDIR}/verity_makefs_test.py --makefs "${VERITY_MAKEFS}" --fsck "${VERITY_FSCK}" --dumpfs "${VERITY_DUMPFS}"
.endif

.PHONY: verity-loader-read-test
verity-loader-read-test:
	${PYTHON} -B ${.CURDIR}/verity_loader_read_test.py

.PHONY: verity-loader-device-test
verity-loader-device-test:
	${PYTHON} -B ${.CURDIR}/verity_loader_device_test.py

.PHONY: verity-loader-partition-test
verity-loader-partition-test:
	${PYTHON} -B ${.CURDIR}/verity_loader_partition_test.py

.PHONY: verity-loader-attach-test
verity-loader-attach-test:
	${PYTHON} -B ${.CURDIR}/verity_loader_attach_test.py

.PHONY: verity-loader-ufs-test
verity-loader-ufs-test:
	@test -n "${VERITY_MAKEFS}" || { echo "VERITY_MAKEFS is required" >&2; exit 1; }
	${PYTHON} -B ${.CURDIR}/verity_loader_ufs_test.py --makefs ${VERITY_MAKEFS:Q}

.PHONY: verity-mount-test
verity-mount-test:
	${PYTHON} -B ${.CURDIR}/verity_mount_test.py

.PHONY: verity-mountroot-test
verity-mountroot-test:
	${PYTHON} -B ${.CURDIR}/verity_mountroot_test.py

.PHONY: verity-admission-test
verity-admission-test:
	${PYTHON} -B ${.CURDIR}/verity_admission_test.py



.PHONY: nfs-setattr-test
nfs-setattr-test:
	${PYTHON} -B ${.CURDIR}/nfs_setattr_test.py

.PHONY: nfs-io-test
nfs-io-test:
	${PYTHON} -B ${.CURDIR}/nfs_io_test.py

.PHONY: nfs-access-test
nfs-access-test:
	${PYTHON} -B ${.CURDIR}/nfs_access_test.py

.PHONY: isolation-fh-test
isolation-fh-test:
	${PYTHON} -B ${.CURDIR}/isolation_fh_test.py

.PHONY: export-flags-test
export-flags-test:
	${PYTHON} -B ${.CURDIR}/export_flags_test.py





.PHONY: verity-transition-test
verity-transition-test:
	${PYTHON} -B ${.CURDIR}/verity_transition_test.py
