.include <kmod.opts.mk>

KMOD=	vmm

SRCS+=	acpi_if.h bus_if.h device_if.h pci_if.h pcib_if.h vnode_if.h

CFLAGS+= -DVMM_KEEP_STATS
CFLAGS+= -I${SRCTOP}/sys/${MACHINE}/vmm

# generic vmm support
.PATH: ${SRCTOP}/sys/dev/vmm ${SRCTOP}/sys/${MACHINE}/vmm

SRCS+=	vmm.c			\
	vmm_dev.c		\
	vmm_dev_machdep.c	\
	vmm_instruction_emul.c	\
	vmm_event_checkpoint.c	\
	vmm_event_coordinator.c	\
	vmm_event_ingress.c	\
	vmm_startup_event.c	\
	vmm_startup_mode.c	\
	vmm_startup_entry_owner.c	\
	vmm_startup_handshake.c	\
	vmm_startup_controller.c	\
	vmm_startup_request.c	\
	vmm_startup_run_request.c	\
	vmm_event_wait.c	\
	vmm_dirty_log.c	\
	vmm_dirty_log_collector.c	\
	vmm_dirty_log_machdep.c	\
	vmm_dirty_log_map.c	\
	vmm_dirty_log_owner.c	\
	vmm_dirty_log_request.c	\
	vmm_mem.c		\
	vmm_stat.c		\
	vmm_vm.c

.if ${MACHINE_CPUARCH} == "aarch64"
CFLAGS+= -I${SRCTOP}/sys/${MACHINE}/vmm/io
DPSRCS+=	assym.inc

# TODO: Add the new EL2 code
SRCS+=	vmm_arm64.c \
	vmm_reset.c \
	vmm_call.S \
	vmm_handlers.c \
	vmm_mmu.c \
	vmm_vhe_exception.S \
	vmm_vhe.c \
	vmm_hyp_el2.S

.PATH: ${SRCTOP}/sys/${MACHINE}/vmm/io
SRCS+=	vgic.c \
	vgic_if.h \
	vgic_if.c \
	vgic_v3.c \
	vtimer.c

CLEANFILES+=	vmm_nvhe_exception.o vmm_nvhe.o

CLEANFILES+=	vmm_hyp_blob.elf.full
CLEANFILES+=	vmm_hyp_blob.elf vmm_hyp_blob.bin

vmm_nvhe_exception.o: vmm_nvhe_exception.S vmm_hyp_exception.S
	${CC} -c -x assembler-with-cpp -DLOCORE \
	    ${NOSAN_CFLAGS:N-mbranch-protection*} ${.IMPSRC} -o ${.TARGET} -fpie

vmm_nvhe.o: vmm_nvhe.c vmm_hyp.c
	${CC} -c ${NOSAN_CFLAGS:N-mbranch-protection*} ${.IMPSRC} \
	    -o ${.TARGET} -fpie

vmm_hyp_blob.elf.full:	vmm_nvhe_exception.o vmm_nvhe.o
	${LD} -m ${LD_EMULATION} -Bdynamic -L ${SYSDIR}/conf -T ${SYSDIR}/conf/ldscript.arm64 \
	    ${_LDFLAGS:N-zbti-report*} --no-warn-mismatch --warn-common --export-dynamic \
	    --dynamic-linker /red/herring -X -o ${.TARGET} ${.ALLSRC} \
	    --defsym=_start='0x0' --defsym=text_start='0x0'

vmm_hyp_blob.elf:	vmm_hyp_blob.elf.full
	${OBJCOPY} --strip-debug ${.ALLSRC} ${.TARGET}

vmm_hyp_blob.bin:	vmm_hyp_blob.elf
	${OBJCOPY} --output-target=binary ${.ALLSRC} ${.TARGET}

vmm_hyp_el2.o:	vmm_hyp_blob.bin

.elif ${MACHINE_CPUARCH} == "amd64"
CFLAGS+= -I${SRCTOP}/sys/${MACHINE}/vmm/io
DPSRCS+=	vmx_assym.h svm_assym.h
DPSRCS+=	vmx_genassym.c svm_genassym.c offset.inc

SRCS+=	vmm_event_state.c vmm_exception.c vmm_intinfo.c \
	vmm_x86_startup_state.c vmm_x86_startup_transaction.c \
	vmm_x86_startup_machine.c vmm_x86_startup_vmreg.c \
	vmm_x86_startup_backend.c vmm_x86_startup_finalizer.c

CFLAGS+= -I${SRCTOP}/sys/amd64/vmm/intel
CFLAGS+= -I${SRCTOP}/sys/amd64/vmm/amd

SRCS+=	opt_acpi.h		\
	opt_bhyve_snapshot.h	\
	opt_ddb.h

SRCS+=	vmm_host.c	\
	vmm_ioport.c	\
	vmm_lapic.c	\
	vmm_mem_machdep.c \
	vmm_util.c	\
	vmm_mtrr.c	\
	x86.c		\
	x86_cpuid.c

.PATH: ${SRCTOP}/sys/${MACHINE}/vmm/io
SRCS+=	iommu.c		\
	ppt.c           \
	vatpic.c	\
	vatpit.c	\
	vhpet.c		\
	vioapic.c	\
	vlapic.c	\
	vpmtmr.c	\
	vpvclock.c	\
	vrtc.c

# intel-specific files
.PATH: ${SRCTOP}/sys/amd64/vmm/intel
SRCS+=	ept.c		\
	vmcs.c		\
	vmx_nested_bitmap.c \
	vmx_nested_caps.c \
	vmx_nested_cold_ept.c \
	vmx_nested_cold_reflect.c \
	vmx_nested_compose.c \
	vmx_nested_continuation.c \
	vmx_nested_continuation_handoff.c \
	vmx_nested_control_msr.c \
	vmx_nested_control_capabilities.c \
	vmx_nested_control_capabilities_intel.c \
	vmx_nested_context.c \
	vmx_nested_checkpoint.c \
	vmx_nested_decode.c \
	vmx_nested_entry.c \
	vmx_nested_entry_event.c \
	vmx_nested_entry_environment.c \
	vmx_nested_entry_environment_intel.c \
	vmx_nested_entry_runtime.c \
	vmx_nested_ept.c \
	vmx_nested_ept_binding.c \
	vmx_nested_ept_cache.c \
	vmx_nested_ept_exit.c \
	vmx_nested_ept_fault.c \
	vmx_nested_ept_handoff.c \
	vmx_nested_ept_memory.c \
	vmx_nested_ept_reflect.c \
	vmx_nested_ept_runtime.c \
	vmx_nested_ept_root.c \
	vmx_nested_event.c \
	vmx_nested_exit_capture.c \
	vmx_nested_exit_flow.c \
	vmx_nested_execution.c \
	vmx_nested_exposure.c \
	vmx_nested_guest.c \
	vmx_nested_guest_memory_intel.c \
	vmx_nested_attempt.c \
	vmx_nested_owner_outcome.c \
	vmx_nested_hardware_entry.c \
	vmx_nested_hardware_result.c \
	vmx_nested_hot_ept.c \
	vmx_nested_hot_exit.c \
	vmx_nested_host.c \
	vmx_nested_refreeze.c \
	vmx_nested_invalidate.c \
	vmx_nested_instruction.c \
	vmx_nested_instruction_capture.c \
	vmx_nested_instruction_gate.c \
	vmx_nested_instruction_handoff.c \
	vmx_nested_instruction_publish.c \
	vmx_nested_instruction_runtime.c \
	vmx_nested_internal.c \
	vmx_nested_link.c \
	vmx_nested_l1_restore.c \
	vmx_nested_late_entry.c \
	vmx_nested_apic_priority.c \
	vmx_nested_l2_access.c \
	vmx_nested_l2_access_intel.c \
	vmx_nested_l2_freeze.c \
	vmx_nested_l2_portable.c \
	vmx_nested_l2_rebuild.c \
	vmx_nested_l2_continuation_state.c \
	vmx_nested_l2_state.c \
	vmx_nested_l2_thaw.c \
	vmx_nested_l2_thaw_staged.c \
	vmx_nested_msr.c \
	vmx_nested_msr_state.c \
	vmx_nested_msr_workspace.c \
	vmx_nested_mtf_owner.c \
	vmx_nested_pdpte.c \
	vmx_nested_reflect.c \
	vmx_nested_run.c \
	vmx_nested_resume_result.c \
	vmx_nested_restore_transaction.c \
	vmx_nested_state.c \
	vmx_nested_startup_policy.c \
	vmx_nested_startup_transaction.c \
	vmx_nested_startup_dispatch.c \
	vmx_nested_timer.c \
	vmx_nested_tsc.c \
	vmx_nested_tsc_aux.c \
	vmx_nested_validate.c \
	vmx_nested_vpid_owner.c \
	vmx_nested_vmcs.c \
	vmx_nested_vmcs_fields.c \
	vmx_nested_vmcs12.c \
	vmx_nested_vmcs02.c \
	vmx_nested_vmcs02_apply.c \
	vmx_nested_vmcs02_bind.c \
	vmx_nested_vmcs02_intel.c \
	vmx_nested_vmcs_launch.c \
	vmx_nested_vmcs02_lease.c \
	vmx_nested_vmcs02_lease_intel.c \
	vmx_nested_vmcs02_program.c \
	vmx_nested_vmcs02_resources_intel.c \
	vmx_nested_vmcs_registry.c \
	vmx_nested_vmcs_registry_state.c \
	vmx_nested_vmcs_store.c \
	vmx_nested_vmexit.c \
	vmx_nested_vmexit_handoff.c \
	vmx_nested_vmentry_handoff.c \
	vmx_nested_vmentry.c \
	vmx_msr.c	\
	vmx_support.S	\
	vmx.c		\
	vtd.c

# amd-specific files
.PATH: ${SRCTOP}/sys/amd64/vmm/amd
SRCS+=	vmcb.c		\
	amdviiommu.c	\
	ivhd_if.c	\
	ivhd_if.h	\
	svm.c		\
	svm_support.S	\
	npt.c		\
	ivrs_drv.c	\
	amdvi_hw.c	\
	svm_msr.c

SRCS.BHYVE_SNAPSHOT=	vmm_snapshot.c vmm_snapshot_envelope.c \
			vmm_snapshot_state.c vmm_snapshot_x86_state.c \
			vmm_snapshot_x86_transaction.c

CLEANFILES+=	vmx_assym.h vmx_genassym.o svm_assym.h svm_genassym.o

OBJS_DEPEND_GUESS.vmx_support.o+= vmx_assym.h
OBJS_DEPEND_GUESS.svm_support.o+= svm_assym.h

vmx_assym.h:    vmx_genassym.o
	sh ${SYSDIR}/kern/genassym.sh vmx_genassym.o > ${.TARGET}

svm_assym.h:    svm_genassym.o
	sh ${SYSDIR}/kern/genassym.sh svm_genassym.o > ${.TARGET}

vmx_support.o:
	${CC} -c -x assembler-with-cpp -DLOCORE ${CFLAGS} \
	    ${.IMPSRC} -o ${.TARGET}

svm_support.o:
	${CC} -c -x assembler-with-cpp -DLOCORE ${CFLAGS} \
	    ${.IMPSRC} -o ${.TARGET}

hyp_genassym.o: offset.inc
	${CC} -c ${NOSAN_CFLAGS:N-flto*:N-fno-common} -fcommon ${.IMPSRC}

vmx_genassym.o: offset.inc
	${CC} -c ${NOSAN_CFLAGS:N-flto*:N-fno-common} -fcommon ${.IMPSRC}

svm_genassym.o: offset.inc
	${CC} -c ${NOSAN_CFLAGS:N-flto*:N-fno-common} -fcommon ${.IMPSRC}

.elif ${MACHINE_CPUARCH} == "riscv"

SRCS+=	vmm_aplic.c	\
	vmm_fence.c	\
	vmm_riscv.c	\
	vmm_sbi.c	\
	vmm_switch.S	\
	vmm_vtimer.c

.endif

.include <bsd.kmod.mk>
