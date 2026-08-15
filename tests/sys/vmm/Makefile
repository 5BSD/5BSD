PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/vmm

BINDIR=		${TESTSDIR}

ATF_TESTS_SH+=	vmm_cred_jail
ATF_TESTS_C+=	vmm_event_ingress_test
ATF_TESTS_C+=	vmm_startup_event_test
ATF_TESTS_C+=	vmm_startup_mode_test
ATF_TESTS_C+=	vmm_startup_entry_owner_test
ATF_TESTS_C+=	vmm_startup_handshake_test
ATF_TESTS_C+=	vmm_startup_controller_test
ATF_TESTS_C+=	vmm_startup_request_test
ATF_TESTS_C+=	vmm_startup_run_request_test
ATF_TESTS_C+=	vmm_event_checkpoint_test
ATF_TESTS_C+=	vmm_event_wait_test
ATF_TESTS_C+=	vmm_dirty_log_test
ATF_TESTS_C+=	vmm_dirty_log_collector_test
ATF_TESTS_C+=	vmm_dirty_log_map_test
ATF_TESTS_C+=	vmm_dirty_log_owner_test
ATF_TESTS_C+=	vmm_dirty_log_request_test
ATF_TESTS_C+=	vmm_dirty_log_management_abi_test

.if ${MACHINE_CPUARCH} == "amd64"
ATF_TESTS_C+=	vmm_snapshot_op_test
ATF_TESTS_C+=	vmm_snapshot_session_abi_test
ATF_TESTS_C+=	vmm_snapshot_session_live_test
ATF_TESTS_C+=	vmm_snapshot_envelope_test
ATF_TESTS_C+=	vmm_snapshot_x86_fpu_test
ATF_TESTS_C+=	vmm_mtrr_test
ATF_TESTS_C+=	vpvclock_model_test
ATF_TESTS_C+=	vmm_event_state_test
ATF_TESTS_C+=	vmm_startup_management_abi_test
ATF_TESTS_C+=	vmm_startup_staging_live_test
ATF_TESTS_C+=	vmm_x86_startup_state_test
ATF_TESTS_C+=	vmm_x86_startup_transaction_test
ATF_TESTS_C+=	vmm_x86_startup_machine_test
ATF_TESTS_C+=	vmm_x86_startup_vmreg_test
ATF_TESTS_C+=	vmm_x86_startup_backend_test
ATF_TESTS_C+=	vmm_x86_startup_finalizer_test
ATF_TESTS_C+=	vmm_exception_test
ATF_TESTS_C+=	vmx_nested_state_test
TESTS_SUBDIRS+=	intr_snapshot_harness
.endif

CFLAGS.vmm_snapshot_envelope_test+=	-I${SRCTOP}/sys \
	-I${SRCTOP}/sys/amd64/vmm
CFLAGS.vmm_snapshot_x86_fpu_test+=	-I${SRCTOP}/sys \
	-I${SRCTOP}/sys/amd64/vmm
CFLAGS.vmm_mtrr_test+=	-I${SRCTOP}/sys \
	-I${SRCTOP}/sys/amd64/vmm
CFLAGS.vpvclock_model_test+=	-I${SRCTOP}/sys \
	-I${SRCTOP}/sys/amd64/vmm
CFLAGS.vmm_exception_test+=	-I${SRCTOP}/sys
CFLAGS.vmm_snapshot_session_abi_test+=	-I${SRCTOP}/sys \
	-I${SRCTOP}/sys/${MACHINE_CPUARCH}/include
CFLAGS.vmm_snapshot_session_live_test+=	-I${SRCTOP}/sys \
	-I${SRCTOP}/sys/${MACHINE_CPUARCH}/include \
	-I${SRCTOP}/lib/libvmmapi
LIBADD.vmm_snapshot_session_live_test+=	vmmapi
CFLAGS.vmm_event_checkpoint_test+=	-I${SRCTOP}/sys
CFLAGS.vmm_event_ingress_test+=	-I${SRCTOP}/sys
CFLAGS.vmm_startup_event_test+=	-I${SRCTOP}/sys
CFLAGS.vmm_startup_mode_test+=	-I${SRCTOP}/sys
CFLAGS.vmm_startup_entry_owner_test+=	-I${SRCTOP}/sys
CFLAGS.vmm_startup_handshake_test+=	-I${SRCTOP}/sys
CFLAGS.vmm_startup_controller_test+=	-I${SRCTOP}/sys
CFLAGS.vmm_startup_request_test+=	-I${SRCTOP}/sys
CFLAGS.vmm_startup_run_request_test+=	-I${SRCTOP}/sys
CFLAGS.vmm_startup_management_abi_test+=	-I${SRCTOP}/sys \
	-I${SRCTOP}/sys/${MACHINE_CPUARCH}/include
CFLAGS.vmm_startup_staging_live_test+=	-I${SRCTOP}/sys \
	-I${SRCTOP}/sys/${MACHINE_CPUARCH}/include \
	-I${SRCTOP}/lib/libvmmapi
LIBADD.vmm_startup_staging_live_test+=	vmmapi
CFLAGS.vmm_x86_startup_state_test+=	-I${SRCTOP}/sys \
	-I${SRCTOP}/sys/amd64/vmm
CFLAGS.vmm_x86_startup_transaction_test+=	-I${SRCTOP}/sys \
	-I${SRCTOP}/sys/amd64/vmm
CFLAGS.vmm_x86_startup_machine_test+=	-I${SRCTOP}/sys \
	-I${SRCTOP}/sys/amd64/vmm
CFLAGS.vmm_x86_startup_vmreg_test+=	-I${SRCTOP}/sys \
	-I${SRCTOP}/sys/${MACHINE_CPUARCH}/include \
	-I${SRCTOP}/sys/amd64/vmm
CFLAGS.vmm_x86_startup_backend_test+=	-I${SRCTOP}/sys \
	-I${SRCTOP}/sys/${MACHINE_CPUARCH}/include \
	-I${SRCTOP}/sys/amd64/vmm
CFLAGS.vmm_x86_startup_finalizer_test+=	-I${SRCTOP}/sys \
	-I${SRCTOP}/sys/${MACHINE_CPUARCH}/include \
	-I${SRCTOP}/sys/amd64/vmm
CFLAGS.vmm_event_wait_test+=	-I${SRCTOP}/sys
CFLAGS.vmm_dirty_log_test+=	-I${SRCTOP}/sys
CFLAGS.vmm_dirty_log_collector_test+=	-I${SRCTOP}/sys
CFLAGS.vmm_dirty_log_map_test+=	-I${SRCTOP}/sys
CFLAGS.vmm_dirty_log_owner_test+=	-I${SRCTOP}/sys
CFLAGS.vmm_dirty_log_request_test+=	-I${SRCTOP}/sys
CFLAGS.vmm_dirty_log_management_abi_test+=	-I${SRCTOP}/sys \
	-I${SRCTOP}/sys/${MACHINE_CPUARCH}/include

CFLAGS.vmx_nested_state_test+=	-I${SRCTOP}/sys \
	-I${SRCTOP}/sys/amd64/vmm/intel

${PACKAGE}FILES+=	utils.subr
${PACKAGE}FILES+=	validate-vmx-nested-requirements.sh
${PACKAGE}FILES+=	validate-vmx-nested-public-headers.sh
${PACKAGE}FILES+=	vmx-nested-requirements-selftest.sh
${PACKAGE}FILESMODE_validate-vmx-nested-requirements.sh=	0555
${PACKAGE}FILESMODE_validate-vmx-nested-public-headers.sh=	0555
${PACKAGE}FILESMODE_vmx-nested-requirements-selftest.sh=	0555
${PACKAGE}FILES+=	run-vmx-nested-live.sh
${PACKAGE}FILESMODE_run-vmx-nested-live.sh=	0555
${PACKAGE}FILES+=	validate-vmx-nested-live-evidence.sh
${PACKAGE}FILES+=	validate-vmx-nested-live-staging.sh
${PACKAGE}FILES+=	validate-vmx-nested-policy-pair.sh
${PACKAGE}FILES+=	validate-vmx-nested-live-coverage.sh
${PACKAGE}FILES+=	vmx-nested-live-evidence-selftest.sh
${PACKAGE}FILES+=	vmx-nested-live-staging-selftest.sh
${PACKAGE}FILES+=	vmx-nested-policy-pair-selftest.sh
${PACKAGE}FILES+=	vmx-nested-live-coverage-selftest.sh
${PACKAGE}FILESMODE_validate-vmx-nested-live-evidence.sh=	0555
${PACKAGE}FILESMODE_validate-vmx-nested-live-staging.sh=	0555
${PACKAGE}FILESMODE_validate-vmx-nested-policy-pair.sh=	0555
${PACKAGE}FILESMODE_validate-vmx-nested-live-coverage.sh=	0555
${PACKAGE}FILESMODE_vmx-nested-live-evidence-selftest.sh=	0555
${PACKAGE}FILESMODE_vmx-nested-live-staging-selftest.sh=	0555
${PACKAGE}FILESMODE_vmx-nested-policy-pair-selftest.sh=	0555
${PACKAGE}FILESMODE_vmx-nested-live-coverage-selftest.sh=	0555
${PACKAGE}FILES+=	run-vmx-nested-model.sh
${PACKAGE}FILESMODE_run-vmx-nested-model.sh=	0555
${PACKAGE}FILES+=	VMX_NESTED_FULL_REVIEW_PROMPT.md
${PACKAGE}FILES+=	vmx-nested-requirements.tsv
${PACKAGE}FILES+=	vmx-nested-live-qualification.tsv
${PACKAGE}FILES+=	vmx-nested-default-policy-live-qualification.tsv
${PACKAGE}FILES+=	vmx-nested-nonstandard-interfaces.tsv
${PACKAGE}FILES+=	vmm-event-ingress-callers.tsv

# Shell tests and the nested-VMX validators resolve their companion artifacts
# through atf_get_srcdir().  Materialize the installed-file set in a separate
# object directory as well, so an object-tree Kyua run exercises the same
# layout as the packaged suite instead of silently depending on /usr/src.
VMM_OBJECT_FILES=	utils.subr \
			validate-vmx-nested-requirements.sh \
			validate-vmx-nested-public-headers.sh \
			vmx-nested-requirements-selftest.sh \
			run-vmx-nested-live.sh \
			validate-vmx-nested-live-evidence.sh \
			validate-vmx-nested-live-staging.sh \
			validate-vmx-nested-policy-pair.sh \
			validate-vmx-nested-live-coverage.sh \
			vmx-nested-live-evidence-selftest.sh \
			vmx-nested-live-staging-selftest.sh \
			vmx-nested-policy-pair-selftest.sh \
			vmx-nested-live-coverage-selftest.sh \
			run-vmx-nested-model.sh \
			VMX_NESTED_FULL_REVIEW_PROMPT.md \
			vmx-nested-requirements.tsv \
			vmx-nested-live-qualification.tsv \
			vmx-nested-default-policy-live-qualification.tsv \
			vmx-nested-nonstandard-interfaces.tsv \
			vmm-event-ingress-callers.tsv

.if ${.OBJDIR} != ${.CURDIR}
CLEANFILES+=	${VMM_OBJECT_FILES}
beforedepend:	${VMM_OBJECT_FILES}
.for _vmm_object_file in ${VMM_OBJECT_FILES}
${_vmm_object_file}: ${.CURDIR}/${_vmm_object_file}
	cp ${.ALLSRC} ${.TARGET}.tmp.${.MAKE.PID}
	mv -f ${.TARGET}.tmp.${.MAKE.PID} ${.TARGET}
.endfor
.endif

.include <bsd.test.mk>
