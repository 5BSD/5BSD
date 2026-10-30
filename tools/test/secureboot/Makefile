.PATH: ${SRCTOP}/lib/libchannel ${SRCTOP}/usr.sbin/BSDFilesystem \
    ${SRCTOP}/lib/libpam/modules/pam_unix
PROGS= firmware_init efi_database_test
SRCS.firmware_init= firmware_init.c
SRCS.efi_database_test= efi_database_test.c
CFLAGS+= -I${SRCTOP}/contrib/openpam/include -I${SRCTOP}/lib/libpam/modules/pam_unix -I${SRCTOP}/usr.sbin/BSDFilesystem -I${SRCTOP}/lib/libcapsulert \
    -I${SRCTOP}/contrib/libucl/include
MAN=
NO_SHARED= yes
CFLAGS+= -I${SRCTOP}/sys -I${SRCTOP}/lib/libchannel
CFLAGS.efi_database_test+= -I${SRCTOP}/stand/efi/include \
    -I${SRCTOP}/stand/efi/include/amd64 \
    -I${SRCTOP}/sys/contrib/edk2/Include \
    -I${SRCTOP}/lib/libsecureboot -I${SRCTOP}/lib/libsecureboot/h \
    -I${SRCTOP}/contrib/bearssl/inc
# Match the EFI-specific library objects used by the tested loader. build-bsd
# can select an isolated object tree; ordinary builds keep BIOS libraries separate.
SECUREBOOT_OBJTOP?= ${OBJTOP}
LDADD.efi_database_test+= ${SECUREBOOT_OBJTOP}/stand/efi/libsaefi/efi_variables.o \
    ${SECUREBOOT_OBJTOP}/stand/efi/libsaefi/x509_tbs.o
DPADD.efi_database_test+= ${LDADD.efi_database_test}
# Native EFI allocation regression; firmware VM gates remain separate.
PYTHON?= /usr/local/bin/python3.12
.PHONY: efi-staging-test evidence-test
efi-staging-test:
	${PYTHON} -B ${.CURDIR}/efi_staging_test.py

evidence-test:
	${PYTHON} -B ${.CURDIR}/verify_evidence_test.py





.include <bsd.progs.mk>

.PHONY: manager-handoff-test
manager-handoff-test:
	${PYTHON} -B ${.CURDIR}/manager_handoff_test.py




.PHONY: property-binding-test
property-binding-test:
	${PYTHON} -B ${.CURDIR}/property_binding_test.py





.PHONY: child-publication-test
child-publication-test:
	${PYTHON} -B ${.CURDIR}/child_publication_test.py

.PHONY: efi-trust-policy-test
efi-trust-policy-test:
	${PYTHON} -B ${.CURDIR}/efi_trust_policy_test.py

# Explicit fixture and probe inputs; these targets never launch a VM.
.PHONY: manifest-trust-prepare manifest-trust-crypto-test
manifest-trust-prepare:
	@test -n "${TRUST_WORK}" || { echo 'TRUST_WORK is required' >&2; exit 1; }
	${PYTHON} -B ${.CURDIR}/manifest_trust_crypto_test.py --prepare --work "${TRUST_WORK}"

manifest-trust-crypto-test:
	@test -n "${TRUST_WORK}" -a -n "${FIRMWARE_TRUST_PROBE}" -a -n "${COMPILED_TRUST_PROBE}" || { echo 'TRUST_WORK and both probe paths are required' >&2; exit 1; }
	${PYTHON} -B ${.CURDIR}/manifest_trust_crypto_test.py --work "${TRUST_WORK}" --firmware-probe "${FIRMWARE_TRUST_PROBE}" --compiled-probe "${COMPILED_TRUST_PROBE}"

.PHONY: runner-signing-test
runner-signing-test:
	${PYTHON} -B ${.CURDIR}/runner_signing_test.py


.PHONY: receive-revalidation-test
receive-revalidation-test:
	${PYTHON} -B ${.CURDIR}/receive_revalidation_test.py





.PHONY: be-destroy-cleanup-test
be-destroy-cleanup-test:
	${PYTHON} -B ${.CURDIR}/be_destroy_cleanup_test.py

.PHONY: verifier-read-test
verifier-read-test:
	${PYTHON} -B ${.CURDIR}/readfile_test.py

.PHONY: signature-path-test
signature-path-test:
	${PYTHON} -B ${.CURDIR}/signature_path_test.py

.PHONY: signature-decode-test
signature-decode-test:
	${PYTHON} -B ${.CURDIR}/signature_decode_test.py

.PHONY: be-activation-test
be-activation-test:
	${PYTHON} -B ${.CURDIR}/be_activation_test.py
	${PYTHON} -B ${.CURDIR}/be_promotion_test.py

.PHONY: be-clone-test
be-clone-test:
	${PYTHON} -B ${.CURDIR}/be_clone_test.py
	${PYTHON} -B ${.CURDIR}/be_clone_cleanup_test.py
	${PYTHON} -B ${.CURDIR}/be_clone_path_test.py
	${PYTHON} -B ${.CURDIR}/be_clone_property_test.py

.PHONY: be-altroot-test
be-altroot-test:
	${PYTHON} -B ${.CURDIR}/be_altroot_test.py

.PHONY: manifest-registration-test
manifest-registration-test:
	${PYTHON} -B ${.CURDIR}/manifest_registration_test.py

.PHONY: manifest-lookup-test
manifest-lookup-test:
	${PYTHON} -B ${.CURDIR}/manifest_lookup_test.py

.PHONY: hash-token-test
hash-token-test:
	${PYTHON} -B ${.CURDIR}/hash_token_test.py

.PHONY: stream-completion-test
stream-completion-test:
	${PYTHON} -B ${.CURDIR}/stream_completion_test.py

.PHONY: direct-verifier-io-test
direct-verifier-io-test:
	${PYTHON} -B ${.CURDIR}/direct_verifier_io_test.py

.PHONY: native-verifier-test
native-verifier-test:
.if empty(VERIFIER_TEST_PROG)
	@echo 'VERIFIER_TEST_PROG must name a built libsecureboot/tests/tvo binary' >&2
	@exit 1
.else
	${PYTHON} -B ${.CURDIR}/native_verifier_test.py --program "${VERIFIER_TEST_PROG}"
.endif

.PHONY: native-signed-verifier-test
native-signed-verifier-test:
.if empty(VERIFIER_TEST_PROG) || empty(VERIFIER_TEST_OPENSSL)
	@echo 'VERIFIER_TEST_PROG and VERIFIER_TEST_OPENSSL must name explicit test executables' >&2
	@exit 1
.else
	${PYTHON} -B ${.CURDIR}/native_signed_verifier_test.py --program "${VERIFIER_TEST_PROG}" --openssl "${VERIFIER_TEST_OPENSSL}"
.endif

.PHONY: raw-loader-cleanup-test
raw-loader-cleanup-test:
	${PYTHON} -B ${.CURDIR}/raw_loader_cleanup_test.py

# Required invariant; currently exposes unverified backward rereads.
# Keep failure visible until verified-byte replay is implemented.
.PHONY: verified-replay-test
VERIFIER_BEARSSL_LIBRARY?= ${OBJTOP}/lib/libbearssl/libbearssl.a
verified-replay-test:
	${PYTHON} -B ${.CURDIR}/verified_replay_test.py --bearssl-library ${VERIFIER_BEARSSL_LIBRARY}

.PHONY: verify-buffer-test
verify-buffer-test:
	${PYTHON} -B ${.CURDIR}/verify_buffer_test.py --bearssl-library ${VERIFIER_BEARSSL_LIBRARY}

.PHONY: root-descriptor-load-test
root-descriptor-load-test:
	${PYTHON} -B ${.CURDIR}/root_descriptor_load_test.py


.PHONY: client-collection-test
client-collection-test:
	${PYTHON} -B ${.CURDIR}/client_collection_test.py

.PHONY: isolation-snapshot-test
isolation-snapshot-test:
	${PYTHON} -B ${.CURDIR}/isolation_snapshot_test.py

.PHONY: preload-buffer-test
preload-buffer-test:
	${PYTHON} -B ${.CURDIR}/preload_buffer_test.py

.PHONY: loader-environment-test
loader-environment-test:
	${PYTHON} -B ${.CURDIR}/loader_environment_test.py

.PHONY: verity-commands-test
verity-commands-test:
	${PYTHON} -B ${.CURDIR}/verity_commands_test.py

.PHONY: loader-mount-test
loader-mount-test:
	${PYTHON} -B ${.CURDIR}/loader_mount_test.py

.PHONY: loader-compressed-source-test
ZSTD_TEST_LIBRARY?= /usr/local/lib/libzstd.so
ZSTD_TEST_INCLUDE?= /usr/local/include
loader-compressed-source-test:
	${PYTHON} -B ${.CURDIR}/loader_compressed_source_test.py --zstd-library ${ZSTD_TEST_LIBRARY:Q} --zstd-include ${ZSTD_TEST_INCLUDE:Q}

.PHONY: efi-config-buffer-test
efi-config-buffer-test:
	${PYTHON} -B ${.CURDIR}/efi_config_buffer_test.py

.PHONY: lua-file-read-test
lua-file-read-test:
	${PYTHON} -B ${.CURDIR}/lua_file_read_test.py

.PHONY: lua-stream-verify-test
lua-stream-verify-test:
	${PYTHON} -B ${.CURDIR}/lua_stream_verify_test.py --bearssl-library ${VERIFIER_BEARSSL_LIBRARY}

LUA_TEST_LIBRARY?= /usr/local/lib/liblua-5.4.so
LUA_TEST_INCLUDE?= /usr/local/include/lua54
LUA_TEST_INTERPRETER?= /usr/local/bin/lua54
.PHONY: lua-config-io-test
lua-config-io-test:
	${PYTHON} -B ${.CURDIR}/lua_io_read_test.py --lua-library ${LUA_TEST_LIBRARY} --lua-include ${LUA_TEST_INCLUDE}
	${LUA_TEST_INTERPRETER} ${.CURDIR}/lua_config_close_test.lua ${SRCTOP}/stand/lua/config.lua

.PHONY: verified-read-failure-test
verified-read-failure-test:
	${PYTHON} -B ${.CURDIR}/verified_read_failure_test.py --bearssl-library ${VERIFIER_BEARSSL_LIBRARY}

.PHONY: libsa-read-test
libsa-read-test:
	${PYTHON} -B ${.CURDIR}/libsa_read_test.py

.PHONY: libsa-seek-test
libsa-seek-test:
	${PYTHON} -B ${.CURDIR}/libsa_seek_test.py

.PHONY: root-descriptor-crypto-test
root-descriptor-crypto-test:
	@test -n "${TRUST_WORK}" -a -n "${COMPILED_TRUST_PROBE}" -a -n "${TRUST_OPENSSL}" || { echo "TRUST_WORK, COMPILED_TRUST_PROBE and TRUST_OPENSSL are required" >&2; exit 1; }
	${PYTHON} -B ${.CURDIR}/root_descriptor_crypto_test.py --work ${TRUST_WORK:Q} --compiled-probe ${COMPILED_TRUST_PROBE:Q} --openssl ${TRUST_OPENSSL:Q}

.PHONY: efi-chain-input-test
efi-chain-input-test:
	${PYTHON} -B ${.CURDIR}/efi_chain_input_test.py

.PHONY: multiboot-input-test
multiboot-input-test:
	${PYTHON} -B ${.CURDIR}/multiboot_input_test.py

.PHONY: multiboot-output-test
multiboot-output-test:
	${PYTHON} -B ${.CURDIR}/multiboot_output_test.py

.PHONY: loader-dispatch-test
loader-dispatch-test:
	${PYTHON} -B ${.CURDIR}/loader_dispatch_test.py

.PHONY: startup-contract-test
startup-contract-test:
	${PYTHON} -B ${.CURDIR}/startup_contract_test.py --lua ${LUA_TEST_INTERPRETER}

.PHONY: elf-source-verify-test
elf-source-verify-test:
	${PYTHON} -B ${.CURDIR}/elf_source_verify_test.py

.PHONY: be-path-test
be-path-test:
	${PYTHON} -B ${.CURDIR}/be_path_test.py

# Explicit scratch location; retained results are not a qualification receipt.
VECTX_COST_BYTES?= 33554432
VECTX_COST_ITERATIONS?= 5
VECTX_COST_REPLAYS?= 1024
.PHONY: vectx-cost
vectx-cost:
	@test -n "${VECTX_COST_WORK}" || { echo 'VECTX_COST_WORK must name an existing scratch directory' >&2; exit 1; }
	${PYTHON} -B ${.CURDIR}/vectx_cost.py --bearssl-library ${VERIFIER_BEARSSL_LIBRARY:Q} --work-dir ${VECTX_COST_WORK:Q} --size-bytes ${VECTX_COST_BYTES:Q} --iterations ${VECTX_COST_ITERATIONS:Q} --replay-reads ${VECTX_COST_REPLAYS:Q}

.PHONY: elf-verifier-cleanup-test
elf-verifier-cleanup-test:
	${PYTHON} -B ${.CURDIR}/elf_verifier_cleanup_test.py

.PHONY: readin-failure-test
readin-failure-test:
	${PYTHON} -B ${.CURDIR}/readin_failure_test.py

.PHONY: loader-trust-rotation-test
loader-trust-rotation-test:
	@test -n "${TRUST_WORK}" -a -n "${TRUST_MAKE}" -a -n "${TRUST_OPENSSL}" -a -n "${TRUST_JOBS}" || { echo 'TRUST_WORK, TRUST_MAKE, TRUST_OPENSSL and TRUST_JOBS are required' >&2; exit 1; }
	${PYTHON} -B ${.CURDIR}/loader_trust_rotation_test.py --work ${TRUST_WORK:Q} --make ${TRUST_MAKE:Q} --openssl ${TRUST_OPENSSL:Q} --jobs ${TRUST_JOBS:Q}

.PHONY: uefi-digest-test
uefi-digest-test:
	${PYTHON} -B ${.CURDIR}/uefi_digest_test.py

.PHONY: loader-manifest-verify-test
loader-manifest-verify-test:
	@test -n "${LOADER_MANIFEST_VERIFIER}" -a -n "${LOADER_MANIFEST_FIXTURES}" || (echo 'explicit verifier and fixture paths required'; exit 1)
	${PYTHON} -B ${.CURDIR}/loader_manifest_verify_test.py --verifier ${LOADER_MANIFEST_VERIFIER:Q} --fixtures ${LOADER_MANIFEST_FIXTURES:Q}

.PHONY: uefi-authenticode-test
uefi-authenticode-test:
	@test -n "${AUTHENTICODE_VERIFIER}" -a -n "${AUTHENTICODE_SIGNER}" -a -n "${AUTHENTICODE_LOADER}" -a -n "${AUTHENTICODE_OPENSSL}" -a -n "${AUTHENTICODE_WORK}" || { echo 'explicit verifier, signer, loader, openssl and fresh work paths required' >&2; exit 1; }
	${PYTHON} -B ${.CURDIR}/uefi_authenticode_test.py --verifier ${AUTHENTICODE_VERIFIER:Q} --signer ${AUTHENTICODE_SIGNER:Q} --loader ${AUTHENTICODE_LOADER:Q} --openssl ${AUTHENTICODE_OPENSSL:Q} --work ${AUTHENTICODE_WORK:Q}
