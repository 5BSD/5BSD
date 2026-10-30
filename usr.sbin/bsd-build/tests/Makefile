.include <src.opts.mk>
PACKAGE= bsd-build-tests
TESTSDIR= ${TESTSBASE}/usr.sbin/bsd-build
ATF_TESTS_SH= bsd_build_test
.PATH: ${SRCTOP}/tools/build/capimage
${PACKAGE}FILES+= deploy.py deploy_test.py installer.py installer_test.py be_vm_test.py
${PACKAGE}FILES+= package_closure_test.py
${PACKAGE}FILES+= package_inventory.py package_inventory_test.py package_closure.py
${PACKAGE}FILES+= inventory_audit.py ${SRCTOP}/tools/test/construction/inventory_audit_test.py
${PACKAGE}FILES+= loader_build_test.py loader_build.py loader_production_test.py
${PACKAGE}FILES+= elf_dependencies.py elf_dependencies_test.py elf_features_build_test.py
${PACKAGE}FILES+= sign-stage.sh signing_custody_test.py
${PACKAGE}FILES+= generation_boot.py generation_boot_test.py
${PACKAGE}FILES+= seed_initialize.py seed_dataset.py state_storage.py state_storage_test.py
${PACKAGE}FILES+= generation_image.py generation_image_test.py generation_check.py generation_check_test.py
${PACKAGE}FILES+= database_preflight.py database_preflight_test.py
${PACKAGE}FILES+= database_payload.py database_payload_test.py payload_extract.py payload_extract_test.py database_construction.py
${PACKAGE}FILES+= construction.py construction_test.py certificate_policy.py certificate_policy_test.py module_policy.py module_policy_test.py library_policy.py library_policy_test.py installation_policy.py installation_policy_test.py
${PACKAGE}FILES+= configuration_compose.py configuration_compose_test.py ucl_policy_json_test.py
${PACKAGE}FILES+= ${SRCTOP}/usr.sbin/capsule/tests/capsule_config_cli_test.sh
.include <bsd.test.mk>
