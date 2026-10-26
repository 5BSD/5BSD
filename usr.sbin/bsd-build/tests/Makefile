.include <src.opts.mk>
PACKAGE= bsd-build-tests
TESTSDIR= ${TESTSBASE}/usr.sbin/bsd-build
ATF_TESTS_SH= bsd_build_test
.PATH: ${SRCTOP}/tools/build/capimage
${PACKAGE}FILES+= deploy.py deploy_test.py installer.py installer_test.py be_vm_test.py
${PACKAGE}FILES+= package_closure.py package_closure_test.py
${PACKAGE}FILES+= package_inventory.py package_inventory_test.py
.include <bsd.test.mk>
