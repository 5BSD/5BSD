#!/usr/libexec/atf-sh

atf_test_case manifest cleanup
manifest_head()
{
	atf_set "descr" \
	    "BSDBluetooth is a verified IPC-activated bundle"
}
manifest_body()
{
	installed="/Capabilities/System/Bluetooth.cap"
	installed_unit="${installed}/Units/blued.unit"
	installed_controller="${installed}/Units/controller.unit"
	switchboardctl="${SWITCHBOARDCTL:-$(atf_get_srcdir)/../../switchboardctl/switchboardctl_test_bin}"
	bundle="${PWD}/Bluetooth.cap"
	unit="${bundle}/Units/blued.unit"

	test -x "${switchboardctl}" ||
	    atf_skip "source-built switchboardctl is required"
	test -x "${installed_unit}/bin/BSDBluetooth" ||
	    atf_skip "installed Bluetooth.cap bundle is required"
	mkdir -p "${unit}/bin" "${unit}/Config"
	cp "${installed}/Bundle.ucl" "${bundle}/Bundle.ucl"
	cp "${installed_unit}/Unit.ucl" "${unit}/Unit.ucl"
	cp "${installed_unit}/Config/blued.conf" "${unit}/Config/blued.conf"
	cp "${installed_unit}/bin/BSDBluetooth" "${unit}/bin/BSDBluetooth"
	controller="${bundle}/Units/controller.unit"
	mkdir -p "${controller}/bin"
	cp "${installed_controller}/Unit.ucl" "${controller}/Unit.ucl"
	cp "${installed_controller}/bin/BSDBluetoothController" \
	    "${controller}/bin/BSDBluetoothController"
	chmod 0555 "${controller}" "${controller}/bin" \
	    "${controller}/bin/BSDBluetoothController"
	chmod 0444 "${controller}/Unit.ucl"
	chmod 0555 "${bundle}" "${bundle}/Units" "${unit}" "${unit}/bin" \
	    "${unit}/Config" "${unit}/bin/BSDBluetooth"
	chmod 0444 "${bundle}/Bundle.ucl" "${unit}/Unit.ucl" \
	    "${unit}/Config/blued.conf"

	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${switchboardctl}" verify "${bundle}"
	atf_check -s exit:0 -o match:'system.Bluetooth' \
	    grep 'activation.*ipc.*system.Bluetooth' "${unit}/Unit.ucl"
	# BSDBluetooth keeps its bond/settings state through its own persist layer,
	# not a manifest storage declaration: fea4a875dd7 removed the dead
	# capabilities.storage block from the unit manifests.
	atf_check -s exit:0 -o not-match:'storage:' \
	    "${switchboardctl}" verify "${bundle}"

	chmod 0644 "${unit}/Unit.ucl"
	printf '%s\n' 'provides = ["org.5bsd.legacy"];' >> "${unit}/Unit.ucl"
	atf_check -s not-exit:0 -o ignore -e match:'unknown key.*provides' \
	    "${switchboardctl}" verify "${bundle}"
}
manifest_cleanup()
{
	chmod -R u+w "${PWD}/Bluetooth.cap" 2>/dev/null || true
	rm -rf "${PWD}/Bluetooth.cap"
}

atf_test_case package_layout
package_layout_head()
{
	atf_set "descr" \
	    "pkgbase installs every BSDBluetooth artifact inside Bluetooth.cap"
}
package_layout_body()
{
	# The test package stages the daemon Makefile beneath srctree/.
	srctree="$(atf_get_srcdir)/srctree"
	makefile="${srctree}/usr.sbin/bluetooth/BSDBluetooth/Makefile"
	test -r "${makefile}" ||
	    atf_skip "staged source file (${makefile}) required"

	for token in '/Capabilities/System/Bluetooth.cap' \
	    'BLUED_CAP_UNIT=.*blued.unit' 'CAP_BUNDLE' 'CAP_UNIT' 'CAP_CONFIG'; do
		atf_check -s exit:0 -o ignore grep "${token}" "${makefile}"
	done
	atf_check -s exit:1 -o empty -e empty \
	    grep -E '(^|[[:space:]])(/etc|/var/db/blued)(/|[[:space:]]|$$)' \
	    "${makefile}"
}

atf_init_test_cases()
{
	atf_add_test_case manifest
	atf_add_test_case package_layout
}
