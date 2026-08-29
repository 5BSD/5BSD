#!/usr/libexec/atf-sh

atf_test_case manifest cleanup
manifest_head()
{
	atf_set "descr" \
	    "Blued is a verified IPC-activated bundle with descriptor storage"
}
manifest_body()
{
	srcdir="@SRCTOP@/usr.sbin/bluetooth/blued"
	objdir="@OBJTOP@/usr.sbin/bluetooth/blued"
	servicectl="${SERVICECTL:-@OBJTOP@/usr.sbin/servicectl/tests/servicectl_test_bin}"
	bundle="${PWD}/Bluetooth.cap"
	unit="${bundle}/Units/blued.unit"

	test -x "${servicectl}" ||
	    atf_skip "source-built servicectl is required"
	test -x "${objdir}/blued" || atf_skip "source-built blued is required"
	mkdir -p "${unit}/bin" "${unit}/Config"
	cp "${srcdir}/capbundle/Bundle.ucl" "${bundle}/Bundle.ucl"
	cp "${srcdir}/blued.ucl" "${unit}/Unit.ucl"
	cp "${srcdir}/blued.conf.sample" "${unit}/Config/blued.conf"
	cp "${objdir}/blued" "${unit}/bin/Bluetooth"
	chmod 0555 "${bundle}" "${bundle}/Units" "${unit}" "${unit}/bin" \
	    "${unit}/Config" "${unit}/bin/Bluetooth"
	chmod 0444 "${bundle}/Bundle.ucl" "${unit}/Unit.ucl" \
	    "${unit}/Config/blued.conf"

	atf_check -s exit:0 -o match:'Verification: PASSED' \
	    "${servicectl}" verify "${bundle}"
	atf_check -s exit:0 -o match:'system.Bluetooth' \
	    grep 'activation.*ipc.*system.Bluetooth' "${unit}/Unit.ucl"
	atf_check -s exit:0 -o match:'storage: state.*lifetime=persistent' \
	    "${servicectl}" verify "${bundle}"

	chmod 0644 "${unit}/Unit.ucl"
	printf '%s\n' 'provides = ["org.5bsd.legacy"];' >> "${unit}/Unit.ucl"
	atf_check -s not-exit:0 -o ignore -e match:'unknown key.*provides' \
	    "${servicectl}" verify "${bundle}"
}
manifest_cleanup()
{
	chmod -R u+w "${PWD}/Bluetooth.cap" 2>/dev/null || true
	rm -rf "${PWD}/Bluetooth.cap"
}

atf_test_case package_layout
package_layout_head()
{
	atf_set "descr" "pkgbase installs every Blued artifact inside Bluetooth.cap"
}
package_layout_body()
{
	makefile="@SRCTOP@/usr.sbin/bluetooth/blued/Makefile"

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
