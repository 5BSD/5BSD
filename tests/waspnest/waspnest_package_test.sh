#!/usr/bin/env atf-sh

waspnest_runner()
{
	src=$(atf_get_srcdir)
	if [ -f "$src/waspnest-test.sh" ]; then
		printf '%s\n' "$src/waspnest-test.sh"
	else
		printf '%s\n' "$src/waspnest-test"
	fi
}

nonvirtio_validator()
{
	src=$(atf_get_srcdir)
	if [ -f "$src/validate-nonvirtio-coverage.sh" ]; then
		printf '%s\n' "$src/validate-nonvirtio-coverage.sh"
	else
		printf '%s\n' "$src/validate-nonvirtio-coverage"
	fi
}

atf_test_case inventory
inventory_head()
{
	atf_set descr "WASPNest gate inventory is unique and complete"
}
inventory_body()
{
	src=$(atf_get_srcdir)
	awk -F '\t' '
	BEGIN {
		expected = "gate\tlayer\tguests\troot\tentrypoint\tacceptance"
	}
	NR == 1 { if ($0 != expected) exit 10; next }
	NF != 6 || seen[$1]++ || ($4 != "yes" && $4 != "no") { exit 11 }
	{ present[$1] = 1; rows++ }
	END {
		split("package-selftest post-reboot audit host-model vmm-kernel linux-live fivebsd-live nonvirtio-live checkpoint nested-vmx soak", required, " ")
		for (i in required) if (!present[required[i]]) exit 12
		if (rows != 11) exit 13
	}' "$src/waspnest-suite.tsv" || atf_fail "invalid suite inventory"
}

atf_test_case list
list_head()
{
	atf_set descr "aggregate runner lists every release gate"
}

atf_test_case nonvirtio_inventory
nonvirtio_inventory_head()
{
	atf_set descr "non-VirtIO production devices have explicit live and restore dispositions"
}
nonvirtio_inventory_body()
{
	src=$(atf_get_srcdir)
	awk -F '\t' '
	BEGIN {
		header = "device\tsource\thost_evidence\tlinux_status\tlinux_case\tfivebsd_status\tfivebsd_case\tcheckpoint_status\tcheckpoint_case\tnotes"
		split("exercised pending driver-gap not-applicable environment-dependent", values, " ")
		for (i in values) allowed[values[i]] = 1
	}
	NR == 1 { if ($0 != header) exit 10; next }
	NF != 10 || seen[$1]++ || !allowed[$4] || !allowed[$6] || !allowed[$8] { exit 11 }
	($4 == "exercised" && $5 == "-") || ($6 == "exercised" && $7 == "-") ||
	    ($8 == "exercised" && $9 == "-") { exit 14 }
	{ present[$1] = 1; rows++ }
	END {
		split("ahci nvme e82545 hda xhci fbuf pci-uart lpc-uart tpm-crb pvpanic hostbridge passthru", required, " ")
		for (i in required) if (!present[required[i]]) exit 12
		if (rows != 12) exit 13
	}' "$src/waspnest-nonvirtio-coverage.tsv" ||
	    atf_fail "invalid non-VirtIO coverage inventory"
}
list_body()
{
	src=$(atf_get_srcdir)
	runner=$(waspnest_runner)
	atf_check -s exit:0 -o save:list.out -e empty \
	    sh "$runner" list
	for gate in post-reboot host-model vmm-kernel linux-live fivebsd-live \
	    nonvirtio-live checkpoint nested-vmx soak; do
		grep -q "^$gate" list.out || atf_fail "missing list gate $gate"
	done
}

atf_test_case status
status_head()
{
	atf_set descr "status is derived from installed activation ledgers"
}

atf_test_case validator_falsification
validator_falsification_head()
{
	atf_set descr "non-VirtIO validator rejects weak claims and new unclassified devices"
}
validator_falsification_body()
{
	src=$(atf_get_srcdir)
	validator=$(nonvirtio_validator)
	mkdir -p tree/usr.sbin/bhyve tree/tests/sys/kern/vsock_device_harness \
	    tree/tests/sys/kern/vsock_e2e
	: >tree/tests/sys/kern/vsock_device_harness/Makefile
	printf '%s\n' 'cases:' >tree/tests/sys/kern/vsock_e2e/virtio-lab.yaml
	for column in 5 7 9; do
		awk -F '\t' -v column="$column" 'NR > 1 && $column != "-" {
		    n = split($column, cases, ",")
		    for (i = 1; i <= n; i++) if (!seen[cases[i]]++) print cases[i]
		}' "$src/waspnest-nonvirtio-coverage.tsv"
	done | sort -u | while IFS= read -r case_id; do
		printf '  - id: %s\n' "$case_id"
	done >>tree/tests/sys/kern/vsock_e2e/virtio-lab.yaml
	awk -F '\t' 'NR > 1 { print $2 }' "$src/waspnest-nonvirtio-coverage.tsv" |
	while IFS= read -r source; do
		case "$source" in
		*/*) mkdir -p "tree/usr.sbin/bhyve/${source%/*}" ;;
		esac
		case "$source" in
		pci_*.c) printf '%s\n' 'PCI_EMUL_SET(synthetic);' ;;
		*) printf '%s\n' '/* synthetic source */' ;;
		esac >"tree/usr.sbin/bhyve/$source"
	done
	awk -F '\t' 'NR > 1 && $3 != "-" {
	    n = split($3, tests, ",")
	    for (i = 1; i <= n; i++) if (!seen[tests[i]]++) print tests[i]
	}' "$src/waspnest-nonvirtio-coverage.tsv" |
	while IFS= read -r test_program; do
		printf 'ATF_TESTS_C+=\t%s\n' "$test_program"
	done >>tree/tests/sys/kern/vsock_device_harness/Makefile
	cp "$src/waspnest-nonvirtio-coverage.tsv" good.tsv
	atf_check -s exit:0 -o match:'PASS non-VirtIO coverage inventory' \
	    -e empty env SRCTOP="$PWD/tree" sh "$validator" "$PWD/good.tsv"
	awk -F '\t' 'BEGIN { OFS = "\t" }
	    NR == 2 { $4 = "exercised"; $5 = "-" }
	    { print }
	' good.tsv >weak.tsv
	atf_check -s exit:1 -o empty -e match:'malformed.*row' env \
	    SRCTOP="$PWD/tree" sh "$validator" "$PWD/weak.tsv"
	printf '%s\n' 'PCI_EMUL_SET(unclassified);' \
	    >tree/usr.sbin/bhyve/pci_new_device.c
	atf_check -s exit:1 -o empty -e match:'unclassified.*pci_new_device.c' env \
	    SRCTOP="$PWD/tree" sh "$validator" "$PWD/good.tsv"
}
status_body()
{
	src=$(atf_get_srcdir)
	runner=$(waspnest_runner)
	mkdir -p root/sys/kern/vsock_device_harness root/sys/kern/vsock_e2e \
	    root/sys/vmm
	cp "$src/waspnest-suite.tsv" root/waspnest-suite.tsv
	cp "$src/waspnest-nonvirtio-coverage.tsv" \
	    root/waspnest-nonvirtio-coverage.tsv
	printf 'id\tfeature\tlinux\tlinux_case\tfivebsd\tfivebsd_case\n' \
	    >root/sys/kern/vsock_device_harness/virtio-feature-activation.tsv
	printf 'A\tx\texercised\tl\tpending\tf\n' \
	    >>root/sys/kern/vsock_device_harness/virtio-feature-activation.tsv
	printf 'B\ty\tdriver-gap\t-\tnot-applicable\t-\n' \
	    >>root/sys/kern/vsock_device_harness/virtio-feature-activation.tsv
	: >root/sys/kern/vsock_device_harness/virtio-1.4-requirements.tsv
	: >root/sys/kern/vsock_device_harness/virtio-nonstandard-interfaces.tsv
	printf 'id\tscope\tlinux\tlinux_case\tfivebsd\tfivebsd_case\n' \
	    >root/sys/vmm/vmx-nested-live-qualification.tsv
	printf 'N\tx\tpending\tl\tpending\tf\n' \
	    >>root/sys/vmm/vmx-nested-live-qualification.tsv
	: >root/sys/vmm/vmx-nested-requirements.tsv
	printf 'id\tscope\tlinux\tlinux_case\tfivebsd\tfivebsd_case\n' \
	    >root/sys/vmm/vmx-nested-default-policy-live-qualification.tsv
	printf 'D\tx\tpending\tl\tpending\tf\n' \
	    >>root/sys/vmm/vmx-nested-default-policy-live-qualification.tsv
	: >root/sys/kern/vsock_e2e/run-waspnest-qualification.sh
	chmod +x root/sys/kern/vsock_e2e/run-waspnest-qualification.sh
	# The runner's manifest lives beside it, while TESTROOT points at the
	# synthetic installed hierarchy.
	atf_check -s exit:0 -o save:status.out -e empty env \
	    WASPNEST_TESTROOT="$PWD/root" sh "$runner" status
	grep -q 'Linux exercised.*1' status.out || atf_fail "missing Linux count"
	grep -q '5BSD  pending.*1' status.out || atf_fail "missing 5BSD count"
	grep -q 'Nested live groups: 1' status.out || atf_fail "missing nested count"
	grep -q 'Nested default-policy groups: 1' status.out ||
	    atf_fail "missing nested default-policy count"
	atf_check -s exit:1 -o match:'VirtIO activation rows: 2' \
	    -e match:'release coverage unresolved' env \
	    WASPNEST_TESTROOT="$PWD/root" sh "$runner" release-ready
	cp root/sys/kern/vsock_device_harness/virtio-feature-activation.tsv \
	    activation.saved
	awk -F '\t' 'BEGIN { OFS = "\t" } NR == 2 { $3 = "typo-pass" } { print }' \
	    activation.saved \
	    >root/sys/kern/vsock_device_harness/virtio-feature-activation.tsv
	atf_check -s exit:1 -o empty -e match:'unknown disposition' env \
	    WASPNEST_TESTROOT="$PWD/root" sh "$runner" release-ready
	cp activation.saved \
	    root/sys/kern/vsock_device_harness/virtio-feature-activation.tsv
	cp root/sys/vmm/vmx-nested-default-policy-live-qualification.tsv \
	    default-policy.saved
	awk -F '\t' 'BEGIN { OFS = "\t" } NR == 2 { $3 = "typo-pass" } { print }' \
	    default-policy.saved \
	    >root/sys/vmm/vmx-nested-default-policy-live-qualification.tsv
	atf_check -s exit:1 -o empty \
	    -e match:'nested default-policy ledger contains an unknown disposition' \
	    env WASPNEST_TESTROOT="$PWD/root" sh "$runner" release-ready
}

atf_init_test_cases()
{
	atf_add_test_case inventory
	atf_add_test_case list
	atf_add_test_case nonvirtio_inventory
	atf_add_test_case status
	atf_add_test_case validator_falsification
}
