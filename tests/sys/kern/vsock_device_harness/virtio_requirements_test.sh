#!/usr/libexec/atf-sh

atf_test_case catalog
catalog_head()
{
	atf_set "descr" "Validate the VirtIO 1.4 requirements and test ledger"
}
catalog_body()
{
	atf_check -s exit:0 -o match:"entries validated" \
	    "$(atf_get_srcdir)/validate-virtio-requirements.sh" \
	    "$(atf_get_srcdir)/virtio-1.4-requirements.tsv" \
	    "$(atf_get_srcdir)"
}

atf_test_case bad_test_reference
bad_test_reference_head()
{
	atf_set "descr" "Reject a VirtIO ledger reference to a nonexistent test"
}
bad_test_reference_body()
{
	catalog="$(atf_get_srcdir)/virtio-1.4-requirements.tsv"
	broken="$(pwd)/broken-requirements.tsv"

	sed 's/virtio_modern_test:features_and_status/virtio_modern_test:no_such_test/' \
	    "$catalog" >"$broken"
	atf_check -s exit:1 -o match:"entries validated" \
	    -e match:"unknown test" \
	    "$(atf_get_srcdir)/validate-virtio-requirements.sh" \
	    "$broken" "$(atf_get_srcdir)"
}

atf_test_case bad_evidence_reference
bad_evidence_reference_head()
{
	atf_set "descr" "Reject unstructured VirtIO ledger evidence"
}
bad_evidence_reference_body()
{
	catalog="$(atf_get_srcdir)/virtio-1.4-requirements.tsv"
	broken="$(pwd)/broken-evidence.tsv"

	sed 's/build:bhyve-dtrace/build:bhyve-dtrcae/' \
	    "$catalog" >"$broken"
	atf_check -s exit:1 -o ignore \
	    -e match:"invalid positive evidence build:bhyve-dtrcae" \
	    "$(atf_get_srcdir)/validate-virtio-requirements.sh" \
	    "$broken" "$(atf_get_srcdir)"
}

atf_test_case self_confirming_endian_expectation
self_confirming_endian_expectation_head()
{
	atf_set "descr" "Reject an endian assertion decoded by the DUT helper"
}
self_confirming_endian_expectation_body()
{
	srcdir="$(atf_get_srcdir)"
	broken="$(pwd)/broken-tests"
	mutated="$(pwd)/virtio_guest_contract_test.mutated"

	mkdir "$broken"
	cp "$srcdir"/*.c "$srcdir"/*.h "$broken"
	if [ -r "$srcdir/virtio_requirements_test.sh" ]; then
		cp "$srcdir/virtio_requirements_test.sh" "$broken"
	else
		cp "$srcdir/virtio_requirements_test" \
		    "$broken/virtio_requirements_test.sh"
	fi
	sed '/virtio14_load_le32.*&low/s/virtio14_load_le32.*/virtio_gtoh32(low),/' \
	    "$srcdir/virtio_guest_contract_test.c" \
	    >"$mutated"
	mv -f "$mutated" "$broken/virtio_guest_contract_test.c"
	atf_check -s exit:1 -o ignore \
	    -e match:"guest endian expectation reuses a production conversion helper" \
	    "$srcdir/validate-virtio-requirements.sh" \
	    "$srcdir/virtio-1.4-requirements.tsv" "$broken"
}

atf_init_test_cases()
{
	atf_add_test_case catalog
	atf_add_test_case bad_test_reference
	atf_add_test_case bad_evidence_reference
	atf_add_test_case self_confirming_endian_expectation
}
