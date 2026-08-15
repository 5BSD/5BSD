#!/usr/libexec/atf-sh

atf_test_case catalog
catalog_head()
{
	atf_set "descr" "Validate the VirtIO 1.4 requirements and test ledger"
}

atf_test_case source_tree_required
source_tree_required_head()
{
	atf_set "descr" "Reject requirements audits without a matching source tree"
}
source_tree_required_body()
{
	srcdir="$(atf_get_srcdir)"
	atf_check -s exit:1 -o ignore \
	    -e match:"requires a source tree matching the installed test suite" \
	    "$srcdir/validate-virtio-requirements.sh" \
	    "$srcdir/virtio-1.4-requirements.tsv" "$srcdir" \
	    "$(pwd)/not-a-source-tree"
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

atf_test_case reference_corpus
reference_corpus_head()
{
	atf_set "descr" "Validate immutable VirtIO, Intel, Linux, and QEMU references"
}
reference_corpus_body()
{
	atf_check -s exit:0 -o match:"entries validated" \
	    "$(atf_get_srcdir)/validate-virtio-reference-corpus.sh" \
	    "$(atf_get_srcdir)/virtio-reference-corpus.tsv" --waspnest
}

atf_test_case missing_waspnest_reference
missing_waspnest_reference_head()
{
	atf_set "descr" "Require the complete pinned WASPNest reference corpus"
}
missing_waspnest_reference_body()
{
	catalog="$(atf_get_srcdir)/virtio-reference-corpus.tsv"
	broken="$(pwd)/missing-waspnest-reference.tsv"

	awk -F '\t' '$1 != "QEMU-300438"' "$catalog" >"$broken"
	atf_check -s exit:1 -o ignore \
	    -e match:"missing a required pinned reference or classification" \
	    "$(atf_get_srcdir)/validate-virtio-reference-corpus.sh" \
	    "$broken" --waspnest
}

atf_test_case bad_reference_digest
bad_reference_digest_head()
{
	atf_set "descr" "Reject an unpinned reference corpus digest"
}
bad_reference_digest_body()
{
	catalog="$(atf_get_srcdir)/virtio-reference-corpus.tsv"
	broken="$(pwd)/broken-reference-corpus.tsv"

	sed '2s/[0-9a-f][0-9a-f]*	2;/not-a-digest	2;/' "$catalog" >"$broken"
	atf_check -s exit:1 -o ignore -e match:"invalid SHA-256" \
	    "$(atf_get_srcdir)/validate-virtio-reference-corpus.sh" "$broken"
}

atf_test_case reference_artifacts_are_complete
reference_artifacts_are_complete_head()
{
	atf_set "descr" "Require exactly one authenticated artifact for every pinned reference"
}
reference_artifacts_are_complete_body()
{
	validator="$(atf_get_srcdir)/validate-virtio-reference-corpus.sh"
	work=$(mktemp -d "$(pwd)/reference-artifacts.XXXXXX")
	trap 'rm -rf "$work"' EXIT HUP INT TERM
	catalog="$work/references.tsv"
	artifacts="$work/artifacts"
	mkdir "$artifacts"
	printf 'alpha-reference\n' > "$artifacts/alpha.pdf"
	printf 'beta-reference\n' > "$artifacts/beta.tar.gz"
	alpha=$(sha256 -q "$artifacts/alpha.pdf")
	beta=$(sha256 -q "$artifacts/beta.tar.gz")
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
	    reference_id authority title revision publication_date url sha256 \
	    applicable_sections classification \
	    ALPHA Example Alpha 1 2026-01-01 \
	    https://example.invalid/alpha.pdf "$alpha" all normative \
	    BETA Example Beta 1 2026-01-01 \
	    https://example.invalid/beta.tar.gz "$beta" all explanatory \
	    > "$catalog"
	atf_check -s exit:0 -o match:'entries validated' \
	    "$validator" "$catalog" "$artifacts"
	rm "$artifacts/beta.tar.gz"
	atf_check -s exit:1 -o ignore -e match:'missing reference artifact: BETA' \
	    "$validator" "$catalog" "$artifacts"
	printf 'beta-reference\n' > "$artifacts/beta.tar.gz"
	cp "$artifacts/beta.tar.gz" "$artifacts/beta-copy.tar.gz"
	atf_check -s exit:1 -o ignore -e match:'duplicate reference artifact: BETA' \
	    "$validator" "$catalog" "$artifacts"
}

atf_test_case reference_artifacts_reject_nonregular_entries
reference_artifacts_reject_nonregular_entries_head()
{
	atf_set "descr" "Reject extra directories and symbolic links in a reference corpus"
}

atf_test_case reference_artifacts_reject_hash_failure
reference_artifacts_reject_hash_failure_head()
{
	atf_set "descr" "Reject a corpus when digest production fails"
}
reference_artifacts_reject_hash_failure_body()
{
	validator="$(atf_get_srcdir)/validate-virtio-reference-corpus.sh"
	work=$(mktemp -d "$(pwd)/reference-artifacts.XXXXXX")
	trap 'rm -rf "$work"' EXIT HUP INT TERM
	catalog="$work/references.tsv"
	artifacts="$work/artifacts"
	shim="$work/shim"
	mkdir "$artifacts" "$shim"
	printf 'alpha-reference\n' > "$artifacts/alpha.pdf"
	alpha=$(sha256 -q "$artifacts/alpha.pdf")
	printf 'reference_id\tauthority\ttitle\trevision\tpublication_date\turl\tsha256\tapplicable_sections\tclassification\n' > "$catalog"
	printf 'ALPHA\tunit\tAlpha\tr1\t2026-01-01\thttps://example.invalid/alpha\t%s\tsection\texplanatory\n' "$alpha" >> "$catalog"
	printf '#!/bin/sh\nexit 1\n' > "$shim/sha256"
	chmod 555 "$shim/sha256"
	atf_check -s exit:1 -o ignore -e match:'cannot hash reference artifact' \
	    env PATH="$shim:$PATH" "$validator" "$catalog" "$artifacts"
}
reference_artifacts_reject_nonregular_entries_body()
{
	validator="$(atf_get_srcdir)/validate-virtio-reference-corpus.sh"
	work=$(mktemp -d "$(pwd)/reference-artifacts.XXXXXX")
	trap 'rm -rf "$work"' EXIT HUP INT TERM
	catalog="$work/references.tsv"
	artifacts="$work/artifacts"
	mkdir "$artifacts"
	printf 'alpha-reference\n' > "$artifacts/alpha.pdf"
	alpha=$(sha256 -q "$artifacts/alpha.pdf")
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
	    reference_id authority title revision publication_date url sha256 \
	    applicable_sections classification \
	    ALPHA Example Alpha 1 2026-01-01 \
	    https://example.invalid/alpha.pdf "$alpha" all normative \
	    > "$catalog"
	mkdir "$artifacts/extra-directory"
	atf_check -s exit:1 -o ignore \
	    -e match:'reference artifact is not a regular non-symbolic file' \
	    "$validator" "$catalog" "$artifacts"
	rmdir "$artifacts/extra-directory"
	ln -s alpha.pdf "$artifacts/extra-link"
	atf_check -s exit:1 -o ignore \
	    -e match:'reference artifact is not a regular non-symbolic file' \
	    "$validator" "$catalog" "$artifacts"
}

atf_test_case unstable_virtio_html_reference
unstable_virtio_html_reference_head()
{
	atf_set "descr" "Reject the request-randomized OASIS HTML as the pinned artifact"
}
unstable_virtio_html_reference_body()
{
	catalog="$(atf_get_srcdir)/virtio-reference-corpus.tsv"
	broken="$(pwd)/unstable-reference-corpus.tsv"

	sed '2s/virtio-v1.4-cs01.pdf/virtio-v1.4-cs01.html/' \
	    "$catalog" >"$broken"
	atf_check -s exit:1 -o ignore \
	    -e match:"must pin the reproducible official PDF" \
	    "$(atf_get_srcdir)/validate-virtio-reference-corpus.sh" "$broken"
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

atf_test_case activation_requires_host_evidence
activation_requires_host_evidence_head()
{
	atf_set "descr" "Reject an exercised live feature without host-path evidence"
}
activation_requires_host_evidence_body()
{
	srcdir="$(atf_get_srcdir)"
	catalog="$srcdir/virtio-feature-activation.tsv"
	broken="$(pwd)/broken-activation.tsv"

	awk -F '\t' 'BEGIN { OFS = "\t" }
	    $1 == "NET-MULTIQUEUE" { $7 = "-" }
	    { print }' "$catalog" >"$broken"
	atf_check -s exit:1 -o match:"entries validated" \
	    -e match:"NET-MULTIQUEUE lacks host-path evidence" \
	    "$srcdir/validate-virtio-requirements.sh" \
	    "$srcdir/virtio-1.4-requirements.tsv" "$srcdir" "" "$broken"
}

atf_test_case activation_guests_are_independent
activation_guests_are_independent_head()
{
	atf_set "descr" "Reject a live feature whose 5BSD status lacks matching evidence"
}
activation_guests_are_independent_body()
{
	srcdir="$(atf_get_srcdir)"
	catalog="$srcdir/virtio-feature-activation.tsv"
	broken="$(pwd)/broken-activation.tsv"

	awk -F '\t' 'BEGIN { OFS = "\t" }
	    $1 == "BLOCK-MULTIQUEUE" { $5 = "exercised" }
	    { print }' "$catalog" >"$broken"
	atf_check -s exit:1 -o match:"entries validated" \
	    -e match:"BLOCK-MULTIQUEUE 5BSD evidence/status disagree" \
	    "$srcdir/validate-virtio-requirements.sh" \
	    "$srcdir/virtio-1.4-requirements.tsv" "$srcdir" "" "$broken"
}

atf_test_case activation_requires_scheduled_case
activation_requires_scheduled_case_head()
{
	atf_set "descr" "Reject exercised feature evidence with no qualification case"
}
activation_requires_scheduled_case_body()
{
	srcdir="$(atf_get_srcdir)"
	catalog="$srcdir/virtio-feature-activation.tsv"
	broken="$(pwd)/broken-activation.tsv"

	awk -F '\t' 'BEGIN { OFS = "\t" }
	    $1 == "NET-MULTIQUEUE" { $8 = "-" }
	    { print }' "$catalog" >"$broken"
	atf_check -s exit:1 -o match:"entries validated" \
	    -e match:"NET-MULTIQUEUE has invalid or missing Linux qualification case -" \
	    "$srcdir/validate-virtio-requirements.sh" \
	    "$srcdir/virtio-1.4-requirements.tsv" "$srcdir" "" "$broken"
}

atf_test_case activation_rejects_unscheduled_case
activation_rejects_unscheduled_case_head()
{
	atf_set "descr" "Reject a qualification case absent from virtio-lab.yaml"
}
activation_rejects_unscheduled_case_body()
{
	srcdir="$(atf_get_srcdir)"
	catalog="$srcdir/virtio-feature-activation.tsv"
	broken="$(pwd)/broken-activation.tsv"

	awk -F '\t' 'BEGIN { OFS = "\t" }
	    $1 == "NET-MULTIQUEUE" { $8 = "not-a-real-release-case" }
	    { print }' "$catalog" >"$broken"
	atf_check -s exit:1 -o match:"entries validated" \
	    -e match:"qualification case is not scheduled: not-a-real-release-case" \
	    "$srcdir/validate-virtio-requirements.sh" \
	    "$srcdir/virtio-1.4-requirements.tsv" "$srcdir" "" "$broken"
}

atf_test_case activation_rejects_unknown_assertion
activation_rejects_unknown_assertion_head()
{
	atf_set "descr" "Reject a fabricated assertion in an existing evidence artifact"
}
activation_rejects_unknown_assertion_body()
{
	srcdir="$(atf_get_srcdir)"
	catalog="$srcdir/virtio-feature-activation.tsv"
	broken="$(pwd)/broken-activation.tsv"

	awk -F '\t' 'BEGIN { OFS = "\t" }
	    $1 == "NET-MULTIQUEUE" {
		    $4 = "gnet.py:not-an-activation-assertion"
	    }
	    { print }' "$catalog" >"$broken"
	atf_check -s exit:1 -o match:"entries validated" \
	    -e match:"evidence assertion not found: gnet.py:not-an-activation-assertion" \
	    "$srcdir/validate-virtio-requirements.sh" \
	    "$srcdir/virtio-1.4-requirements.tsv" "$srcdir" "" "$broken"
}

atf_test_case self_confirming_endian_expectation
self_confirming_endian_expectation_head()
{
	atf_set "descr" "Reject an endian assertion decoded by the DUT helper"
}
self_confirming_endian_expectation_body()
{
	local_work=$(mktemp -d "${TMPDIR:-/tmp}/virtio-requirements.XXXXXX") || \
		atf_fail "cannot create isolated requirements fixture"
	trap 'rm -rf "$local_work"' EXIT HUP INT TERM
	srcdir="$(atf_get_srcdir)"
	broken="$local_work/broken-tests"
	rx_broken="$local_work/vsock_rx_harness"
	mutated="$local_work/virtio_guest_contract_test.mutated"

	mkdir "$broken"
	mkdir "$rx_broken"
	cp "$srcdir"/*.c "$srcdir"/*.h "$broken"
	# An object or installed test directory need not retain every C source
	# named by the ledger.  Preserve its ATF executables as a fallback so
	# the synthetic tree remains complete; copied sources still take
	# precedence, including the deliberately mutated guest contract below.
	for executable in "$srcdir"/*_test; do
		[ -x "$executable" ] || continue
		cp "$executable" "$broken"
	done
	for program in vsock_rx_test virtio_vsock_transport_test; do
		if [ -r "$srcdir/../vsock_rx_harness/$program.c" ]; then
			cp "$srcdir/../vsock_rx_harness/$program.c" "$rx_broken"
		else
			cp "$srcdir/../vsock_rx_harness/$program" "$rx_broken"
		fi
	done
	if [ -r "$srcdir/../vsock_test.c" ]; then
		cp "$srcdir/../vsock_test.c" "$local_work"
	else
		cp "$srcdir/../vsock_test" "$local_work"
	fi
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
	atf_add_test_case source_tree_required
	atf_add_test_case reference_corpus
	atf_add_test_case missing_waspnest_reference
	atf_add_test_case reference_artifacts_are_complete
	atf_add_test_case reference_artifacts_reject_nonregular_entries
	atf_add_test_case reference_artifacts_reject_hash_failure
	atf_add_test_case bad_reference_digest
	atf_add_test_case unstable_virtio_html_reference
	atf_add_test_case bad_test_reference
	atf_add_test_case bad_evidence_reference
	atf_add_test_case activation_requires_host_evidence
	atf_add_test_case activation_guests_are_independent
	atf_add_test_case activation_requires_scheduled_case
	atf_add_test_case activation_rejects_unscheduled_case
	atf_add_test_case activation_rejects_unknown_assertion
	atf_add_test_case self_confirming_endian_expectation
}
