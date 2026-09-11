# SPDX-License-Identifier: BSD-2-Clause
atf_test_case detects_changes
detects_changes_body()
{
	tool="$(atf_get_srcdir)/base-integrity.sh"
	mkdir root
	printf 'original\n' > "root/file with spaces"
	ln -s "file with spaces" root/link
	atf_check -s exit:0 sh "$tool" create root baseline
	atf_check -s exit:0 sh "$tool" check root baseline
	atf_check -s exit:73 -e not-empty sh "$tool" create root baseline
	printf 'modified\n' > "root/file with spaces"
	atf_check -s not-exit:0 -o not-empty sh "$tool" check root baseline
	printf 'original\n' > "root/file with spaces"
	atf_check -s exit:0 sh "$tool" check root baseline
	chmod 600 "root/file with spaces"
	atf_check -s not-exit:0 -o not-empty sh "$tool" check root baseline
	chmod 644 "root/file with spaces"
	touch root/extra
	atf_check -s not-exit:0 -o not-empty sh "$tool" check root baseline
	rm root/extra root/link
	atf_check -s not-exit:0 -o not-empty sh "$tool" check root baseline
	ln -s elsewhere root/link
	atf_check -s not-exit:0 -o not-empty sh "$tool" check root baseline
	atf_check -s exit:64 -e not-empty sh "$tool" create root root/baseline
	atf_check -s exit:64 -e not-empty sh "$tool" create / forbidden
}
atf_init_test_cases()
{
	atf_add_test_case detects_changes
}
