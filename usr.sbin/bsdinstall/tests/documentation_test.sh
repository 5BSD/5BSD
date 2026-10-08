#!/usr/bin/env atf-sh

atf_test_case native_book_is_installed_with_base
native_book_is_installed_with_base_body()
{
	book=/usr/share/doc/5bsd
	chapters="$(atf_get_srcdir)/book-chapters"

	atf_check -s exit:0 test -f "$book/SUMMARY.md"
	atf_check -s exit:0 test -f \
	    "$book/capability/capability-mode-and-launch.md"
	atf_check -s exit:0 test -f "$book/develop/provider.md"
	atf_check -s exit:0 test -f "$book/operations/building.md"
	# Check the entire book, including new and nested chapters.  The test
	# package installs the chapter list collected from docs/book/src.
	test -s "$chapters" || atf_fail "missing chapter list $chapters"
	while read -r relative; do
		atf_check -s exit:0 test -f "$book/$relative"
	done <"$chapters"
	# On a pkgbase system the book belongs to the runtime package.
	if pkg -N >/dev/null 2>&1 &&
	    owner=$(pkg which -qo "$book/SUMMARY.md" 2>/dev/null); then
		case "$owner" in
		*-runtime) ;;
		*) atf_fail "$book is installed by $owner, not runtime" ;;
		esac
	fi
}

atf_test_case freebsd_docs_are_optional_upstream_reference
freebsd_docs_are_optional_upstream_reference_body()
{
	script=/usr/libexec/bsdinstall/docsinstall
	atf_check -s exit:0 -o ignore grep -F \
	    'The 5BSD Epic is already installed in /usr/share/doc/5bsd.' \
	    "$script"
	atf_check -s exit:0 -o ignore grep -F \
	    'upstream FreeBSD Handbook' "$script"
	atf_check -s exit:0 -o ignore grep -F \
	    'en) f_getvar DIST_DOC_$upper:-off status' "$script"
	atf_check -s exit:0 -o ignore grep -F \
	    '[ -z "$docsets" ] && exit 0' "$script"
}

atf_test_case installer_explains_type2_capability_design
installer_explains_type2_capability_design_body()
{
	script=/usr/libexec/bsdinstall/startbsdinstall
	atf_check -s exit:0 -o ignore grep -F \
	    'Type2 capability system with a microkernel userland' \
	    "$script"
	atf_check -s exit:0 -o ignore grep -F \
	    'on top of a monolithic BSD kernel.' "$script"
	atf_check -s exit:0 -o ignore grep -F \
	    'Thanks to the people who built Darwin, FreeBSD, seL4, and QNX for their inspiration.' "$script"
}

atf_test_case installer_defaults_to_5bsd_branding
installer_defaults_to_5bsd_branding_body()
{
	common=/usr/share/bsdconfig/common.subr
	atf_check -s exit:0 -o inline:'5BSD Installer\n5BSD\n' /bin/sh -c '
	    unset OSNAME EFI_LABEL_NAME
	    DEBUG_SELF_INITIALIZE= common="$1" . "$1"
	    printf "%s Installer\n%s\n" "$OSNAME" "$EFI_LABEL_NAME"
	' sh "$common"
}

atf_init_test_cases()
{
	atf_add_test_case native_book_is_installed_with_base
	atf_add_test_case freebsd_docs_are_optional_upstream_reference
	atf_add_test_case installer_explains_type2_capability_design
	atf_add_test_case installer_defaults_to_5bsd_branding
}
