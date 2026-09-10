#!/usr/bin/env atf-sh

atf_test_case native_book_is_installed_with_base
native_book_is_installed_with_base_body()
{
	mkdir root
	atf_check -s exit:0 -o ignore -e ignore make \
	    -C @SRCTOP@/share/doc/5bsd \
	    DESTDIR="$(pwd)/root" MK_INSTALL_AS_USER=yes install
	atf_check -s exit:0 test -f root/usr/share/doc/5bsd/SUMMARY.md
	atf_check -s exit:0 test -f \
	    root/usr/share/doc/5bsd/security/rootless-hardening.md
	atf_check -s exit:0 test -f \
	    root/usr/share/doc/5bsd/development/writing-components.md
	atf_check -s exit:0 test -f \
	    root/usr/share/doc/5bsd/operations/building.md
	atf_check -s exit:0 -o inline:'runtime\n' make \
	    -C @SRCTOP@/share/doc/5bsd -V PACKAGE
}

atf_test_case freebsd_docs_are_optional_upstream_reference
freebsd_docs_are_optional_upstream_reference_body()
{
	script=@SRCTOP@/usr.sbin/bsdinstall/scripts/docsinstall
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

atf_init_test_cases()
{
	atf_add_test_case native_book_is_installed_with_base
	atf_add_test_case freebsd_docs_are_optional_upstream_reference
}
