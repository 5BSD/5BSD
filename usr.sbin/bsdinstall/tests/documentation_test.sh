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

atf_test_case installer_explains_hybrid_rootless_design
installer_explains_hybrid_rootless_design_body()
{
	script=@SRCTOP@/usr.sbin/bsdinstall/startbsdinstall
	atf_check -s exit:0 -o ignore grep -F \
	    'hybrid operating system that interposes capability-based security' \
	    "$script"
	atf_check -s exit:0 -o ignore grep -F \
	    'inspired by seL4 and iOS' "$script"
	atf_check -s exit:0 -o ignore grep -F \
	    'BSD UNIX userspace to achieve a rootless design' "$script"
}

atf_test_case installer_defaults_to_5bsd_branding
installer_defaults_to_5bsd_branding_body()
{
	common=@SRCTOP@/usr.sbin/bsdconfig/share/common.subr
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
	atf_add_test_case installer_explains_hybrid_rootless_design
	atf_add_test_case installer_defaults_to_5bsd_branding
}
