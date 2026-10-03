#!/usr/bin/env atf-sh

policy_script()
{
	if [ -n "${CAPABILITYPOLICY:-}" ]; then
		printf '%s' "$CAPABILITYPOLICY"
	else
		printf '%s' @SRCTOP@/usr.sbin/bsdinstall/scripts/capabilitypolicy
	fi
}

make_root()
{
	mkdir -p root/etc root/Capabilities/Config state
	cat >root/etc/master.passwd <<-EOF
	root:*:0:0::0:0:Charlie &:/root:/bin/sh
	alice:*:1001:1001::0:0:Alice:/home/alice:/bin/sh
	bob:*:1002:1002::0:0:Bob:/home/bob:/bin/sh
	EOF
	cat >root/etc/group <<-EOF
	wheel:*:0:root
	staff:*:20:alice
	operators:*:5:bob
	EOF
}

atf_test_case defaults
defaults_body()
{
	make_root
	atf_check -s exit:0 env \
	    BSDINSTALL_CAPABILITY_POLICY_NONINTERACTIVE=yes \
	    BSDINSTALL_CHROOT="$(pwd)/root" \
	    BSDINSTALL_TMPETC="$(pwd)/state" \
	    BSDINSTALL_CAPABILITY_ADMIN_USERS= \
	    BSDINSTALL_CAPABILITY_ADMIN_GROUPS= \
	    /bin/sh "$(policy_script)"
	atf_check -s exit:0 -o match:'uids = \[ 0 \];' \
	    grep 'uids' root/Capabilities/Config/principal-policy.ucl
	atf_check -s exit:0 -o match:'groups = \[ "wheel" \];' \
	    grep 'groups' root/Capabilities/Config/principal-policy.ucl
	# Only the principals form is written; the removed top-level admin block is not.
	atf_check -s exit:0 -o ignore grep -q '^principals {' \
	    root/Capabilities/Config/principal-policy.ucl
	atf_check -s exit:0 -o match:'anointments = \[ "\*" \];' \
	    grep anointments root/Capabilities/Config/principal-policy.ucl
	atf_check -s exit:1 -o ignore grep -q '^admin' \
	    root/Capabilities/Config/principal-policy.ucl
}

atf_test_case additional_principals
additional_principals_body()
{
	make_root
	atf_check -s exit:0 env \
	    BSDINSTALL_CAPABILITY_POLICY_NONINTERACTIVE=yes \
	    BSDINSTALL_CHROOT="$(pwd)/root" \
	    BSDINSTALL_TMPETC="$(pwd)/state" \
	    BSDINSTALL_CAPABILITY_ADMIN_USERS='alice, 1002 alice' \
	    BSDINSTALL_CAPABILITY_ADMIN_GROUPS='operators, staff operators' \
	    /bin/sh "$(policy_script)"
	atf_check -s exit:0 -o match:'uids = \[ 0, 1001, 1002 \];' \
	    grep 'uids' root/Capabilities/Config/principal-policy.ucl
	atf_check -s exit:0 \
	    -o match:'groups = \[ "wheel", "operators", "staff" \];' \
	    grep 'groups' root/Capabilities/Config/principal-policy.ucl
}

atf_test_case rejects_unknown
rejects_unknown_body()
{
	make_root
	printf '%s\n' sentinel >root/Capabilities/Config/principal-policy.ucl
	atf_check -s exit:1 -e match:"User or UID 'mallory' does not exist" env \
	    BSDINSTALL_CAPABILITY_POLICY_NONINTERACTIVE=yes \
	    BSDINSTALL_CHROOT="$(pwd)/root" \
	    BSDINSTALL_TMPETC="$(pwd)/state" \
	    BSDINSTALL_CAPABILITY_ADMIN_USERS=mallory \
	    BSDINSTALL_CAPABILITY_ADMIN_GROUPS=staff \
	    /bin/sh "$(policy_script)"
	atf_check -s exit:0 -o inline:'sentinel\n' \
	    cat root/Capabilities/Config/principal-policy.ucl
	atf_check -s exit:1 -e match:"Group 'unknown' does not exist" env \
	    BSDINSTALL_CAPABILITY_POLICY_NONINTERACTIVE=yes \
	    BSDINSTALL_CHROOT="$(pwd)/root" \
	    BSDINSTALL_TMPETC="$(pwd)/state" \
	    BSDINSTALL_CAPABILITY_ADMIN_USERS=alice \
	    BSDINSTALL_CAPABILITY_ADMIN_GROUPS=unknown \
	    /bin/sh "$(policy_script)"
	atf_check -s exit:0 -o inline:'sentinel\n' \
	    cat root/Capabilities/Config/principal-policy.ucl
}

atf_test_case explains_core_boundary
explains_core_boundary_body()
{
	atf_check -s exit:0 -o ignore grep -F \
	    'Administrators can manage SYSTEM daemons' \
	    "$(policy_script)"
	atf_check -s exit:0 -o ignore grep -F \
	    'CORE daemons cannot be managed at runtime by anyone, including root' "$(policy_script)"
	atf_check -s exit:0 -o ignore grep -F \
	    'but cannot manage CORE daemons' "$(policy_script)"
}

atf_test_case missing_database_preserves_policy
missing_database_preserves_policy_body()
{
	make_root
	echo sentinel >root/Capabilities/Config/principal-policy.ucl
	rm root/etc/group
	atf_check -s exit:1 -e match:'group database is unavailable' env \
	    BSDINSTALL_CAPABILITY_POLICY_NONINTERACTIVE=yes \
	    BSDINSTALL_CHROOT="$(pwd)/root" \
	    BSDINSTALL_TMPETC="$(pwd)/state" \
	    /bin/sh "$(policy_script)"
	atf_check -s exit:0 -o inline:'sentinel\n' \
	    cat root/Capabilities/Config/principal-policy.ucl
}


atf_test_case scripted_accounts_before_policy
scripted_accounts_before_policy_body()
{
	make_root
	# The account must be absent until the post-install hook executes.
	mkdir -p root/tmp scratch bin
	export TEST_POLICY_SCRIPT="$(policy_script)"
	export TEST_CALLS="$(pwd)/calls"
	cat >bin/bsdinstall <<-'EOF'
	#!/bin/sh
	printf '%s\n' "$1" >>"$TEST_CALLS"
	if [ "$1" = capabilitypolicy ]; then
		exec /bin/sh "$TEST_POLICY_SCRIPT"
	fi
	EOF
	cat >bin/chroot <<-'EOF'
	#!/bin/sh
	# Execute only our fixture hook without requiring host root privileges.
	[ "$2" = /tmp/installscript ] || exit 1
	export TEST_TARGET="$1"
	exec /bin/sh "$1$2"
	EOF
	chmod 0755 bin/*
	cat >installscript <<-'EOF'
	BSDINSTALL_CAPABILITY_ADMIN_USERS=carol
	export BSDINSTALL_CAPABILITY_ADMIN_USERS
	#!/bin/sh
	printf '%s\n' 'carol:*:1003:1003::0:0:Carol:/home/carol:/bin/sh' >>"$TEST_TARGET/etc/master.passwd"
	EOF
	atf_check -s exit:0 -o ignore -e ignore env \
	    PATH="$(pwd)/bin:/bin:/usr/bin:/sbin:/usr/sbin" \
	    TMPDIR="$(pwd)/scratch" BSDINSTALL_LOG="$(pwd)/install.log" \
	    BSDINSTALL_CHROOT="$(pwd)/root" \
	    BSDINSTALL_TMPETC="$(pwd)/state" \
	    PATH_FSTAB="$(pwd)/state/fstab" BSDINSTALL_SKIP_FIRMWARE=yes \
	    /bin/sh "$(dirname "$(policy_script)")/script" "$(pwd)/installscript"
	atf_check -s exit:0 -o match:'uids = \[ 0, 1003 \];' \
	    grep uids root/Capabilities/Config/principal-policy.ucl
	atf_check -s exit:0 -o inline:'capabilitypolicy\nentropy\numount\n' tail -n 3 calls
}

atf_test_case explicit_grants
explicit_grants_body()
{
	make_root
	atf_check -s exit:0 env \
	    BSDINSTALL_CAPABILITY_POLICY_NONINTERACTIVE=yes \
	    BSDINSTALL_CHROOT="$(pwd)/root" BSDINSTALL_TMPETC="$(pwd)/state" \
	    BSDINSTALL_CAPABILITY_COMPAT=no \
	    BSDINSTALL_CAPABILITY_ADMIN_USERS=alice \
	    BSDINSTALL_CAPABILITY_ADMIN_GROUPS= \
	    BSDINSTALL_CAPABILITY_MANAGE_USERS='bob, 1002' \
	    /bin/sh "$(policy_script)"
	atf_check -s exit:0 -o match:'uids = \[ 1001 \];' \
	    grep uids root/Capabilities/Config/principal-policy.ucl
	atf_check -s exit:0 -o match:'uids = \[ 1002 \];' \
	    grep uids root/Capabilities/Config/principal-policy.ucl
	atf_check -s exit:1 grep -q wheel root/Capabilities/Config/principal-policy.ucl
	atf_check -s exit:1 grep -q 'uids = \[ 0' root/Capabilities/Config/principal-policy.ucl
	atf_check -s exit:0 -o ignore grep 'system.switchboard.admin' root/Capabilities/Config/principal-policy.ucl
	atf_check -s exit:0 -o ignore grep 'admin_rights = false' root/Capabilities/Config/principal-policy.ucl
}

atf_test_case empty_grants
empty_grants_body()
{
	make_root
	atf_check -s exit:0 env \
	    BSDINSTALL_CAPABILITY_POLICY_NONINTERACTIVE=yes \
	    BSDINSTALL_CHROOT="$(pwd)/root" BSDINSTALL_TMPETC="$(pwd)/state" \
	    BSDINSTALL_CAPABILITY_COMPAT=no BSDINSTALL_CAPABILITY_ADMIN_USERS= \
	    BSDINSTALL_CAPABILITY_ADMIN_GROUPS= BSDINSTALL_CAPABILITY_MANAGE_USERS= \
	    /bin/sh "$(policy_script)"
	atf_check -s exit:1 grep -q 'uids\|groups\|"\*"' root/Capabilities/Config/principal-policy.ucl
	atf_check -s exit:0 -o ignore grep 'anointments = \[\];' root/Capabilities/Config/principal-policy.ucl
}

atf_test_case rejects_bad_options
rejects_bad_options_body()
{
	make_root
	echo sentinel > root/Capabilities/Config/principal-policy.ucl
	atf_check -s exit:1 -e match:'Compatibility must be yes or no' env \
	    BSDINSTALL_CAPABILITY_POLICY_NONINTERACTIVE=yes \
	    BSDINSTALL_CHROOT="$(pwd)/root" BSDINSTALL_TMPETC="$(pwd)/state" \
	    BSDINSTALL_CAPABILITY_COMPAT=maybe /bin/sh "$(policy_script)"
	atf_check -s exit:1 -e match:"User or UID 'mallory' does not exist" env \
	    BSDINSTALL_CAPABILITY_POLICY_NONINTERACTIVE=yes \
	    BSDINSTALL_CHROOT="$(pwd)/root" BSDINSTALL_TMPETC="$(pwd)/state" \
	    BSDINSTALL_CAPABILITY_MANAGE_USERS=mallory /bin/sh "$(policy_script)"
	atf_check -s exit:0 -o inline:'sentinel\n' cat root/Capabilities/Config/principal-policy.ucl
}

atf_test_case account_selection
account_selection_body()
{
	make_root
	printf '%s\n' 'toor:*:0:0::0:0:Alias:/root:/bin/sh' >> root/etc/master.passwd
	mkdir bin
	# Drive the actual dialog flow; verify the account list comes from the target.
	cat >bin/bsddialog <<-'EOF'
	#!/bin/sh
	printf '%s\n' "$@" >> "$TEST_DIALOG_LOG"
	case "$*" in
	*--msgbox*) exit 0 ;;
	*--menu*) echo no >&2 ;;
	*--checklist*"Full-access accounts already"*) echo '"1002"' >&2 ;;
	*--checklist*) echo '"1001"' >&2 ;;
	*) exit 1 ;;
	esac
	EOF
	chmod 0755 bin/bsddialog
	atf_check -s exit:0 -o ignore env \
	    PATH="$(pwd)/bin:/bin:/usr/bin:/sbin:/usr/sbin" \
	    TEST_DIALOG_LOG="$(pwd)/dialogs" BSDINSTALL_CHROOT="$(pwd)/root" \
	    BSDINSTALL_TMPETC="$(pwd)/state" /bin/sh "$(policy_script)"
	atf_check -s exit:0 -o ignore grep -F 'alice (UID 1001)' dialogs
	atf_check -s exit:0 -o ignore grep -F 'bob (UID 1002)' dialogs
	atf_check -s exit:0 -o inline:'2\n' grep -c '^root (UID 0)$' dialogs
	atf_check -s exit:1 grep -F 'toor (UID 0)' dialogs
	atf_check -s exit:0 -o match:'uids = \[ 1001 \];' grep uids root/Capabilities/Config/principal-policy.ucl
	atf_check -s exit:0 -o match:'uids = \[ 1002 \];' grep uids root/Capabilities/Config/principal-policy.ucl
	atf_check -s exit:1 grep -q wheel root/Capabilities/Config/principal-policy.ucl
}

atf_init_test_cases()
{
	atf_add_test_case explicit_grants
	atf_add_test_case empty_grants
	atf_add_test_case rejects_bad_options
	atf_add_test_case account_selection
	atf_add_test_case scripted_accounts_before_policy
	atf_add_test_case missing_database_preserves_policy
	atf_add_test_case defaults
	atf_add_test_case additional_principals
	atf_add_test_case rejects_unknown
	atf_add_test_case explains_core_boundary
}
