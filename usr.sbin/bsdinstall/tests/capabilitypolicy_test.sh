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

atf_init_test_cases()
{
	atf_add_test_case missing_database_preserves_policy
	atf_add_test_case defaults
	atf_add_test_case additional_principals
	atf_add_test_case rejects_unknown
	atf_add_test_case explains_core_boundary
}
