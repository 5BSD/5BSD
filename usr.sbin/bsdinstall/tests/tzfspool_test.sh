#!/usr/bin/env atf-sh

pool_script()
{
	if [ -n "${TZFSPOOL:-}" ]; then
		printf '%s' "$TZFSPOOL"
	else
		printf '%s' @SRCTOP@/usr.sbin/bsdinstall/scripts/tzfspool
	fi
}

make_root()
{
	mkdir -p root/Capabilities/Config state
	cat >root/Capabilities/Config/bsdfilesystem.ucl <<-EOF
	# pool = "zroot";
	open_paths = [
	    { label = "system.Auth/authagentd";
	      path = "/etc/passwd"; rights = ["read"]; },
	]
	EOF
}

atf_test_case selected_name_is_persisted
selected_name_is_persisted_body()
{
	make_root
	printf '%s\n' 'fast:pool-1' >state/bsdfilesystem.pool
	atf_check -s exit:0 env \
	    BSDINSTALL_CHROOT="$(pwd)/root" \
	    BSDINSTALL_TMPETC="$(pwd)/state" \
	    /bin/sh "$(pool_script)"
	atf_check -s exit:0 -o inline:'pool = "fast:pool-1";\n' \
	    grep '^pool' root/Capabilities/Config/bsdfilesystem.ucl
	atf_check -s exit:0 -o match:'system.Auth/authagentd' \
	    grep 'system.Auth' root/Capabilities/Config/bsdfilesystem.ucl
	atf_check -s exit:1 test -e state/bsdfilesystem.pool
}

atf_test_case no_guided_pool_is_noop
no_guided_pool_is_noop_body()
{
	make_root
	cp root/Capabilities/Config/bsdfilesystem.ucl before
	atf_check -s exit:0 env \
	    BSDINSTALL_CHROOT="$(pwd)/root" \
	    BSDINSTALL_TMPETC="$(pwd)/state" \
	    /bin/sh "$(pool_script)"
	atf_check -s exit:0 cmp before root/Capabilities/Config/bsdfilesystem.ucl
}

atf_test_case invalid_state_fails_closed
invalid_state_fails_closed_body()
{
	make_root
	cp root/Capabilities/Config/bsdfilesystem.ucl before
	printf '%s\n' '../wrong' >state/bsdfilesystem.pool
	atf_check -s exit:1 -e match:'invalid selected pool name' env \
	    BSDINSTALL_CHROOT="$(pwd)/root" \
	    BSDINSTALL_TMPETC="$(pwd)/state" \
	    /bin/sh "$(pool_script)"
	atf_check -s exit:0 cmp before root/Capabilities/Config/bsdfilesystem.ucl
	atf_check -s exit:0 test -f state/bsdfilesystem.pool
}

atf_init_test_cases()
{
	atf_add_test_case selected_name_is_persisted
	atf_add_test_case no_guided_pool_is_noop
	atf_add_test_case invalid_state_fails_closed
}
