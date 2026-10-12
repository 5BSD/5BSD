# SPDX-License-Identifier: BSD-2-Clause
setup()
{
    script=$(atf_config_get ports_script /usr/libexec/bsdinstall/ports)
    [ -f "$script" ] || atf_skip 'installer ports helper not installed'
    mkdir root bin
    export BSDINSTALL_CHROOT="$(pwd)/root"
    export PORTS_TEST_ARGS="$(pwd)/args"
    export PATH="$(pwd)/bin:$PATH"
    cat > bin/git <<'MOCK'
#!/bin/sh
printf '%s\n' "$@" > "$PORTS_TEST_ARGS"
MOCK
    chmod +x bin/git
}
atf_test_case defaults
defaults_body()
{
    setup
    atf_check -s exit:0 -o match:'5BSD/5BSD-ports.git' -e empty sh "$script"
    printf '%s\n' clone --depth 1 --single-branch --branch main -- https://github.com/5BSD/5BSD-ports.git "$BSDINSTALL_CHROOT/usr/ports" > expected
    atf_check -s exit:0 -o empty diff -u expected args
    atf_check -s exit:0 -o match:'custom.git' -e empty env BSDINSTALL_PORTS_REPOSITORY=https://example.invalid/custom.git BSDINSTALL_PORTS_BRANCH=testing sh "$script"
    atf_check -s exit:0 -o ignore grep -Fx testing args
    atf_check -s exit:0 -o ignore grep -Fx https://example.invalid/custom.git args
}
atf_test_case reject_destinations
reject_destinations_body()
{
    setup
    mkdir -p root/usr/ports
    echo preserve > root/usr/ports/local
    atf_check -s not-exit:0 -o empty -e match:'not empty' sh "$script"
    [ ! -e args ] || atf_fail 'invoked git for nonempty destination'
    atf_check -s exit:0 -o inline:'preserve\n' cat root/usr/ports/local
    mv root/usr outside
    ln -s ../outside root/usr
    atf_check -s not-exit:0 -o empty -e match:symlinked sh "$script"
    atf_check -s not-exit:0 -o empty -e match:'alternate installation root' env BSDINSTALL_CHROOT=/ sh "$script"
    [ ! -e args ] || atf_fail 'invoked git for rejected root'
}
atf_init_test_cases()
{
    atf_add_test_case defaults
    atf_add_test_case reject_destinations
}
