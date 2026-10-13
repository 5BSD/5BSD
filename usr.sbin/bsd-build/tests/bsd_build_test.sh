# SPDX-License-Identifier: BSD-2-Clause
setup()
{
    tool=$(atf_config_get bsd_build /usr/sbin/build-bsd)
    [ -f "$tool" ] || atf_skip 'build-bsd not installed'
    [ -f /usr/src/Makefile ] || atf_skip 'source build frontend requires /usr/src'
}
atf_test_case plans
plans_body()
{
    setup
    output=/usr/obj/usr/src/bsd-build-plan-only-$$
    [ ! -e "$output" ] || atf_fail 'test output already exists'
    atf_check -s exit:0 -o save:stage -e empty "$tool" plan stage --output "$output" --signing development --cache
    [ ! -e "$output" ] || atf_fail 'plan created a stage'
    atf_check -s exit:0 -o ignore grep 'host-tools:' stage
    atf_check -s exit:0 -o ignore grep "installworld:.*NO_ROOT=yes DESTDIR=$output" stage
    atf_check -s exit:0 -o ignore grep 'CAPIMAGE_SIGNING_MODE=development' stage
    atf_check -s exit:0 -o save:packages -e empty env REPODIR=/home/incorrect MAKEOBJDIRPREFIX=/home/incorrect "$tool" plan packages
    atf_check -s exit:0 -o ignore grep 'buildworld:.*WITH_MALLOC_PRODUCTION=yes.*buildworld' packages
    atf_check -s exit:0 -o ignore grep 'system-packages:.*REPODIR=/usr/obj/usr/src/repo' packages
    atf_check -s exit:1 -o empty grep /home/incorrect packages
    cpus=$(sysctl -n hw.ncpu)
    atf_check -s exit:0 -o ignore grep "buildkernel:.*-j $cpus " packages
    atf_check -s exit:0 -o save:development -e empty "$tool" plan build
    atf_check -s exit:0 -o ignore grep WITH_MALLOC_PRODUCTION development
    atf_check -s exit:0 -o ignore grep '^system-packages:' development
    atf_check -s exit:1 -o empty grep host-tools development
}
atf_test_case make_clean_options
make_clean_options_head()
{
    atf_set descr 'Frontend clean options select the intended value in the real BSD make option parser'
    atf_set require.progs make
}
make_clean_options_body()
{
    setup
    printf '.include <src.opts.mk>\n' > options.mk
    for mode in clean incremental; do
        if [ "$mode" = incremental ]; then
            atf_check -s exit:0 -o save:plan -e empty "$tool" plan build --incremental
            expected=no
        else
            atf_check -s exit:0 -o save:plan -e empty "$tool" plan build
            expected=yes
        fi
        option=$(awk '/^buildworld:/ { for (i = 1; i <= NF; i++) if ($i ~ /^(WITH|WITHOUT)_CLEAN=/) print $i }' plan)
        [ -n "$option" ] || atf_fail 'missing explicit clean option'
        atf_check -s exit:0 -o inline:"$expected\n" -e empty make -m /usr/src/share/mk -f options.mk SRCTOP=/usr/src "$option" -V MK_CLEAN
    done
}
atf_test_case invalid_options
invalid_options_body()
{
    setup
    atf_check -s not-exit:0 -o empty -e match:'applies only to media' "$tool" plan build --media-format iso
    atf_check -s not-exit:0 -o empty -e match:'applies only to build, packages or stage' "$tool" plan media --signing development --cache
    atf_check -s not-exit:0 -o empty -e match:'applies only to build or packages' "$tool" plan verify --pkg-key /nonexistent/private.pem
    bad_key=$(printf '/tmp/key\nname')
    atf_check -s not-exit:0 -o empty -e match:'control characters' "$tool" plan stage --key "$bad_key"
    atf_check -s not-exit:0 -o empty -e match:'under /usr/obj' "$tool" plan stage --output /home/unsafe-stage
    atf_check -s not-exit:0 -o empty -e match:'requires development or signed' "$tool" plan stage --cache
    atf_check -s not-exit:0 -o empty -e match:'requires a readable' "$tool" plan stage --signing signed
    atf_check -s not-exit:0 -o empty -e match:'applies only to packages' "$tool" plan stage --ports /usr/ports
    atf_check -s not-exit:0 -o empty -e match:'requires development signing' "$tool" plan stage --development-key /usr/obj/key
    atf_check -s not-exit:0 -o empty -e match:'traversal or whitespace' "$tool" plan stage --output /usr/obj/../unsafe
}
atf_test_case path_preflight cleanup
path_preflight_body()
{
    setup
    [ -w /usr/obj/usr/src ] || atf_skip 'requires write access to the standard object directory'
    work=/usr/obj/usr/src/bsd-build-preflight-$$
    mkdir -m 0700 "$work"
    printf '%s\n' "$work" > created-preflight
    mkdir -m 0700 "$work/private"
    printf 'key permission fixture\n' > "$work/private/key"
    chmod 0644 "$work/private/key"
    atf_check -s not-exit:0 -o empty -e match:'accessible to group' "$tool" plan stage --key "$work/private/key"
    chmod 0600 "$work/private/key"
    chmod 0777 "$work/private"
    atf_check -s not-exit:0 -o empty -e match:'directory must not be writable' "$tool" plan stage --key "$work/private/key"
    chmod 0700 "$work/private"
    atf_check -s exit:0 -o ignore -e empty "$tool" plan stage --key "$work/private/key"
    ln -s key "$work/private/link"
    atf_check -s not-exit:0 -o empty -e ignore "$tool" plan stage --signing development --development-key "$work/private/link"
    ln -s /tmp "$work/escape"
    atf_check -s not-exit:0 -o empty -e match:'resolves outside /usr/obj' "$tool" plan stage --output "$work/escape/new-parent/new-stage"
    [ ! -e new-parent ] || atf_fail 'preflight created an escaped stage parent'
    ln -s "$work" "$work/alias"
    atf_check -s not-exit:0 -o empty -e match:'outside the stage' "$tool" plan stage --output "$work/new-stage" --signing development --development-key "$work/alias/new-stage/private/key"
    [ ! -e "$work/new-stage" ] || atf_fail 'preflight created a stage or key directory'
    ln -s /usr/obj/usr/src/repo "$work/repo-alias"
    atf_check -s not-exit:0 -o empty -e ignore "$tool" plan stage --signing development --development-key "$work/repo-alias/uncreated/private.pem"
    atf_check -s not-exit:0 -o empty -e match:'traversal' "$tool" plan stage --signing development --development-key "$work/private/../key"
    atf_check -s exit:0 -o ignore -e empty "$tool" plan stage --output "$work/new-parent/new-stage" --signing development --development-key "$work/keys/new/key.pem"
    [ ! -e "$work/new-parent" ] && [ ! -e "$work/keys" ] || atf_fail 'planning created directories'
}
path_preflight_cleanup()
{
    if [ -f created-preflight ]; then
        work=$(cat created-preflight)
        case "$work" in /usr/obj/usr/src/bsd-build-preflight-*) rm -rf "$work";; esac
    fi
}
atf_test_case failure_stops_pipeline cleanup
failure_stops_pipeline_head()
{
    atf_set descr 'A failed world build stops orchestration and records the real exit status'
}
failure_stops_pipeline_body()
{
    setup
    [ -w /usr/obj/usr/src ] || atf_skip 'requires write access to the standard object directory'
    mkdir mock
    cat > mock/make <<'SCRIPT'
#!/bin/sh
printf '%s\n' "$*" >> "$BSD_BUILD_TEST_LOG"
exit 42
SCRIPT
    chmod +x mock/make
    atf_check -s exit:42 -o save:out -e save:err env PATH="$(pwd)/mock:$PATH" BSD_BUILD_TEST_LOG="$(pwd)/commands" "$tool" build
    atf_check -s exit:0 -o ignore grep 'buildworld' commands
    atf_check -s exit:1 -o empty grep 'buildkernel' commands
    run=$(sed -n 's/^failed step=buildworld exit=42 logs=//p' err)
    case "$run" in /usr/obj/usr/src/build-runs/*) ;; *) atf_fail 'missing failure log location';; esac
    printf '%s\n' "$run" > created-run
    atf_check -s exit:0 -o match:'failed step=buildworld exit=42' -e empty "$tool" status "$run"
    [ -f "$run/01-buildworld.log" ] || atf_fail 'missing step log'
}
failure_stops_pipeline_cleanup()
{
    if [ -f created-run ]; then
        run=$(cat created-run)
        case "$run" in /usr/obj/usr/src/build-runs/*) rm -rf "$run";; esac
    fi
}
atf_test_case successful_stage cleanup
successful_stage_head()
{
    atf_set descr 'A staged build preserves order, private destinations, and signing configuration'
}
successful_stage_body()
{
    setup
    [ -w /usr/obj/usr/src ] || atf_skip 'requires write access to the standard object directory'
    mkdir mock
    cat > mock/make <<'SCRIPT'
#!/bin/sh
printf '%s\n' "$*" >> "$BSD_BUILD_TEST_LOG"
exit 0
SCRIPT
    chmod +x mock/make
    stage=/usr/obj/usr/src/bsd-build-test-stage-$$
    [ ! -e "$stage" ] || atf_fail 'test stage exists'
    printf '%s\n' "$stage" > created-stage
    atf_check -s exit:0 -o save:out -e empty env PATH="$(pwd)/mock:$PATH" BSD_BUILD_TEST_LOG="$(pwd)/commands" "$tool" stage --output "$stage" --signing development --cache --relaxed-signatures
    sed 's/.* //' commands > targets
    printf '%s\n' SRCTOP=/usr/src buildworld buildkernel installworld distribution installkernel capimage-stage > expected
    atf_check -s exit:0 -o empty diff -u expected targets
    for target in installworld distribution installkernel capimage-stage; do
        atf_check -s exit:0 -o ignore grep "NO_ROOT=yes DESTDIR=$stage.*$target\$" commands
    done
    atf_check -s exit:0 -o ignore grep 'CAPIMAGE_SIGNING_MODE=development.*CAPIMAGE_REQUIRE_SIGNATURES=no.*CAPIMAGE_BUILD_CACHE=yes' commands
    run=$(sed -n 's/^complete action=stage logs=\([^ ]*\) stage=.*/\1/p' out)
    case "$run" in /usr/obj/usr/src/build-runs/*) ;; *) atf_fail 'missing completion log location';; esac
    printf '%s\n' "$run" > created-run
    atf_check -s exit:0 -o match:'complete action=stage' -e empty "$tool" status "$run"
}
successful_stage_cleanup()
{
    failure_stops_pipeline_cleanup
    if [ -f created-stage ]; then
        stage=$(cat created-stage)
        case "$stage" in /usr/obj/usr/src/bsd-build-test-stage-*) rmdir "$stage";; esac
    fi
}
atf_test_case configuration
configuration_body()
{
    setup
    cat > settings <<'CONFIG'
jobs=2
kernel=GENERIC-NODEBUG
src_conf=/dev/null
make_conf=/dev/null
signing=development
cache=yes
CONFIG
    atf_check -s exit:0 -o save:configured -e empty "$tool" plan build --jobs 3 --config settings
    atf_check -s exit:0 -o ignore grep 'cpus=3 kernel=GENERIC-NODEBUG production=yes' configured
    atf_check -s exit:0 -o ignore grep 'SRCCONF=/dev/null __MAKE_CONF=/dev/null' configured
    atf_check -s exit:0 -o ignore grep 'CAPIMAGE_SIGNING_MODE=development' configured
    atf_check -s exit:0 -o ignore grep '^system-packages:' configured
    atf_check -s exit:0 -o save:configured2 -e empty "$tool" plan packages --config settings --jobs 3
    # Run paths contain a process ID: compare policy/argument lines after normalization.
    sed -E 's@build-runs/[^/ ]+@build-runs/RUN@g' configured > first
    sed -E 's@build-runs/[^/ ]+@build-runs/RUN@g' configured2 > second
    atf_check -s exit:0 -o empty diff -u first second
    for bad in 0 -1 autoX 999999999999999999999; do
        atf_check -s not-exit:0 -o empty -e match:jobs "$tool" plan build --jobs "$bad"
    done
    printf 'jobs=2\njobs=3\n' > bad
    atf_check -s not-exit:0 -o empty -e match:duplicate "$tool" plan build --config bad
    printf 'unknown=value\n' > bad
    atf_check -s not-exit:0 -o empty -e match:unknown "$tool" plan build --config bad
    printf 'cache=perhaps\n' > bad
    atf_check -s not-exit:0 -o empty -e match:'yes or no' "$tool" plan build --config bad
    printf '%s\n' 'kernel=$(touch executed)' > bad
    atf_check -s not-exit:0 -o empty -e match:'configuration name' "$tool" plan build --config bad
    [ ! -e executed ] || atf_fail 'configuration executed shell code'
    atf_check -s not-exit:0 -o empty -e match:'only one' "$tool" plan build --config settings --config settings
    atf_check -s not-exit:0 -o empty -e match:'not readable' "$tool" plan build --src-conf /nonexistent/bsd-build-src.conf
}
atf_test_case architectures
architectures_body()
{
    setup
    for selection in native amd64 arm64 riscv64; do
        atf_check -s exit:0 -o save:plan -e empty "$tool" plan stage --arch "$selection"
        case "$selection" in
        native) native=$(uname -p); case "$native" in amd64) target=amd64; arch=amd64;; aarch64) target=arm64; arch=aarch64;; riscv64) target=riscv; arch=riscv64;; esac;;
        amd64) target=amd64; arch=amd64;;
        arm64) target=arm64; arch=aarch64;;
        riscv64) target=riscv; arch=riscv64;;
        esac
        for operation in buildworld buildkernel; do
            atf_check -s exit:0 -o ignore grep "^$operation:.*TARGET=$target TARGET_ARCH=$arch " plan
        done
    done
    atf_check -s not-exit:0 -o empty -e match:'--arch must' "$tool" plan build --arch i386
    atf_check -s exit:0 -o save:signed -e empty "$tool" plan stage --arch arm64 --signing development
    atf_check -s exit:1 -o empty grep '^host-tools:.*TARGET' signed
}
atf_test_case deploy_lifecycle
deploy_lifecycle_head()
{
    atf_set require.progs 'python3.12 /usr/local/sbin/pkg-static'
    atf_set descr 'Deployment failures preserve target roots and never activate boot environments'
}
deploy_lifecycle_body()
{
    helper=$(atf_config_get deploy_helper "$(atf_get_srcdir)/deploy.py")
    tests=$(atf_config_get deploy_tests "$(atf_get_srcdir)/deploy_test.py")
    atf_check -s exit:0 -o ignore -e match:'OK' env BSD_BUILD_DEPLOY_HELPER="$helper" python3.12 "$tests"
}
atf_test_case installer_lifecycle
installer_lifecycle_head()
{
    atf_set require.progs 'python3.12'
    atf_set descr 'Installer launch verifies inputs before opening disks and retains failure state'
}
installer_lifecycle_body()
{
    helper=$(atf_config_get installer_helper "$(atf_get_srcdir)/installer.py")
    tests=$(atf_config_get installer_tests "$(atf_get_srcdir)/installer_test.py")
    atf_check -s exit:0 -o ignore -e match:'OK' env BSD_BUILD_INSTALLER_HELPER="$helper" python3.12 "$tests"
}
atf_test_case media_orchestration cleanup
media_orchestration_body()
{
    setup
    [ -w /usr/obj/usr/src/repo ] || atf_skip 'requires standard object repository fixture access'
    repository=/usr/obj/usr/src/repo/bsd-build-test-media-$$
    stage=/usr/obj/usr/src/bsd-build-test-media-$$
    [ ! -e "$repository" ] && [ ! -e "$stage" ] || atf_fail 'fixture paths exist'
    printf '%s\n' "$repository" > created-repository
    printf '%s\n' "$stage" > created-media
    mkdir "$repository" mock
    echo '{}' > "$repository/publication.json"
    echo 'mock public key' > public
    cat > mock/make <<'SCRIPT'
#!/bin/sh
printf '%s\n' "$*" >> "$BSD_BUILD_TEST_LOG"
case "$*" in
*host-tools.mk*)
    directory=$2
    printf '#!/bin/sh\nexit 0\n' > "$directory/capsign"
    chmod +x "$directory/capsign";;
*RELEASE_OBJDIR=*)
    for argument do
        case "$argument" in RELEASE_OBJDIR=*) directory=${argument#*=};; esac
    done
    printf 'mock ISO artifact\n' > "$directory/disc1.iso"
    printf 'mock memory-stick artifact\n' > "$directory/memstick.img";;
esac
SCRIPT
    chmod +x mock/make
    atf_check -s exit:0 -o save:out -e empty env PATH="$(pwd)/mock:$PATH" BSD_BUILD_TEST_LOG="$(pwd)/commands" \
        "$tool" media --repository "$repository" --pkg-public-key "$(pwd)/public" \
        --public-key "$(pwd)/public" --output "$stage"
    run=$(sed -n 's/^complete action=media logs=\([^ ]*\) output=.*/\1/p' out)
    printf '%s\n' "$run" > created-run
    atf_check -s exit:0 -o ignore grep 'PKGBASE_SIGNED_REPOSITORY=' commands
    atf_check -s exit:0 -o ignore grep 'NOPKGBASE= NODISTSETS=yes NOPKG=yes disc1.iso memstick.img' commands
    atf_check -s exit:1 -o empty grep 'buildworld\|buildkernel' commands
    atf_check -s exit:0 test -s "$stage/CHECKSUM.SHA256"
    atf_check -s exit:0 test -s "$stage/CHECKSUM.SHA512"
    atf_check -s exit:0 -o match:'complete action=media' -e empty "$tool" status "$run"
    for selection in amd64 arm64 riscv64; do
        atf_check -s exit:0 -o save:plan -e empty "$tool" plan media --arch "$selection" \
            --repository "$repository" --pkg-public-key "$(pwd)/public" --public-key "$(pwd)/public" --media-format iso
        atf_check -s exit:0 -o ignore grep '^media:.* disc1.iso$' plan
        atf_check -s exit:1 -o empty grep '^media:.*memstick.img' plan
    done
}
media_orchestration_cleanup()
{
    failure_stops_pipeline_cleanup
    if [ -f created-media ]; then
        path=$(cat created-media)
        case "$path" in /usr/obj/usr/src/bsd-build-test-media-*) rm -rf "$path";; esac
    fi
    if [ -f created-repository ]; then
        path=$(cat created-repository)
        case "$path" in /usr/obj/usr/src/repo/bsd-build-test-media-*) rm -rf "$path";; esac
    fi
}
atf_test_case publication_destination
publication_destination_body()
{
    setup
    destination=/var/db/5bsd/repositories/bsd-build-plan-only-$$
    atf_check -s exit:0 -o save:custom -e empty env PUBLISH_REPODIR=/home/incorrect "$tool" plan packages --publish-repository "$destination"
    atf_check -s exit:0 -o ignore grep "REPODIR=/usr/obj/usr/src/repo PUBLISH_REPODIR=$destination" custom
    atf_check -s exit:0 -o ignore grep 'PORTSDIR=/usr/obj/5BSD-ports' custom
    atf_check -s exit:1 -o empty grep /home/incorrect custom
    [ ! -e "$destination" ] || atf_fail 'plan created publication directory'
    printf 'publish_repository=%s\n' "$destination" > config
    atf_check -s exit:0 -o save:configured -e empty "$tool" plan packages --config config
    atf_check -s exit:0 -o ignore grep "PUBLISH_REPODIR=$destination" configured
    for invalid in relative /usr/src/repository /home/unsafe-repository; do
        atf_check -s not-exit:0 -o empty -e match:'publication destination' "$tool" plan packages --publish-repository "$invalid"
    done
    atf_check -s not-exit:0 -o empty -e ignore "$tool" plan stage --publish-repository "$destination"
}
atf_test_case cache_layout_constraints
cache_layout_constraints_body()
{
    setup
    atf_check -s exit:0 -o save:layout -e empty "$tool" plan stage --arch amd64 --signing development --cache --cache-layout
    atf_check -s exit:0 -o ignore grep 'CAPIMAGE_BUILD_CACHE=yes CAPIMAGE_BUILD_LAYOUT=yes' layout
    atf_check -s not-exit:0 -o empty -e match:'requires --cache' "$tool" plan stage --signing development --cache-layout
    atf_check -s not-exit:0 -o empty -e match:'requires development or signed' "$tool" plan stage --cache --cache-layout
    for arch in arm64 riscv64; do
        atf_check -s not-exit:0 -o empty -e match:'currently requires amd64' "$tool" plan stage --arch "$arch" --signing development --cache --cache-layout
    done
    printf 'arch=amd64\nsigning=development\ncache=yes\ncache_layout=yes\n' > config
    atf_check -s exit:0 -o save:configured -e empty "$tool" plan stage --config config
    atf_check -s exit:0 -o ignore grep 'CAPIMAGE_BUILD_LAYOUT=yes' configured
}
atf_test_case build_profiles
build_profiles_body()
{
    setup
    atf_check -s exit:0 -o save:debug -e empty "$tool" plan stage --build-profile debug
    atf_check -s exit:0 -o ignore grep 'DEBUG_FLAGS=-g WITHOUT_MALLOC_PRODUCTION=yes' debug
    atf_check -s not-exit:0 -o empty -e match:'requires --allow-debug-publication' "$tool" plan packages --build-profile debug
    atf_check -s exit:0 -o save:testpub -e empty "$tool" plan packages --build-profile debug --allow-debug-publication
    atf_check -s exit:0 -o ignore grep '^system-packages:.*ALLOW_DEBUG_MALLOC=yes WITHOUT_MALLOC_PRODUCTION=yes' testpub
    atf_check -s not-exit:0 -o empty -e match:'requires development/debug packages' "$tool" plan packages --allow-debug-publication
    atf_check -s not-exit:0 -o empty -e match:'must be production' "$tool" plan stage --build-profile typo
    printf 'build_profile=debug\n' > profile
    atf_check -s exit:0 -o save:override -e empty "$tool" plan packages --config profile --production
    atf_check -s exit:0 -o ignore grep WITH_MALLOC_PRODUCTION=yes override
    foreign=arm64
    [ "$(uname -p)" != aarch64 ] || foreign=amd64
    atf_check -s not-exit:0 -o empty -e match:'native hardware backend cannot publish' "$tool" plan packages --arch "$foreign"
}
atf_test_case boards
boards_body()
{
    setup
    for board in rpi4 rpi5 rpi-zero2w; do
        atf_check -s exit:0 -o save:plan -e empty "$tool" plan stage --board "$board"
        expected=GENERIC-RPI
        [ "$board" != rpi5 ] || expected=GENERIC
        atf_check -s exit:0 -o ignore grep "TARGET=arm64 TARGET_ARCH=aarch64 KERNCONF=$expected " plan
        atf_check -s exit:0 -o ignore grep "board=$board" plan
    done
    atf_check -s not-exit:0 -o empty -e match:'require arm64' "$tool" plan stage --board rpi4 --arch amd64
    atf_check -s not-exit:0 -o empty -e match:'board image backend is not integrated' "$tool" plan media --board rpi5
    atf_check -s not-exit:0 -o empty -e match:'--board must' "$tool" plan stage --board unknown
    printf 'board=rpi-zero2w\n' > config
    atf_check -s exit:0 -o save:plan -e empty "$tool" plan stage --config config --kernel CUSTOM-RPI
    atf_check -s exit:0 -o ignore grep 'KERNCONF=CUSTOM-RPI ' plan
}
atf_test_case hardware_inputs
hardware_inputs_body()
{
    setup
    printf 'graphics/drm-kmod\n' > hardware
    atf_check -s exit:0 -o save:plan -e empty "$tool" plan packages --hardware-profile "$(pwd)/hardware" --distfiles /usr/obj/usr/src/distfiles
    atf_check -s exit:0 -o ignore grep "HARDWARE_PORT_LIST=$(pwd)/hardware DISTDIR=/usr/obj/usr/src/distfiles" plan
    atf_check -s not-exit:0 -o empty -e match:'readable hardware profile' "$tool" plan packages --hardware-profile /nonexistent/profile
    atf_check -s not-exit:0 -o empty -e match:'ports checkout is missing' "$tool" plan packages --ports /nonexistent/ports
    atf_check -s not-exit:0 -o empty -e match:'must be absolute' "$tool" plan packages --distfiles relative
    atf_check -s not-exit:0 -o empty -e match:'apply only to build or packages' "$tool" plan stage --hardware-profile "$(pwd)/hardware"
}
atf_test_case json_plan
json_plan_head()
{
    atf_set require.progs python3.12
}
json_plan_body()
{
    setup
    atf_check -s exit:0 -o save:plan.jsonl -e empty "$tool" plan stage --format json --board rpi4 --build-profile debug --jobs 2
    atf_check -s exit:0 -o empty -e empty python3.12 -c '
import json
rows=[json.loads(line) for line in open("plan.jsonl")]
assert rows[0]["schema"]=="org.5bsd.build-plan.v1"
assert rows[0]["record"]=="request" and rows[0]["target_arch"]=="aarch64"
assert rows[0]["board"]=="rpi4" and rows[0]["build_profile"]=="debug"
assert rows[0]["jobs"]==2 and rows[0]["build_backend"]=="bsd-make"
steps=rows[1:]
assert [s["number"] for s in steps]==list(range(1,len(steps)+1))
assert all(s["record"]=="step" and isinstance(s["argv"],list) for s in steps)
world=next(s for s in steps if s["name"]=="buildworld")
assert "DEBUG_FLAGS=-g" in world["argv"] and "WITHOUT_MALLOC_PRODUCTION=yes" in world["argv"]
assert world["argv"][-1]=="buildworld"
'
    atf_check -s not-exit:0 -o empty -e match:'requires plan' "$tool" stage --format json
    atf_check -s not-exit:0 -o empty -e match:'must be text or json' "$tool" plan stage --format unknown
}
atf_init_test_cases()
{
    atf_add_test_case publication_destination
    atf_add_test_case cache_layout_constraints
    atf_add_test_case json_plan
    atf_add_test_case hardware_inputs
    atf_add_test_case boards
    atf_add_test_case build_profiles
    atf_add_test_case media_orchestration
    atf_add_test_case installer_lifecycle
    atf_add_test_case deploy_lifecycle
    atf_add_test_case architectures
    atf_add_test_case configuration
    atf_add_test_case plans
    atf_add_test_case make_clean_options
    atf_add_test_case invalid_options
    atf_add_test_case path_preflight
    atf_add_test_case failure_stops_pipeline
    atf_add_test_case successful_stage
}
