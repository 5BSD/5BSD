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
    atf_check -s exit:0 -o save:stage -e empty "$tool" plan stage --output "$output" --signing development
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
atf_test_case bootstrap_pkg_plan
bootstrap_pkg_plan_head()
{
    atf_set descr 'Bootstrap package inputs reach combined publication and require a pinned hash'
    atf_set require.progs python3.12
}
bootstrap_pkg_plan_body()
{
    setup
    printf 'archive-input-fixture\n' > bootstrap.pkg
    archive=$(pwd)/bootstrap.pkg
    digest=$(sha256 -q "$archive")
    atf_check -s exit:0 -o save:plan.jsonl -e empty "$tool" plan packages --pkg-package "$archive" --pkg-package-sha256 "$digest" --format json
    atf_check -s exit:0 -o empty -e empty python3.12 - "$archive" "$digest" <<'PYTHON'
import json, sys
rows = [json.loads(line) for line in open('plan.jsonl')]
publication = next(row for row in rows[1:] if row['name'] == 'system-packages')
assert 'PKGBASE_PKG_PACKAGE=' + sys.argv[1] in publication['argv']
assert 'PKGBASE_PKG_SHA256=' + sys.argv[2] in publication['argv']
assert 'REPODIR=/usr/obj/usr/src/repo' in publication['argv']
assert not any(row['name'] in ('deploy', 'media') for row in rows[1:])
PYTHON
    atf_check -s exit:0 -o save:backend -e empty make -C /usr/src -f release/Makefile.hardware -n publish-packages BASE_REPOSITORY=/usr/obj/base-plan HARDWARE_REPO=/usr/obj/hardware-plan COMPLETE_REPOSITORY=/usr/obj/complete-plan PKGBASE_PKG_PACKAGE="$archive" PKGBASE_PKG_SHA256="$digest"
    atf_check -s exit:0 -o ignore grep -- "--pkg-package $archive" backend
    atf_check -s exit:0 -o ignore grep -- "--pkg-package-sha256 $digest" backend
    atf_check -s not-exit:0 -o empty -e match:'64-digit' "$tool" plan packages --pkg-package "$archive"
    atf_check -s not-exit:0 -o empty -e match:'64-digit' "$tool" plan packages --pkg-package-sha256 "$digest"
    atf_check -s not-exit:0 -o empty -e match:'64-digit' "$tool" plan packages --pkg-package "$archive" --pkg-package-sha256 invalid
    atf_check -s not-exit:0 -o empty -e match:'only to build or packages' "$tool" plan world --pkg-package "$archive" --pkg-package-sha256 "$digest"
    printf 'pkg_package=%s\npkg_package_sha256=%s\n' "$archive" "$digest" > configured.conf
    atf_check -s exit:0 -o save:configured -e empty "$tool" plan build --config configured.conf
    atf_check -s exit:0 -o ignore grep -F "PKGBASE_PKG_PACKAGE=$archive" configured
    atf_check -s exit:0 -o ignore grep -F "PKGBASE_PKG_SHA256=$digest" configured
    cp bootstrap.pkg override.pkg
    atf_check -s exit:0 -o save:override -e empty "$tool" plan packages --config configured.conf --pkg-package "$(pwd)/override.pkg"
    atf_check -s exit:0 -o ignore grep -F "PKGBASE_PKG_PACKAGE=$(pwd)/override.pkg" override
    atf_check -s exit:0 -o save:ordinary -e empty "$tool" plan packages
    atf_check -s exit:1 -o empty grep PKGBASE_PKG_PACKAGE ordinary
    ln -s bootstrap.pkg link.pkg
    atf_check -s not-exit:0 -o empty -e match:'not a symlink' "$tool" plan packages --pkg-package "$(pwd)/link.pkg" --pkg-package-sha256 "$digest"
    for name in 'unsafe archive.pkg' 'make$input.pkg'; do
        cp bootstrap.pkg "$name"
        atf_check -s not-exit:0 -o empty -e match:'safe characters' "$tool" plan packages --pkg-package "$(pwd)/$name" --pkg-package-sha256 "$digest"
    done
}

atf_test_case package_tool_plan
package_tool_plan_body()
{
    setup
    cp /usr/bin/true pkg-tool
    package_tool=$(pwd)/pkg-tool
    atf_check -s exit:0 -o save:plan -e empty "$tool" plan packages --package-tool "$package_tool" --candidate-publication
    atf_check -s exit:0 -o ignore grep "system-packages:.*PKG_CMD=$package_tool" plan
    atf_check -s exit:0 -o ignore grep 'PUBLISH_ADVANCE_LATEST=no' plan
    atf_check -s not-exit:0 -o empty -e match:'only to build, packages or snapshot' "$tool" plan world --package-tool "$package_tool"
    chmod 600 pkg-tool
    atf_check -s not-exit:0 -o empty -e match:'must be executable' "$tool" plan packages --package-tool "$package_tool"
    chmod 700 pkg-tool
    ln -s pkg-tool pkg-link
    atf_check -s not-exit:0 -o empty -e match:'not a symlink' "$tool" plan packages --package-tool "$(pwd)/pkg-link"
    cp pkg-tool 'pkg tool'
    atf_check -s not-exit:0 -o empty -e match:'safe characters' "$tool" plan packages --package-tool "$(pwd)/pkg tool"
}

atf_test_case candidate_publication_plan
candidate_publication_plan_body()
{
    setup
    atf_check -s exit:0 -o save:candidate -e empty "$tool" plan packages --candidate-publication
    atf_check -s exit:0 -o ignore grep 'PUBLISH_ADVANCE_LATEST=no' candidate
    atf_check -s exit:0 -o ignore grep 'REPODIR=/usr/obj/usr/src/repo' candidate
    for stage in WSTAGEDIR KSTAGEDIR SSTAGEDIR; do
        atf_check -s exit:0 -o ignore grep -E "$stage=/usr/obj/usr/src/build-runs/[^ /]+/package-stage/" candidate
    done
    atf_check -s exit:0 -o save:fresh -e empty "$tool" plan packages --candidate-publication
    first_stage=$(sed -n 's/.*WSTAGEDIR=\([^ ]*\).*/\1/p' candidate)
    next_stage=$(sed -n 's/.*WSTAGEDIR=\([^ ]*\).*/\1/p' fresh)
    [ "$first_stage" != "$next_stage" ] || atf_fail "package executions reused a stage"
    atf_check -s exit:0 -o save:normal -e empty env PUBLISH_ADVANCE_LATEST=no "$tool" plan packages
    atf_check -s exit:0 -o ignore grep 'PUBLISH_ADVANCE_LATEST=yes' normal
    atf_check -s not-exit:0 -o empty -e match:'only to packages/build' "$tool" plan world --candidate-publication
    atf_check -s exit:0 -o save:backend -e empty make -C /usr/src -f release/Makefile.hardware -n publish-packages BASE_REPOSITORY=/usr/obj/base-plan HARDWARE_REPO=/usr/obj/hardware-plan COMPLETE_REPOSITORY=/usr/obj/candidate-plan PUBLISH_ADVANCE_LATEST=no
    atf_check -s exit:0 -o ignore grep -- '--no-latest' backend
    atf_check -s not-exit:0 -o ignore -e match:'must be yes or no' make -C /usr/src -f release/Makefile.hardware -n publish-packages PUBLISH_ADVANCE_LATEST=invalid
}

atf_test_case security_scope
security_scope_head()
{
    atf_set descr 'Signing plans never claim verified boot or compromised-root qualification'
    atf_set require.progs python3.12
}
security_scope_body()
{
    setup
    for mode in unsigned development; do
        atf_check -s exit:0 -o save:plan.jsonl -e empty "$tool" plan stage --signing "$mode" --format json
        atf_check -s exit:0 -o empty -e empty python3.12 - "$mode" <<'PYTHON'
import json, sys
request = json.loads(open('plan.jsonl').readline())
assert request['signing'] == sys.argv[1]
assert request['signing_scope'] == 'system-bundles'
assert request['verification_scope'] == 'system-bundles'
assert request['boot_verification'] == 'not-performed'
assert request['root_protection_verification'] == 'not-performed'
PYTHON
    done
    atf_check -s exit:0 -o match:'boot-verification=not-performed' -e empty "$tool" plan stage
    atf_check -s exit:0 -o match:'bundle-signing-mode=unsigned' -e empty "$tool" plan stage --signing unsigned
}
atf_test_case optional_integrity_profile
optional_integrity_profile_head()
{
    atf_set descr 'Signing preserves ordinary kernel defaults; explicit BIP profile selects the real policy object'
    atf_set require.progs python3.12
    atf_set require.arch amd64
}
optional_integrity_profile_body()
{
    setup
    kernel_config=$(atf_config_get kernel_config /usr/sbin/config)
    atf_check -s exit:0 -o ignore -e empty python3.12 - "$tool" "$kernel_config" <<'PYTHON'
import json, pathlib, subprocess, sys
frontend, config = sys.argv[1:]
for signing in ('unsigned', 'development'):
    for selected in (None, 'GENERIC-INTEGRITY'):
        command = [frontend, 'plan', 'stage', '--signing', signing, '--format', 'json',
                   '--src-conf', '/dev/null', '--make-conf', '/dev/null']
        if selected:
            command += ['--kernel', selected]
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        expected = selected or 'GENERIC'
        assert rows[0]['kernel'] == expected
        assert rows[0]['boot_verification'] == 'not-performed'
        assert rows[0]['root_protection_verification'] == 'not-performed'
        kernel = next(row for row in rows[1:] if row['name'] == 'buildkernel')
        assert 'KERNCONF=' + expected in kernel['argv']
for profile, enabled in (('GENERIC', False), ('GENERIC-INTEGRITY', True)):
    output = pathlib.Path(profile).resolve()
    subprocess.run([config, '-d', str(output), '-s', '/usr/src/sys', profile],
                   cwd='/usr/src/sys/amd64/conf', check=True, capture_output=True)
    options = (output / 'opt_system_integrity.h').read_text()
    makefile = (output / 'Makefile').read_text()
    assert ('#define MAC_SYSTEM_INTEGRITY 1' in options) == enabled
    assert ('mac_system_integrity.o' in makefile) == enabled
PYTHON
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
atf_test_case make_object_environment
make_object_environment_head()
{
    atf_set descr 'Generated build argv passes the real top-level make object-root validation'
    atf_set require.progs 'make python3.12'
}
make_object_environment_body()
{
    setup
    for operation in world kernel; do
        atf_check -s exit:0 -o save:plan.jsonl -e empty "$tool" plan "$operation" --format json --src-conf /dev/null --make-conf /dev/null
        atf_check -s exit:0 -o empty -e empty python3.12 - "$operation" <<'PYTHON'
import json, os, subprocess, sys
steps = [json.loads(line) for line in open('plan.jsonl')]
step = next(x for x in steps if x.get('name') == 'build' + sys.argv[1])
assert step['argv'][-1] == 'build' + sys.argv[1]
result = subprocess.run(step['argv'][:-1] + ['-V', 'OBJTOP'],
                        env=dict(os.environ, MAKEOBJDIRPREFIX='/home/incorrect'),
                        capture_output=True, text=True)
assert result.returncode == 0, result.stderr
lines = result.stdout.splitlines()
assert len(lines) == 1 and lines[0].startswith('/usr/obj/usr/src/'), lines
PYTHON
    done
}
atf_test_case invalid_options
invalid_options_body()
{
    setup
    atf_check -s not-exit:0 -o empty -e match:'applies only to media' "$tool" plan build --media-format iso
    atf_check -s not-exit:0 -o empty -e match:'applies only to build or packages' "$tool" plan verify --pkg-key /nonexistent/private.pem
    bad_key=$(printf '/tmp/key\nname')
    atf_check -s not-exit:0 -o empty -e match:'control characters' "$tool" plan stage --key "$bad_key"
    atf_check -s not-exit:0 -o empty -e match:'under /usr/obj' "$tool" plan stage --output /home/unsafe-stage
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
    atf_check -s exit:0 -o save:out -e empty env PATH="$(pwd)/mock:$PATH" BSD_BUILD_TEST_LOG="$(pwd)/commands" "$tool" stage --output "$stage" --signing development --relaxed-signatures
    sed 's/.* //' commands > targets
    printf '%s\n' SRCTOP=/usr/src buildworld buildkernel installworld distribution installkernel capimage-stage > expected
    atf_check -s exit:0 -o empty diff -u expected targets
    for target in installworld distribution installkernel capimage-stage; do
        atf_check -s exit:0 -o ignore grep "NO_ROOT=yes DESTDIR=$stage.*$target\$" commands
    done
    atf_check -s exit:0 -o ignore grep 'CAPIMAGE_SIGNING_MODE=development.*CAPIMAGE_REQUIRE_SIGNATURES=no' commands
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
    printf 'incremental=perhaps\n' > bad
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
atf_test_case package_closure
package_closure_head()
{
    atf_set require.progs 'python3.12'
    atf_set descr 'Selected package metadata must cover dependencies and libraries without conflicts'
}
package_closure_body()
{
    helper=$(atf_config_get closure_helper "$(atf_get_srcdir)/package_closure.py")
    tests=$(atf_config_get closure_tests "$(atf_get_srcdir)/package_closure_test.py")
    atf_check -s exit:0 -o ignore -e match:'OK' env BSD_BUILD_CLOSURE_HELPER="$helper" python3.12 "$tests"
}
atf_test_case package_inventory
package_inventory_head()
{
    atf_set require.progs 'python3.12'
    atf_set descr 'Package payload inventory follows actual archives and rejects ambiguous provenance'
}
package_inventory_body()
{
    helper=$(atf_config_get inventory_helper "$(atf_get_srcdir)/package_inventory.py")
    tests=$(atf_config_get inventory_tests "$(atf_get_srcdir)/package_inventory_test.py")
    atf_check -s exit:0 -o ignore -e match:'OK' env BSD_BUILD_INVENTORY_HELPER="$helper" python3.12 "$tests"
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
    atf_check -s exit:0 -o ignore grep 'host-tools.mk.* all kldxref' commands
    atf_check -s exit:0 -o ignore grep 'HARDWARE_KLDXREF=.*/native-tools/kldxref' commands
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
    printf 'graphics/drm-kmod\n' > hardware
    atf_check -s exit:0 -o save:custom -e empty env PUBLISH_REPODIR=/home/incorrect "$tool" plan packages --publish-repository "$destination" --hardware-profile "$(pwd)/hardware"
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
    printf 'graphics/drm-kmod\n' > hardware
    atf_check -s not-exit:0 -o empty -e match:'native hardware backend cannot publish' "$tool" plan packages --arch "$foreign" --hardware-profile "$(pwd)/hardware"
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
    # The hardware stage is told which backend this plan reported.
    atf_check -s exit:0 -o ignore grep '^system-packages:.* HARDWARE_BACKEND=native-ports PORTSDIR=' plan
    atf_check -s not-exit:0 -o empty -e match:'readable hardware profile: /nonexistent/profile' "$tool" plan packages --hardware-profile /nonexistent/profile
    atf_check -s exit:1 -o empty grep '^hardware:' plan
    atf_check -s not-exit:0 -o empty -e match:'ports checkout is missing' "$tool" plan packages --hardware-profile "$(pwd)/hardware" --ports /nonexistent/ports
    atf_check -s not-exit:0 -o empty -e match:'must be absolute' "$tool" plan packages --hardware-profile "$(pwd)/hardware" --distfiles relative
    atf_check -s not-exit:0 -o empty -e match:'apply only to build or packages' "$tool" plan stage --hardware-profile "$(pwd)/hardware"
}
atf_test_case kernel_identity_only
kernel_identity_only_head()
{
    atf_set require.progs python3.12
}
kernel_identity_only_body()
{
    setup
    foreign=arm64
    [ "$(uname -p)" != aarch64 ] || foreign=amd64
    # A profile without ports compiles nothing for the target, so it needs
    # neither a ports checkout nor a native builder; the plan says what it is.
    printf '# no hardware ports for this target yet\nno-hardware-ports # kernel identity only\n' > none
    for target in "--arch $foreign" ""; do
        atf_check -s exit:0 -o save:plan -e empty "$tool" plan packages $target --hardware-profile "$(pwd)/none" --ports /nonexistent/ports
        atf_check -s exit:0 -o ignore grep -x 'hardware: backend=kernel-identity-only hardware-packages=none hardware-compilation=not-performed' plan
        atf_check -s exit:0 -o ignore grep -x 'security: verification-scope=system-bundles boot-verification=not-performed root-protection-verification=not-performed' plan
        atf_check -s exit:0 -o ignore grep "^system-packages:.* HARDWARE_BACKEND=kernel-identity-only HARDWARE_PORT_LIST=$(pwd)/none REPODIR=/usr/obj/usr/src/repo .* system-packages\$" plan
        atf_check -s exit:0 -o ignore grep '^buildworld:.* WITH_MALLOC_PRODUCTION=yes ' plan
        atf_check -s exit:1 -o empty grep -E 'PORTSDIR=|DISTDIR=|nonexistent' plan
    done
    atf_check -s exit:0 -o ignore grep "^system-packages:.* TARGET_ARCH=$(uname -p) " plan
    atf_check -s exit:0 -o save:plan.jsonl -e empty "$tool" plan packages --arch "$foreign" --hardware-profile "$(pwd)/none" --format json
    atf_check -s exit:0 -o empty -e empty python3.12 -c '
import json
rows=[json.loads(line) for line in open("plan.jsonl")]
assert rows[0]["record"]=="request" and rows[0]["hardware_backend"]=="kernel-identity-only"
assert rows[0]["boot_verification"]=="not-performed"
assert rows[0]["root_protection_verification"]=="not-performed"
packages=next(s for s in rows[1:] if s["name"]=="system-packages")
assert not any(a.startswith(("PORTSDIR=","DISTDIR=")) for a in packages["argv"])
'
    printf 'graphics/drm-kmod\n' > hardware
    atf_check -s exit:0 -o save:plan.jsonl -e empty "$tool" plan packages --hardware-profile "$(pwd)/hardware" --format json
    atf_check -s exit:0 -o ignore grep '"record":"request".*"hardware_backend":"native-ports"' plan.jsonl
    # The entry cannot be combined with ports to pass a foreign target.
    printf 'no-hardware-ports\ngraphics/drm-kmod\n' > mixed
    atf_check -s not-exit:0 -o empty -e match:'must be the only hardware profile entry' "$tool" plan packages --arch "$foreign" --hardware-profile "$(pwd)/mixed"
    atf_check -s not-exit:0 -o empty -e match:'must be the only hardware profile entry' "$tool" plan packages --hardware-profile "$(pwd)/mixed"
    # An empty profile selects nothing and is refused for any target.
    printf '# nothing\n' > empty
    atf_check -s not-exit:0 -o empty -e match:'empty hardware profile' "$tool" plan packages --arch "$foreign" --hardware-profile "$(pwd)/empty"
    atf_check -s not-exit:0 -o empty -e match:'empty hardware profile' "$tool" plan packages --hardware-profile "$(pwd)/empty"
    # The maintained arm64 profile has no ports, so a cross builder plans it
    # by default; a target without a maintained profile is told which file.
    if [ "$(uname -p)" != aarch64 ]; then
        atf_check -s exit:0 -o save:plan -e empty "$tool" plan packages --arch arm64
        atf_check -s exit:0 -o ignore grep '^hardware: backend=kernel-identity-only ' plan
        atf_check -s exit:0 -o ignore grep '^system-packages:.* HARDWARE_PORT_LIST=[^ ]*/release/tools/hardware-ports.aarch64 ' plan
    fi
    atf_check -s not-exit:0 -o empty -e match:'readable hardware profile: .*/release/tools/hardware-ports.riscv64$' "$tool" plan packages --arch riscv64
}
atf_test_case hardware_profile_grammar
hardware_profile_grammar_body()
{
    setup
    foreign=arm64
    [ "$(uname -p)" != aarch64 ] || foreign=amd64
    cases=$(atf_config_get hardware_profile_cases "$(atf_get_srcdir)/hardware-profile-cases")
    # release/tests/hardware_packages_test.py gives the same cases to the
    # hardware stage, so the plan and the stage read every profile alike.  A
    # foreign target tells the three outcomes apart without a ports checkout.
    count=0
    while read -r outcome profile <&3; do
        case "$outcome" in ''|'#'*) continue;; esac
        echo "profile case: $outcome $profile"
        printf "$profile" > profile
        case "$outcome" in
        none) atf_check -s exit:0 -o match:'^hardware: backend=kernel-identity-only ' -e empty "$tool" plan packages --arch "$foreign" --hardware-profile "$(pwd)/profile";;
        ports) atf_check -s not-exit:0 -o empty -e match:'cannot publish a foreign target' "$tool" plan packages --arch "$foreign" --hardware-profile "$(pwd)/profile";;
        refuse) atf_check -s not-exit:0 -o empty -e match:'empty hardware profile|must be the only hardware profile entry|hardware profile must be ASCII text|invalid port in hardware profile' "$tool" plan packages --arch "$foreign" --hardware-profile "$(pwd)/profile";;
        *) atf_fail "unknown outcome: $outcome";;
        esac
        count=$((count+1))
    done 3< "$cases"
    [ "$count" -ge 50 ] || atf_fail "only $count profile cases were read"
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

atf_test_case retired_bip_options
retired_bip_options_body()
{
    setup
    for option in storage-disk storage-policy filesystem-policy session-policy storage-principal-a storage-principal-b storage-principal-denied provider-crash provider-lifecycle filesystem-policy-destination; do
        atf_check -s exit:64 -o empty -e match:'usage: build-bsd' \
            "$tool" plan secureboot-test "--$option" unused
        printf '%s=unused\n' "$option" > retired.conf
        atf_check -s exit:64 -o empty -e match:"unknown config setting: $option" \
            "$tool" plan secureboot-test --config "$PWD/retired.conf"
    done
}

atf_test_case secureboot_generation_plan
secureboot_generation_plan_body()
{
    setup
    root=$(atf_config_get secureboot_root '')
    vars=$(atf_config_get uefi_vars_tool /usr/local/bin/virt-fw-vars)
    [ -f "$root/boot/kernel/kernel" ] || atf_skip 'requires a qualification root'
    [ -x "$vars" ] || atf_skip 'requires virt-fw-vars'
    output=/usr/obj/usr/src/secureboot-generation-plan-$$
    printf 'private plan fixture\n' > generation.key
    chmod 600 generation.key
    printf 'public plan fixture\n' > generation.crt
    atf_check -s exit:0 -o save:generation-plan.jsonl -e empty "$tool" plan secureboot-test --root "$root" --uefi-vars-tool "$vars" --output "$output" --test-case approved --test-generation-key "$PWD/generation.key" --test-generation-certificate "$PWD/generation.crt" --format json
    atf_check -s exit:0 -o empty -e empty /usr/local/bin/python3.12 -c '
import json, pathlib
rows=[json.loads(x) for x in open("generation-plan.jsonl")]
key=str(pathlib.Path("generation.key").resolve())
cert=str(pathlib.Path("generation.crt").resolve())
for name in ("secureboot-loader-clean", "secureboot-loader"):
    argv=next(s["argv"] for s in rows[1:] if s["name"] == name)
    assert "WITHOUT_LOADER_EFI_TRUST_DB=yes" in argv
    assert "TRUST_ANCHORS=" + cert in argv
    assert all(key not in x for x in argv)
vm=next(s["argv"] for s in rows[1:] if s["name"] == "secureboot-vm")
assert vm[vm.index("--generation-key") + 1] == key
assert vm[vm.index("--generation-certificate") + 1] == cert
assert "--require-complete" not in rows[-1]["argv"]
'
    atf_check -s not-exit:0 -o empty -e match:'both key and certificate' "$tool" plan secureboot-test --root "$root" --test-generation-key "$PWD/generation.key"
    atf_check -s not-exit:0 -o empty -e match:'requires secureboot-test' "$tool" plan kernel --test-generation-key "$PWD/generation.key" --test-generation-certificate "$PWD/generation.crt"
    atf_check -s not-exit:0 -o empty -e match:'explicit case independent' "$tool" plan secureboot-test --root "$root" --test-generation-key "$PWD/generation.key" --test-generation-certificate "$PWD/generation.crt"
    for testcase in firmware-signed-manifest revoked-generation-manifest; do
        atf_check -s not-exit:0 -o empty -e match:'require explicit generation' "$tool" plan secureboot-test --root "$root" --test-case "$testcase"
        atf_check -s exit:0 -o save:"$testcase.jsonl" -e empty "$tool" plan secureboot-test --root "$root" --uefi-vars-tool "$vars" --test-case "$testcase" --test-generation-key "$PWD/generation.key" --test-generation-certificate "$PWD/generation.crt" --format json
        atf_check -s exit:0 -o empty -e empty /usr/local/bin/python3.12 -c '
import json, sys
rows=[json.loads(x) for x in open(sys.argv[1] + ".jsonl")]
vm=next(s["argv"] for s in rows[1:] if s["name"] == "secureboot-vm")
assert vm[vm.index("--case") + 1] == sys.argv[1]
assert "--generation-key" in vm and "--generation-certificate" in vm
' "$testcase"
    done
    for testcase in second-db-cert second-dbx-cert second-dbx-hash; do
        atf_check -s not-exit:0 -o empty -e match:'explicit case independent' "$tool" plan secureboot-test --root "$root" --test-case "$testcase" --test-generation-key "$PWD/generation.key" --test-generation-certificate "$PWD/generation.crt"
    done
}

atf_test_case secureboot_plan
secureboot_plan_head()
{
    atf_set descr 'Secure Boot qualification is explicit, isolated and has no publication steps'
    atf_set require.progs python3.12
}
secureboot_plan_body()
{
    setup
    root=$(atf_config_get secureboot_root '')
    vars=$(atf_config_get uefi_vars_tool /usr/local/bin/virt-fw-vars)
    [ -f "$root/boot/kernel/kernel" ] || atf_skip 'requires a qualification root'
    [ -x "$vars" ] || atf_skip 'requires virt-fw-vars'
    output=/usr/obj/usr/src/secureboot-plan-$$
    atf_check -s exit:0 -o save:plan.jsonl -e empty "$tool" plan secureboot-test --root "$root" --uefi-vars-tool "$vars" --output "$output" --format json
    [ ! -e "$output" ] || atf_fail 'plan created a qualification output'
    atf_check -s exit:0 -o empty -e empty python3.12 - <<'PYTHON'
import json
rows = [json.loads(line) for line in open('plan.jsonl')]
assert rows[0]['verification_scope'] == 'uefi-and-loader'
assert rows[0]['boot_verification'] == 'qemu-qualification-requested'
assert rows[0]['root_protection_verification'] == 'not-performed'
assert rows[0]['system_image_verification'] == 'qemu-qualification-requested'
assert rows[0]['bootstrap_integrity_verification'] == 'kernel-dependent'
assert rows[0]['program_compatibility_verification'] == 'bounded-vm-fixture-requested'
assert [s['name'] for s in rows[1:]] == ['secureboot-loader-clean', 'secureboot-loader', 'secureboot-bootstrap', 'secureboot-fixture', 'secureboot-parser', 'secureboot-host-tools-directory', 'secureboot-host-tools', 'secureboot-staging-growth', 'secureboot-vm', 'secureboot-evidence']
assert rows[-1]['argv'][1:] == ['/usr/src/tools/test/secureboot/verify_evidence.py', '--work', rows[-2]['argv'][rows[-2]['argv'].index('--work') + 1], '--require-complete']
assert rows[-3]['argv'] == ['/usr/local/bin/python3.12', '/usr/src/tools/test/secureboot/efi_staging_test.py']
assert rows[2]['argv'][-1] == 'efi-loader'
assert 'WITH_LOADER_EFI_SECUREBOOT=yes' in rows[2]['argv']
prefix = next(a.split('=', 1)[1] for a in rows[2]['argv'] if a.startswith('MAKEOBJDIRPREFIX='))
assert prefix.startswith('/usr/obj/usr/src/build-runs/') and prefix.endswith('/secureboot-obj')
assert 'MAKEOBJDIRPREFIX=' + prefix in rows[1]['argv']
loader_objtop = prefix + '/usr/src/amd64.amd64'
assert rows[4]['argv'][5] == 'buildenv'
fixture_build = next(a for a in rows[4]['argv'] if a.startswith('BUILDENV_SHELL='))
assert fixture_build.startswith('BUILDENV_SHELL=make -C /usr/src/tools/test/secureboot -j')
assert (' SECUREBOOT_OBJTOP=' + loader_objtop + ' all') in fixture_build
assert rows[-2]['argv'][rows[-2]['argv'].index('--loader') + 1] == loader_objtop + '/stand/efi/loader_lua/loader_lua.efi'
# Ask BSD make itself where the selected prefix puts loader objects. Disable
# automatic directory creation for this plan-only assertion.
import subprocess
actual = subprocess.check_output(rows[2]['argv'][:-1] + ['WITHOUT_AUTO_OBJ=yes', '-V', 'OBJTOP'], text=True)
assert actual.strip() == loader_objtop, actual
assert rows[3]['argv'][5] == 'buildenv'
assert any(a.startswith('BUILDENV_SHELL=sh /usr/src/tools/test/secureboot/build-bootstrap.sh /usr/src ') for a in rows[3]['argv'])
assert '--vars-tool' in rows[-2]['argv']
assert '--capsign' in rows[-2]['argv']
assert '--pwd-mkdb' not in rows[-2]['argv']
host_tools = next(s['argv'] for s in rows[1:] if s['name'] == 'secureboot-host-tools')
assert 'pwd_mkdb' not in host_tools
assert 'host-tools.mk' in next(a for a in host_tools if a.endswith('host-tools.mk'))
assert rows[-2]['argv'][-2:] == ['--startup-policy', '/usr/src/stand/lua/secureboot.lua']
assert not any('publish-packages' in s['argv'] for s in rows[1:])
PYTHON
    atf_check -s not-exit:0 -o empty -e match:'one runner case name' "$tool" plan secureboot-test --root "$root" --uefi-vars-tool "$vars" --test-case '../bad'
    atf_check -s not-exit:0 -o empty -e match:'apply only to secureboot-test' "$tool" plan kernel --test-case approved
    atf_check -s not-exit:0 -o empty -e match:'requires --root' "$tool" plan secureboot-test
    atf_check -s not-exit:0 -o empty -e match:'always rebuilds' "$tool" plan secureboot-test --root "$root" --uefi-vars-tool "$vars" --incremental
    atf_check -s not-exit:0 -o empty -e match:'apply only to secureboot-test' "$tool" plan kernel --qemu /usr/bin/true
}
atf_test_case deployment_reconciliation_plan
deployment_reconciliation_plan_body()
{
    setup
    mkdir repository
    printf '{}' > repository/publication.json
    printf 'public fixture\n' > public
    printf '{"format":1,"entries":{}}\n' > generated.json
    atf_check -s not-exit:0 -o empty -e match:'deploy requires --generated' "$tool" plan deploy --root "$(pwd)/candidate" --repository "$(pwd)/repository" --pkg-public-key "$(pwd)/public" --public-key "$(pwd)/public"
    atf_check -s exit:0 -o save:plan.jsonl -e empty "$tool" plan deploy --root "$(pwd)/candidate" --repository "$(pwd)/repository" --pkg-public-key "$(pwd)/public" --public-key "$(pwd)/public" --generated "$(pwd)/generated.json" --format json
    atf_check -s exit:0 -o empty -e empty python3.12 - <<'PYTHON'
import json
rows = [json.loads(line) for line in open('plan.jsonl')]
assert rows[0]['verification_scope'] == 'packages-bundles-and-filesystem'
assert rows[0]['boot_verification'] == 'not-performed'
assert rows[0]['root_protection_verification'] == 'not-performed'
step = next(row for row in rows[1:] if row['name'] == 'deploy')
assert '--generated' in step['argv']
assert '--inventory' not in step['argv']
PYTHON
    [ ! -e candidate ] || atf_fail 'plan created the deployment target'
    atf_check -s not-exit:0 -o empty -e match:'derives inventory' "$tool" plan deploy --root "$(pwd)/candidate" --repository "$(pwd)/repository" --pkg-public-key "$(pwd)/public" --public-key "$(pwd)/public" --generated "$(pwd)/generated.json" --inventory "$(pwd)/generated.json"
}
atf_test_case generation_reconciliation
generation_reconciliation_head()
{
    atf_set require.progs 'python3.12 setextattr setfacl cc elfctl'
    atf_set descr 'Offline generation reconciliation rejects unexplained objects and metadata changes'
}
generation_reconciliation_body()
{
    helper=$(atf_config_get generation_helper "$(atf_get_srcdir)/generation_check.py")
    tests=$(atf_config_get generation_tests "$(atf_get_srcdir)/generation_check_test.py")
    elfctl=$(atf_config_get elfctl elfctl)
    atf_check -s exit:0 -o ignore -e match:'OK' env BSD_BUILD_GENERATION_HELPER="$helper" BSD_BUILD_ELFCTL="$elfctl" python3.12 -B "$tests"
}
atf_test_case inventory_plan
inventory_plan_head()
{
    atf_set descr 'Explicit package inventory plan preserves inputs and performs no writes'
    atf_set require.progs 'python3.12'
}
inventory_plan_body()
{
    setup
    printf '{}' > selection.json
    output=/usr/obj/usr/src/inventory-plan-$$
    [ ! -e "$output" ] || atf_fail 'test output already exists'
    atf_check -s exit:0 -o save:plan.jsonl -e empty "$tool" plan inventory --package-selection "$PWD/selection.json" --output "$output" --format json
    [ ! -e "$output" ] || atf_fail 'plan created output'
    atf_check -s exit:0 -o empty -e empty python3.12 - "$PWD/selection.json" "$output" <<'PYTHON'
import json, sys
rows = [json.loads(line) for line in open('plan.jsonl')]
assert rows[0]['verification_scope'] == 'package-payload-inventory'
assert [row['name'] for row in rows[1:]] == ['inventory-parent', 'inventory-directory', 'inventory']
assert rows[-1]['argv'][1:] == ['/usr/src/tools/build/capimage/package_inventory.py', '--selection', sys.argv[1], '--output', sys.argv[2] + '/inventory.json']
PYTHON
    atf_check -s not-exit:0 -o empty -e ignore "$tool" plan inventory --output "$output"
    atf_check -s not-exit:0 -o empty -e ignore "$tool" plan inventory --package-selection "$PWD/selection.json" --inventory "$PWD/selection.json" --output "$output"
    atf_check -s not-exit:0 -o empty -e ignore "$tool" plan inventory --package-selection "$PWD/selection.json" --signing development --output "$output"
    atf_check -s not-exit:0 -o empty -e ignore "$tool" plan inventory --package-selection "$PWD/selection.json" --root "$PWD" --output "$output"
}

atf_test_case inventory_audit
inventory_audit_head()
{
    atf_set require.progs python3.12
    atf_set descr 'Package review exposes coverage gaps and binds reports to explicit inventory bytes'
}
inventory_audit_body()
{
    atf_check -s exit:0 -o ignore -e match:'OK' python3.12 -B "$(atf_get_srcdir)/inventory_audit_test.py"
}
atf_test_case inventory_audit_plan
inventory_audit_plan_head()
{
    atf_set require.progs python3.12
    atf_set descr 'Package review plans preserve explicit inputs and do not claim qualification'
}
inventory_audit_plan_body()
{
    setup
    printf '{}' > inventory.json
    output=/usr/obj/usr/src/inventory-audit-plan-$$
    [ ! -e "$output" ] || atf_fail 'test output already exists'
    atf_check -s exit:0 -o save:plan.jsonl -e empty "$tool" plan inventory-audit --inventory "$PWD/inventory.json" --output "$output" --format json
    [ ! -e "$output" ] || atf_fail 'plan created output'
    atf_check -s exit:0 -o empty -e empty python3.12 - "$PWD/inventory.json" "$output" <<'PYTHON'
import json, sys
rows = [json.loads(line) for line in open('plan.jsonl')]
assert rows[0]['verification_scope'] == 'selected-package-review-inventory'
for key in ('boot_verification', 'root_protection_verification', 'program_compatibility_verification'):
    assert rows[0][key] == 'not-performed'
assert [row['name'] for row in rows[1:]] == ['audit-parent', 'audit-directory', 'inventory-audit']
assert rows[-1]['argv'][1:] == ['/usr/src/tools/build/capimage/inventory_audit.py', '--inventory', sys.argv[1], '--output', sys.argv[2] + '/inventory-review.json']
PYTHON
    atf_check -s not-exit:0 -o empty -e ignore "$tool" plan inventory-audit --output "$output"
    atf_check -s not-exit:0 -o empty -e ignore "$tool" plan inventory-audit --inventory "$PWD/inventory.json" --generated "$PWD/inventory.json" --output "$output"
    atf_check -s not-exit:0 -o empty -e ignore "$tool" plan inventory-audit --inventory "$PWD/inventory.json" --signing development --output "$output"
    atf_check -s not-exit:0 -o empty -e ignore "$tool" plan inventory-audit --inventory "$PWD/inventory.json" --root "$PWD" --output "$output"
}
atf_test_case reconciliation_plan
reconciliation_plan_body()
{
    setup
    mkdir root
    printf '{}' > inventory.json
    printf '{}' > generated.json
    output=/usr/obj/usr/src/reconciliation-plan-$$
    atf_check -s exit:0 -o save:plan.jsonl -e empty "$tool" plan reconcile --root "$(pwd)/root" --inventory "$(pwd)/inventory.json" --generated "$(pwd)/generated.json" --output "$output" --format json
    [ ! -e "$output" ] || atf_fail 'plan created output'
    atf_check -s exit:0 -o empty -e empty python3.12 - <<'PYTHON'
import json
rows = [json.loads(line) for line in open('plan.jsonl')]
assert rows[0]['verification_scope'] == 'offline-filesystem-reconciliation'
assert rows[0]['boot_verification'] == 'not-performed'
assert rows[0]['root_protection_verification'] == 'not-performed'
assert [row['name'] for row in rows[1:]] == ['reconcile']
assert rows[1]['argv'][1] == '/usr/src/tools/build/capimage/generation_check.py'
assert '--inventory' in rows[1]['argv'] and '--generated' in rows[1]['argv']
PYTHON
    printf '{"format":1,"boundaries":[]}' > layout.json
    atf_check -s exit:0 -o save:layout-plan.jsonl -e empty "$tool" plan reconcile --root "$PWD/root" --inventory "$PWD/inventory.json" --generated "$PWD/generated.json" --storage-layout-policy "$PWD/layout.json" --output "$output" --format json
    atf_check -s exit:0 -o empty -e empty python3.12 - <<'PYTHON'
import json, os
rows = [json.loads(line) for line in open('layout-plan.jsonl')]
assert rows[1]['argv'][-2:] == ['--storage-layout-policy', os.path.realpath('layout.json')]
PYTHON
    atf_check -s not-exit:0 -o empty -e match:'applies only to reconcile' "$tool" plan kernel --storage-layout-policy "$PWD/layout.json"
    atf_check -s not-exit:0 -o empty -e match:'applies only to reconcile' "$tool" plan kernel --inventory "$(pwd)/inventory.json"
    atf_check -s not-exit:0 -o empty -e match:'alternate root' "$tool" plan reconcile --root / --inventory "$(pwd)/inventory.json" --generated "$(pwd)/generated.json"
}
atf_test_case construction_execution
construction_execution_head()
{
    atf_set require.progs python3.12
    atf_set descr 'Construction receipts reject undeclared changes; jail calls are mocked here'
}
construction_execution_body()
{
    helper=$(atf_config_get construction_helper "$(atf_get_srcdir)/construction.py")
    tests=$(atf_config_get construction_tests "$(atf_get_srcdir)/construction_test.py")
    atf_check -s exit:0 -o ignore -e match:'OK' env BSD_BUILD_CONSTRUCTION_HELPER="$helper" python3.12 "$tests"
}
atf_test_case loader_build_configuration
loader_build_configuration_head()
{
    atf_set descr 'Loader build configuration is derived from the source tree'
    atf_set require.progs python3.12
}
loader_build_configuration_body()
{
    atf_check -s exit:0 -o save:configuration.json -e empty python3.12 -B \
        "$(atf_get_srcdir)/loader_build_test.py" --src "$(atf_config_get src /usr/src)"
    atf_check -s exit:0 -o empty -e empty python3.12 - <<'PYTHON'
import json
record = json.load(open('configuration.json'))
assert record['result'] == 'PASS'
assert record['packaged_loader_qualified'] is False
assert record['firmware_qualified'] is False
PYTHON
}

atf_test_case boot_transport
boot_transport_head()
{
    atf_set descr 'Complete boot transport, signing and GPT payload checks'
    atf_set require.progs 'python3.12 openssl'
    atf_set timeout 120
}
boot_transport_body()
{
    helpers=$(atf_config_get boot_helpers "$(atf_get_srcdir)")
    tests=$(atf_config_get boot_tests "$(atf_get_srcdir)/generation_boot_test.py")
    makefs=$(atf_config_get boot_makefs /usr/sbin/makefs)
    mkimg=$(atf_config_get boot_mkimg /usr/bin/mkimg)
    loader=$(atf_config_get boot_efi_fixture /boot/loader.efi)
    signer=$(atf_config_get boot_uefisign /usr/sbin/uefisign)
    [ -x "$makefs" ] || atf_skip 'selected makefs unavailable'
    [ -x "$mkimg" ] || atf_skip 'selected mkimg unavailable'
    [ -f "$loader" ] || atf_skip 'selected EFI fixture unavailable'
    [ -x "$signer" ] || atf_skip 'selected uefisign unavailable'
    atf_check -s exit:0 -o empty -e match:'OK' env BSD_BUILD_HELPERS="$helpers" \
        BSD_BUILD_MAKEFS="$makefs" BSD_BUILD_MKIMG="$mkimg" BSD_BUILD_EFI_FIXTURE="$loader" \
        BSD_BUILD_UEFISIGN="$signer" python3.12 -B "$tests"
}

atf_test_case boot_check_plan
boot_check_plan_body()
{
    setup
    printf '{}' > receipt.json
    printf 'image' > image.ufs
    printf 'archive' > boot.tar
    atf_check -s exit:0 -o save:verity-plan -e empty "$tool" plan boot-check --boot-image "$(pwd)/image.ufs" --boot-archive "$(pwd)/boot.tar" --image-receipt "$(pwd)/receipt.json" --boot-policy "$(pwd)/receipt.json" --boot-verity-image "$(pwd)/image.ufs" --boot-verity-descriptor "$(pwd)/receipt.json"
    atf_check -s exit:0 -o save:verity-stage-plan -e empty "$tool" plan boot-stage --boot-image "$(pwd)/image.ufs" --boot-archive "$(pwd)/boot.tar" --image-receipt "$(pwd)/receipt.json" --boot-policy "$(pwd)/receipt.json" --boot-verity-image "$(pwd)/image.ufs" --boot-verity-descriptor "$(pwd)/receipt.json" --output "/usr/obj/usr/src/verity-stage-plan-only-$$"
    atf_check -s exit:0 -o ignore grep -- "--verity-image $(pwd)/image.ufs --verity-descriptor $(pwd)/receipt.json" verity-plan
    atf_check -s not-exit:0 -o empty -e match:'both image and descriptor' "$tool" plan boot-check --boot-image "$(pwd)/image.ufs" --boot-archive "$(pwd)/boot.tar" --image-receipt "$(pwd)/receipt.json" --boot-verity-image "$(pwd)/image.ufs"
    atf_check -s exit:0 -o save:plan.jsonl -e empty "$tool" plan boot-check --boot-image "$(pwd)/image.ufs" --boot-archive "$(pwd)/boot.tar" --image-receipt "$(pwd)/receipt.json" --format json
    atf_check -s exit:0 -o empty -e empty python3.12 - <<'PYTHON'
import json
rows = [json.loads(line) for line in open('plan.jsonl')]
assert rows[0]['verification_scope'] == 'collected-boot-transport-consistency'
assert rows[0]['boot_verification'] == 'not-performed'
assert len(rows) == 2 and rows[1]['name'] == 'boot-check'
assert rows[1]['argv'][1] == '/usr/src/tools/build/capimage/generation_boot.py'
assert '--image-receipt' in rows[1]['argv']
PYTHON
    atf_check -s not-exit:0 -o empty -e match:'require image' "$tool" plan boot-check
    atf_check -s not-exit:0 -o empty -e match:'only to boot-check' "$tool" plan kernel --boot-archive "$(pwd)/boot.tar"
    output=/usr/obj/usr/src/boot-stage-plan-$$
    atf_check -s exit:0 -o save:stage.jsonl -e empty "$tool" plan boot-stage --boot-image "$(pwd)/image.ufs" --boot-archive "$(pwd)/boot.tar" --image-receipt "$(pwd)/receipt.json" --output "$output" --format json
    [ ! -e "$output" ] || atf_fail 'boot-stage plan created output'
    atf_check -s exit:0 -o save:generated-plan -e empty "$tool" plan boot-stage --boot-image "$(pwd)/image.ufs" --boot-archive "$(pwd)/boot.tar" --image-receipt "$(pwd)/receipt.json" --output "$output" --boot-generated "$(pwd)/receipt.json"
    atf_check -s exit:0 -o ignore grep -- "--generated $(pwd)/receipt.json" generated-plan
    atf_check -s not-exit:0 -o empty -e match:'only to boot-stage' "$tool" plan kernel --boot-generated "$(pwd)/receipt.json"
    atf_check -s not-exit:0 -o empty -e match:'boot-root-path requires boot-stage' "$tool" plan kernel --boot-root-path /boot/root.ufs
    cp receipt.json private.key
    chmod 600 private.key
    atf_check -s exit:0 -o save:signed-plan -e empty "$tool" plan boot-stage --boot-image "$(pwd)/image.ufs" --boot-archive "$(pwd)/boot.tar" --image-receipt "$(pwd)/receipt.json" --output "$output" --boot-generated "$(pwd)/receipt.json" --boot-policy "$(pwd)/receipt.json" --boot-signing-key "$(pwd)/private.key" --boot-signing-certificate "$(pwd)/receipt.json" --boot-openssl /usr/bin/openssl --boot-efi-path /boot/loader.efi --boot-efi-signer /usr/sbin/uefisign --boot-efi-signature-verifier /usr/bin/true --boot-loader-build "$PWD/receipt.json" --boot-loader-build-sha256 "$(sha256 -q receipt.json)" --boot-manifest-verifier /usr/bin/true --boot-media-makefs /usr/sbin/makefs --boot-media-mkimg /usr/bin/mkimg --boot-efi-fallback BOOTX64.EFI --boot-esp-mib 32 --boot-free-percent 5 --boot-root-path /boot/selected-root.ufs
    atf_check -s exit:0 -o ignore grep -- "--signing-key $(pwd)/private.key --signing-certificate $(pwd)/receipt.json --openssl /usr/bin/openssl" signed-plan
    atf_check -s not-exit:0 -o empty -e match:'signing requires' "$tool" plan kernel --boot-signing-key "$(pwd)/private.key"
    atf_check -s exit:0 -o ignore grep -- '--efi-path /boot/loader.efi --efi-signer /usr/sbin/uefisign' signed-plan
    atf_check -s exit:0 -o ignore grep -- "--loader-build-receipt $PWD/receipt.json --loader-build-sha256 $(sha256 -q receipt.json)" signed-plan
    atf_check -s exit:0 -o ignore grep -- '--manifest-verifier /usr/bin/true' signed-plan
    atf_check -s exit:0 -o ignore grep -- '--efi-signature-verifier /usr/bin/true' signed-plan
    atf_check -s not-exit:0 -o empty -e match:'EFI signing requires' "$tool" plan kernel --boot-efi-path /boot/loader.efi
    cp private.key efi-private.key
    atf_check -s exit:0 -o save:separate-plan -e empty "$tool" plan boot-stage --boot-image "$(pwd)/image.ufs" --boot-archive "$(pwd)/boot.tar" --image-receipt "$(pwd)/receipt.json" --output "$output" --boot-generated "$(pwd)/receipt.json" --boot-policy "$(pwd)/receipt.json" --boot-signing-key "$(pwd)/private.key" --boot-signing-certificate "$(pwd)/receipt.json" --boot-openssl /usr/bin/openssl --boot-efi-path /boot/loader.efi --boot-efi-signer /usr/sbin/uefisign --boot-efi-signature-verifier /usr/bin/true --boot-loader-build "$PWD/receipt.json" --boot-loader-build-sha256 "$(sha256 -q receipt.json)" --boot-manifest-verifier /usr/bin/true --boot-efi-signing-key "$(pwd)/efi-private.key" --boot-efi-signing-certificate "$(pwd)/receipt.json"
    atf_check -s exit:0 -o ignore grep -- "--efi-signing-key $(pwd)/efi-private.key --efi-signing-certificate $(pwd)/receipt.json" separate-plan
    atf_check -s not-exit:0 -o empty -e match:'separate EFI signing requires' "$tool" plan kernel --boot-efi-signing-key "$(pwd)/efi-private.key"
    atf_check -s not-exit:0 -o empty -e match:'separate EFI signing requires' "$tool" plan boot-stage --boot-image "$(pwd)/image.ufs" --boot-archive "$(pwd)/boot.tar" --image-receipt "$(pwd)/receipt.json" --output "$output" --boot-efi-path /boot/loader.efi --boot-efi-signing-key "$(pwd)/efi-private.key"
    atf_check -s exit:0 -o ignore grep -- '--media-makefs /usr/sbin/makefs --media-mkimg /usr/bin/mkimg --efi-fallback-name BOOTX64.EFI --esp-mib 32 --boot-free-percent 5' signed-plan
    atf_check -s not-exit:0 -o empty -e match:'boot media requires' "$tool" plan kernel --boot-esp-mib 32
    atf_check -s exit:0 -o empty -e empty python3.12 - <<'PYTHON'
import json
rows = [json.loads(line) for line in open('stage.jsonl')]
assert rows[0]['verification_scope'] == 'boot-transport-makefs-input'
assert len(rows) == 2 and rows[1]['name'] == 'boot-stage'
assert '--output' in rows[1]['argv']
PYTHON
}

atf_test_case image_validation
image_validation_head()
{
    atf_set require.progs 'python3.12 cc elfctl'
    atf_set descr 'Image receipts and ordinary construction inputs are validated offline'
}
image_validation_body()
{
    helper=$(atf_config_get image_helper "$(atf_get_srcdir)/generation_image.py")
    construction=$(atf_config_get construction_helper "$(atf_get_srcdir)/construction.py")
    tests=$(atf_config_get image_tests "$(atf_get_srcdir)/generation_image_test.py")
    capsule_validator=$(atf_config_get image_capsule_validator "")
    elfctl=$(atf_config_get elfctl elfctl)
    atf_check -s exit:0 -o ignore -e match:'OK' env BSD_BUILD_IMAGE_HELPER="$helper" BSD_BUILD_CONSTRUCTION_HELPER="$construction" BSD_BUILD_ELFCTL="$elfctl" BSD_BUILD_CAPSULE_VALIDATOR="$capsule_validator" python3.12 -B "$tests"
}

atf_test_case image_plan
image_plan_head()
{
    atf_set require.progs python3.12
    atf_set descr 'Explicit generation image inputs and scope reach the maintained backend'
}
image_plan_body()
{
    setup
    mkdir root
    printf '{}' > inventory.json
    printf '{}' > generated.json
    printf '{}' > receipt.json
    output=/usr/obj/usr/src/image-plan-$$
    atf_check -s exit:0 -o save:plan.jsonl -e empty "$tool" plan image --root "$(pwd)/root" --inventory "$(pwd)/inventory.json" --generated "$(pwd)/generated.json" --construction-receipt "$(pwd)/receipt.json" --image-makefs /bin/sh --image-mdconfig /bin/sh --image-mount /bin/sh --image-umount /bin/sh --image-boot-archive --output "$output" --format json
    [ ! -e "$output" ] || atf_fail 'image plan created output'
    atf_check -s exit:0 -o empty -e empty python3.12 - <<'PYTHON'
import json
rows = [json.loads(line) for line in open('plan.jsonl')]
assert rows[0]['verification_scope'] == 'trusted-builder-filesystem-image'
assert rows[0]['boot_verification'] == 'not-performed'
assert [r['name'] for r in rows[1:]] == ['image']
args = rows[1]['argv']
assert args[1] == '/usr/src/tools/build/capimage/generation_image.py'
for flag in ('--construction-receipt', '--makefs', '--mdconfig', '--mount', '--umount', '--boot-archive'):
    assert flag in args
PYTHON
    printf '{}' > layout.json
    printf '{}' > storage-bindings.json
    hash=0000000000000000000000000000000000000000000000000000000000000000
    printf '%s\n' '{"format":1,"block_size":4096,"salt_hex":""}' > verity.json
    atf_check -s exit:0 -o save:layout-image-plan.jsonl -e empty "$tool" plan image --root "$PWD/root" --inventory "$PWD/inventory.json" --generated "$PWD/generated.json" --construction-receipt "$PWD/receipt.json" --image-makefs /bin/sh --image-mdconfig /bin/sh --image-mount /bin/sh --image-umount /bin/sh --storage-layout-policy "$PWD/layout.json" --image-verity-policy "$PWD/verity.json" --image-boot-archive --output "$output" --format json
    atf_check -s exit:0 -o empty -e empty python3.12 - <<'PYTHON'
import json, os
rows = [json.loads(line) for line in open('layout-image-plan.jsonl')]
assert rows[1]['argv'][-2:] == ['--storage-layout-policy', os.path.realpath('layout.json')]
assert '--boot-archive' in rows[1]['argv']
assert rows[1]['argv'][rows[1]['argv'].index('--verity-policy')+1] == os.path.realpath('verity.json')
PYTHON
    atf_check -s not-exit:0 -o empty -e match:'usage: build-bsd' "$tool" plan image --storage-bindings "$PWD/storage-bindings.json"
    atf_check -s not-exit:0 -o empty -e match:'usage: build-bsd' "$tool" plan image --storage-layout-policy "$PWD/layout.json" --storage-bindings "$PWD/storage-bindings.json"
    atf_check -s not-exit:0 -o empty -e match:'all four explicit image tools' "$tool" plan image --root "$(pwd)/root" --inventory "$(pwd)/inventory.json" --generated "$(pwd)/generated.json" --construction-receipt "$(pwd)/receipt.json"
    atf_check -s not-exit:0 -o empty -e match:'only to image' "$tool" plan kernel --image-makefs /bin/sh
    atf_check -s not-exit:0 -o empty -e match:'only to image' "$tool" plan kernel --image-boot-archive
}
atf_test_case construction_plan
construction_plan_head()
{
    atf_set require.progs python3.12
    atf_set descr 'Construction inputs and timeout reach the backend without claiming authentication'
}
construction_plan_body()
{
    setup
    mkdir root
    printf '{}' > inventory.json
    printf '{}' > generated.json
    output=/usr/obj/usr/src/construction-plan-$$
    printf '{"format":1,"boundaries":[]}' > storage-policy.json
    atf_check -s exit:0 -o save:plan.jsonl -e empty "$tool" plan construct --root "$(pwd)/root" --inventory "$(pwd)/inventory.json" --generated "$(pwd)/generated.json" --output "$output" --construction-timeout 17 --storage-layout-policy "$(pwd)/storage-policy.json" --format json
    [ ! -e "$output" ] || atf_fail 'plan created output'
    atf_check -s exit:0 -o empty -e empty python3.12 - <<'PYTHON'
import json
rows = [json.loads(line) for line in open('plan.jsonl')]
assert rows[0]['verification_scope'] == 'trusted-builder-construction'
assert rows[0]['boot_verification'] == 'not-performed'
assert rows[0]['root_protection_verification'] == 'not-performed'
assert [row['name'] for row in rows[1:]] == ['construct']
argv = rows[1]['argv']
assert argv[1] == '/usr/src/tools/build/capimage/construction.py'
assert argv[argv.index('--timeout') + 1] == '17'
assert '--inventory' in argv and '--generated' in argv
from pathlib import Path
assert argv[argv.index('--storage-layout-policy') + 1] == str(Path('storage-policy.json').resolve())
PYTHON
    for timeout in 0 -1 86401 invalid 1.5; do
        atf_check -s not-exit:0 -o empty -e match:'between 1 and 86400' "$tool" plan construct --root "$(pwd)/root" --inventory "$(pwd)/inventory.json" --generated "$(pwd)/generated.json" --construction-timeout "$timeout"
    done
    atf_check -s exit:0 -o match:'--extract-tar' -e empty "$tool" plan construct --root "$(pwd)/root" --inventory "$(pwd)/inventory.json" --generated "$(pwd)/generated.json" --extract-tar /bin/sh --output "$output" --format json
    atf_check -s not-exit:0 -o empty -e match:'only to construct' "$tool" plan kernel --extract-tar /bin/sh
    echo '{}' > database-contract.json
    echo '{}' > database-policy.json
    atf_check -s exit:0 -o save:database-plan.jsonl -e empty "$tool" plan construct --root "$(pwd)/root" --inventory "$(pwd)/inventory.json" --generated "$(pwd)/generated.json" --output "$output" --database-pkg /bin/sh --database-sqlite /bin/sh --database-contract "$(pwd)/database-contract.json" --database-policy "$(pwd)/database-policy.json" --database-osversion 1600027 --format json
    atf_check -s exit:0 -o empty -e empty python3.12 - <<'PYTHON'
import json
rows = [json.loads(line) for line in open('database-plan.jsonl')]
argv = rows[1]['argv']
for flag in ('--database-pkg', '--database-sqlite', '--database-contract', '--database-policy'):
    assert flag in argv
assert argv[argv.index('--database-osversion') + 1] == '1600027'
assert rows[0]['boot_verification'] == 'not-performed'
PYTHON
    atf_check -s not-exit:0 -o empty -e match:'all five explicit' "$tool" plan construct --root "$(pwd)/root" --inventory "$(pwd)/inventory.json" --generated "$(pwd)/generated.json" --database-pkg /bin/sh
    atf_check -s not-exit:0 -o empty -e match:'only to construct' "$tool" plan kernel --database-pkg /bin/sh
    atf_check -s not-exit:0 -o empty -e match:'positive 32-bit' "$tool" plan construct --root "$(pwd)/root" --inventory "$(pwd)/inventory.json" --generated "$(pwd)/generated.json" --database-pkg /bin/sh --database-sqlite /bin/sh --database-contract "$(pwd)/database-contract.json" --database-policy "$(pwd)/database-policy.json" --database-osversion 0
    [ ! -e "$output" ] || atf_fail 'database plan created output'
    echo '{}' > installation-policy.json
    atf_check -s exit:0 -o match:'--installation-policy' -e empty "$tool" plan construct --root "$(pwd)/root" --inventory "$(pwd)/inventory.json" --generated "$(pwd)/generated.json" --installation-policy "$(pwd)/installation-policy.json" --output "$output" --format json
    atf_check -s not-exit:0 -o empty -e match:'applies only to construct' "$tool" plan kernel --installation-policy "$(pwd)/installation-policy.json"
    echo '{}' > library-policy.json
    atf_check -s exit:0 -o match:'--library-policy' -e empty "$tool" plan construct --root "$(pwd)/root" --inventory "$(pwd)/inventory.json" --generated "$(pwd)/generated.json" --library-policy "$(pwd)/library-policy.json" --output "$output" --format json
    atf_check -s not-exit:0 -o empty -e match:'applies only to construct' "$tool" plan kernel --library-policy "$(pwd)/library-policy.json"
    echo '{}' > module-policy.json
    atf_check -s exit:0 -o match:'--module-policy' -e empty "$tool" plan construct --root "$(pwd)/root" --inventory "$(pwd)/inventory.json" --generated "$(pwd)/generated.json" --module-policy "$(pwd)/module-policy.json" --output "$output" --format json
    atf_check -s not-exit:0 -o empty -e match:'applies only to construct' "$tool" plan kernel --module-policy "$(pwd)/module-policy.json"
    echo '{}' > certificate-policy.json
    atf_check -s exit:0 -o match:'--certificate-policy' -e empty "$tool" plan construct --root "$(pwd)/root" --inventory "$(pwd)/inventory.json" --generated "$(pwd)/generated.json" --certificate-policy "$(pwd)/certificate-policy.json" --output "$output" --format json
    atf_check -s not-exit:0 -o empty -e match:'applies only to construct' "$tool" plan kernel --certificate-policy "$(pwd)/certificate-policy.json"
    atf_check -s not-exit:0 -o empty -e match:'applies only to construct' "$tool" plan kernel --construction-timeout 17
    atf_check -s not-exit:0 -o empty -e match:'alternate root' "$tool" plan construct --root / --inventory "$(pwd)/inventory.json" --generated "$(pwd)/generated.json"
    atf_check -s not-exit:0 -o empty -e match:'do not authenticate or sign' "$tool" plan construct --root "$(pwd)/root" --inventory "$(pwd)/inventory.json" --generated "$(pwd)/generated.json" --signing development
}
atf_test_case payload_extraction
payload_extraction_head()
{
    atf_set require.progs python3.12
    atf_set descr 'Package payload extraction preflight and destination refusal'
}
payload_extraction_body()
{
    helper=$(atf_config_get extraction_helper "$(atf_get_srcdir)/payload_extract.py")
    tests=$(atf_config_get extraction_tests "$(atf_get_srcdir)/payload_extract_test.py")
    atf_check -s exit:0 -o empty -e match:'OK' env BSD_BUILD_EXTRACTION_HELPER="$helper" python3.12 -B "$tests"
}

atf_test_case certificate_policy
certificate_policy_head()
{
    atf_set "descr" "Certificate selection policy and bounded planning records"
    atf_set "require.progs" "python3.12"
}
certificate_policy_body()
{
    helper=$(atf_config_get construction_helper "$(atf_get_srcdir)/construction.py")
    tests=$(atf_config_get certificate_policy_tests "$(atf_get_srcdir)/certificate_policy_test.py")
    atf_check -s exit:0 -o empty -e match:"OK" env BSD_BUILD_CONSTRUCTION_HELPER="$helper" python3.12 -B "$tests"
}

atf_test_case installation_policy
installation_policy_head()
{
    atf_set require.progs python3.12
    atf_set descr 'Explicit installation configuration provenance and safe replacement'
}
installation_policy_body()
{
    helper=$(atf_config_get construction_helper "$(atf_get_srcdir)/construction.py")
    tests=$(atf_config_get installation_policy_tests "$(atf_get_srcdir)/installation_policy_test.py")
    atf_check -s exit:0 -o empty -e match:'OK' env BSD_BUILD_CONSTRUCTION_HELPER="$helper" python3.12 -B "$tests"
}
atf_test_case signing_custody
signing_custody_head()
{
    atf_set descr "Direct stage signing rejects exposed keys before signing"
    atf_set require.progs "python3.12"
}
signing_custody_body()
{
    script=$(atf_config_get sign_stage "$(atf_get_srcdir)/sign-stage.sh")
    tests=$(atf_config_get signing_custody_tests "$(atf_get_srcdir)/signing_custody_test.py")
    atf_check -s exit:0 -o ignore -e ignore env BSD_BUILD_SIGN_STAGE="$script" python3.12 -B "$tests"
}

atf_test_case elf_feature_build
elf_feature_build_head()
{
    atf_set require.progs 'python3.12 cc make elfctl'
    atf_set descr 'Declarative ELF feature marking before stripping and packaging'
}
elf_feature_build_body()
{
    source=$(atf_config_get source /usr/src)
    [ -f "$source/share/mk/bsd.prog.mk" ] || atf_skip 'requires source build rules'
    tests=$(atf_config_get elf_build_tests "$(atf_get_srcdir)/elf_features_build_test.py")
    elfctl=$(atf_config_get elfctl elfctl)
    atf_check -s exit:0 -o empty -e match:'OK' env BSD_BUILD_SRC="$source" BSD_BUILD_ELFCTL="$elfctl" python3.12 -B "$tests"
}
atf_test_case elf_dependency_metadata
elf_dependency_metadata_head()
{
    atf_set require.progs 'python3.12 cc elfctl'
    atf_set descr 'ELF loading metadata without executing target objects'
}
elf_dependency_metadata_body()
{
    helper=$(atf_config_get elf_helper "$(atf_get_srcdir)/elf_dependencies.py")
    tests=$(atf_config_get elf_tests "$(atf_get_srcdir)/elf_dependencies_test.py")
    elfctl=$(atf_config_get elfctl elfctl)
    atf_check -s exit:0 -o empty -e match:'OK' env BSD_BUILD_ELF_HELPER="$helper" BSD_BUILD_ELFCTL="$elfctl" python3.12 -B "$tests"
}
atf_test_case library_policy
library_policy_head()
{
    atf_set require.progs python3.12
    atf_set descr 'Explicit library search policy and exact hints output'
}
library_policy_body()
{
    helper=$(atf_config_get construction_helper "$(atf_get_srcdir)/construction.py")
    tests=$(atf_config_get library_policy_tests "$(atf_get_srcdir)/library_policy_test.py")
    atf_check -s exit:0 -o empty -e match:'OK' env BSD_BUILD_CONSTRUCTION_HELPER="$helper" python3.12 -B "$tests"
}
atf_test_case module_policy
module_policy_head()
{
    atf_set require.progs python3.12
    atf_set descr 'Package-derived module selection and output declarations'
}
module_policy_body()
{
    helper=$(atf_config_get construction_helper "$(atf_get_srcdir)/construction.py")
    tests=$(atf_config_get module_policy_tests "$(atf_get_srcdir)/module_policy_test.py")
    atf_check -s exit:0 -o empty -e match:'OK' env BSD_BUILD_CONSTRUCTION_HELPER="$helper" python3.12 -B "$tests"
}
atf_test_case database_preflight
database_preflight_head()
{
    atf_set descr 'Real SQLite package policy, schema, relationship and lock checks'
    atf_set require.progs 'python3.12 sqlite3'
}
database_preflight_body()
{
    helper=$(atf_config_get database_preflight_helper "$(atf_get_srcdir)/database_preflight.py")
    tests=$(atf_config_get database_preflight_tests "$(atf_get_srcdir)/database_preflight_test.py")
    atf_check -s exit:0 -o empty -e match:'OK' env BSD_BUILD_DATABASE_PREFLIGHT_HELPER="$helper" python3.12 -B "$tests" --sqlite "$(command -v sqlite3)"
}

atf_test_case database_payload
database_payload_head()
{
    atf_set descr 'Compare real SQLite payload metadata and dependency records against manifests'
    atf_set require.progs 'python3.12 sqlite3'
}
database_payload_body()
{
    helper=$(atf_config_get database_payload_helper "$(atf_get_srcdir)/database_payload.py")
    tests=$(atf_config_get database_payload_tests "$(atf_get_srcdir)/database_payload_test.py")
    atf_check -s exit:0 -o empty -e match:'OK' env BSD_BUILD_DATABASE_PAYLOAD_HELPER="$helper" python3.12 -B "$tests" --sqlite "$(command -v sqlite3)"
}

atf_test_case boot_observation_plan
boot_observation_plan_body()
{
    setup
    printf '{}' > observation.json
    output=/usr/obj/usr/src/boot-observation-plan-$$
    atf_check -s exit:0 -o save:observation.jsonl -e empty "$tool" plan boot-observe --boot-observation-policy "$(pwd)/observation.json" --output "$output" --format json
    [ ! -e "$output" ] || atf_fail 'observation plan created output'
    atf_check -s exit:0 -o empty -e empty python3.12 - <<'PYTHON'
import json
rows=[json.loads(line) for line in open('observation.jsonl')]
assert len(rows)==2
assert rows[0]['verification_scope']=='installed-boot-observation'
assert rows[0]['boot_verification']=='not-performed'
assert rows[0]['program_compatibility_verification']=='not-performed'
assert rows[1]['argv'][1]=='/usr/src/tools/test/boot-observe/run.py'
assert '--policy' in rows[1]['argv'] and '--work' in rows[1]['argv']
PYTHON
    atf_check -s not-exit:0 -o empty -e match:'requires --boot-observation-policy' "$tool" plan boot-observe
    atf_check -s not-exit:0 -o empty -e match:'only to boot-observe' "$tool" plan kernel --boot-observation-policy "$(pwd)/observation.json"
}

atf_test_case configuration_composition
configuration_composition_head()
{
    atf_set descr 'Explicit base-bound policy changes preserve unrelated fields and reject stale inputs'
    atf_set require.progs 'python3.12'
}
configuration_composition_body()
{
    tests=$(atf_config_get configuration_compose_tests "$(atf_get_srcdir)/configuration_compose_test.py")
    atf_check -s exit:0 -o empty -e match:'OK' python3.12 -B "$tests"
}

atf_test_case ucl_policy_normalization
ucl_policy_normalization_head()
{
    atf_set descr 'Confined UCL normalization rejects macros, duplicates and oversized input'
    atf_set require.progs 'python3.12'
}
ucl_policy_normalization_body()
{
    helper=$(atf_config_get ucl_policy_helper /usr/libexec/bsd-build/bsd-ucl-json)
    tests=$(atf_config_get ucl_policy_tests "$(atf_get_srcdir)/ucl_policy_json_test.py")
    atf_check -s exit:0 -o empty -e match:'OK' env BSD_BUILD_UCL_JSON="$helper" python3.12 -B "$tests"
}

atf_test_case configuration_composition_plan
configuration_composition_plan_body()
{
    setup
    printf '{}' > base.json
    printf '{}' > changes.json
    output=/usr/obj/usr/src/configuration-composition-plan-$$
    hash=0000000000000000000000000000000000000000000000000000000000000000
    atf_check -s exit:0 -o save:composition.jsonl -e empty "$tool" plan compose-config --configuration-base "$(pwd)/base.json" --configuration-changes "$(pwd)/changes.json" --configuration-parser /bin/sh --configuration-parser-sha256 "$hash" --output "$output" --format json
    [ ! -e "$output" ] || atf_fail 'composition plan created output'
    atf_check -s exit:0 -o empty -e empty python3.12 - <<'PYTHON'
import json
rows = [json.loads(line) for line in open('composition.jsonl')]
assert len(rows) == 2
assert rows[0]['verification_scope'] == 'explicit-configuration-composition'
assert rows[1]['argv'][1] == '/usr/src/tools/build/capimage/configuration_compose.py'
assert '--ucl-parser-sha256' in rows[1]['argv']
PYTHON
    atf_check -s exit:0 -o save:validated-composition.jsonl -e empty "$tool" plan compose-config --configuration-base "$PWD/base.json" --configuration-changes "$PWD/changes.json" --configuration-parser /bin/sh --configuration-parser-sha256 "$hash" --capsule-validator /bin/sh --capsule-validator-sha256 "$hash" --output "$output" --format json
    atf_check -s exit:0 -o empty -e empty python3.12 - <<'PYTHON'
import json
rows = [json.loads(line) for line in open('validated-composition.jsonl')]
assert rows[1]['argv'][-4:] == ['--capsule-validator', '/bin/sh', '--capsule-validator-sha256', '0'*64]
PYTHON
    atf_check -s not-exit:0 -o empty -e match:'requires a selected executable' "$tool" plan compose-config --capsule-validator /bin/sh
    atf_check -s not-exit:0 -o empty -e match:'only to compose-config' "$tool" plan kernel --capsule-validator /bin/sh --capsule-validator-sha256 "$hash"
    atf_check -s not-exit:0 -o empty -e match:'requires base, changes and parser' "$tool" plan compose-config
    atf_check -s not-exit:0 -o empty -e match:'only to compose-config' "$tool" plan kernel --configuration-base "$(pwd)/base.json"
}

atf_test_case repository_snapshot_plan
repository_snapshot_plan_head()
{
    atf_set descr 'Consumer snapshot requires explicit trust and target inputs without signing or activation'
    atf_set require.progs python3.12
}
repository_snapshot_plan_body()
{
    setup
    mkdir 'source repository'
    printf '{}' > 'source repository/publication.json'
    printf 'plan-only public trust input' > 'trust key.pub'
    output=/usr/obj/usr/src/repository-snapshot-plan-$$
    atf_check -s exit:0 -o save:snapshot.jsonl -e empty "$tool" plan snapshot --repository "$(pwd)/source repository" --pkg-public-key "$(pwd)/trust key.pub" --package-tool /bin/sh --snapshot-abi FreeBSD:16:amd64 --snapshot-osversion 1600027 --output "$output" --format json
    [ ! -e "$output" ] || atf_fail 'snapshot plan created output'
    atf_check -s exit:0 -o empty -e empty python3.12 - <<'PYTHON'
import json, os
rows = [json.loads(line) for line in open('snapshot.jsonl')]
assert len(rows) == 2
assert rows[0]['verification_scope'] == 'signed-repository-snapshot'
argv = rows[1]['argv']
assert argv[:3] == ['/usr/local/bin/python3.12', '/usr/src/release/scripts/hardware-packages.py', 'copy-signed-repository']
assert argv[argv.index('--repository') + 1] == os.getcwd() + '/source repository'
assert argv[argv.index('--public-key') + 1] == os.getcwd() + '/trust key.pub'
assert argv[argv.index('--abi') + 1] == 'FreeBSD:16:amd64'
assert argv[argv.index('--osversion') + 1] == '1600027'
assert '--signing-key' not in argv
PYTHON
    atf_check -s not-exit:0 -o empty -e match:'snapshot requires' "$tool" plan snapshot
    atf_check -s not-exit:0 -o empty -e match:'positive 32-bit' "$tool" plan snapshot --repository "$(pwd)/source repository" --pkg-public-key "$(pwd)/trust key.pub" --package-tool /bin/sh --snapshot-abi FreeBSD:16:amd64 --snapshot-osversion 0
    atf_check -s not-exit:0 -o empty -e match:'only to snapshot' "$tool" plan kernel --snapshot-abi FreeBSD:16:amd64
    atf_check -s not-exit:0 -o empty -e match:'only to build, packages or snapshot' "$tool" plan kernel --package-tool /bin/sh
}

atf_test_case state_storage_inputs
state_storage_inputs_head()
{
    atf_set descr 'State workflow verifies selected tools and parsed initialization inputs'
    atf_set require.progs python3.12
}
state_storage_inputs_body()
{
    tests=$(atf_config_get state_storage_tests "$(atf_get_srcdir)/state_storage_test.py")
    atf_check -s exit:0 -o empty -e match:'OK' python3.12 -B "$tests"
}

atf_test_case state_storage_plan
state_storage_plan_body()
{
    setup
    echo '{}' > plan.json
    output=/usr/obj/usr/src/state-storage-plan-$$
    atf_check -s exit:0 -o save:plan.jsonl -e empty "$tool" plan state-storage --state-plan "$(pwd)/plan.json" --output "$output" --format json
    [ ! -e "$output" ] || atf_fail 'plan created output'
    atf_check -s exit:0 -o empty -e empty python3.12 - <<'PYTHON'
import json, os
rows = [json.loads(line) for line in open('plan.jsonl')]
assert len(rows) == 2
assert rows[0]['verification_scope'] == 'offline-state-provisioning'
argv = rows[1]['argv']
assert argv[:2] == ['/usr/local/bin/python3.12', '/usr/src/tools/build/capimage/state_storage.py']
assert argv[argv.index('--plan')+1] == os.getcwd() + '/plan.json'
PYTHON
    atf_check -s not-exit:0 -o empty -e match:'requires --state-plan' "$tool" plan state-storage
    atf_check -s not-exit:0 -o empty -e match:'only to state-storage' "$tool" plan kernel --state-plan "$(pwd)/plan.json"
}

atf_test_case native_capsule_validation
native_capsule_validation_head()
{
    atf_set descr 'Native builder validator passes the production Capsule CLI contract'
}
native_capsule_validation_body()
{
    tool=$(atf_config_get capsule_validator /usr/libexec/bsd-build/bsd-capsule-validate)
    [ -x "$tool" ] || atf_fail "native Capsule validator unavailable: $tool"
    atf_check -s exit:0 -o match:passed -e ignore /usr/libexec/atf-sh \
        "$(atf_get_srcdir)/capsule_config_cli_test.sh" -v "capsule=$tool" static_only
}

atf_test_case production_loader_plan
production_loader_plan_body()
{
    setup
    printf 'public-anchor-plan-input\n' > anchors.pem
    output=/usr/obj/usr/src/loader-plan-$$
    atf_check -s exit:0 -o save:loader.jsonl -e empty "$tool" plan loader-build --loader-anchors "$PWD/anchors.pem" --output "$output" --format json
    [ ! -e "$output" ] || atf_fail 'plan created loader output'
    atf_check -s exit:0 -o empty -e empty python3.12 - "$output" <<'PYTHON'
import json, os, sys
rows=[json.loads(line) for line in open('loader.jsonl')]
assert rows[0]['verification_scope']=='trusted-builder-loader-compilation'
assert rows[0]['boot_verification']=='not-performed'
assert len(rows)==2 and rows[1]['name']=='loader-build'
assert rows[1]['argv']==['/usr/local/bin/python3.12', '/usr/src/tools/build/capimage/loader_build.py', '--anchors', os.path.realpath('anchors.pem'), '--output', sys.argv[1], '--jobs', str(rows[0]['jobs'])]
PYTHON
    atf_check -s not-exit:0 -o ignore -e ignore "$tool" plan loader-build
    atf_check -s not-exit:0 -o ignore -e ignore "$tool" plan world --loader-anchors "$PWD/anchors.pem"
    atf_check -s not-exit:0 -o ignore -e ignore "$tool" plan loader-build --loader-anchors "$PWD/anchors.pem" --incremental
    atf_check -s not-exit:0 -o ignore -e ignore "$tool" plan loader-build --loader-anchors "$PWD/anchors.pem" --arch arm64
    atf_check -s exit:0 -o ignore -e ignore python3.12 -B "$(atf_get_srcdir)/loader_production_test.py"
}

atf_test_case firmware_plan
firmware_plan_head()
{
    atf_set descr 'Firmware-only plan uses explicit inputs and avoids retired OS fixtures'
    atf_set require.progs python3.12
}
firmware_plan_body()
{
    setup
    touch code.fd vars.fd
    output=/usr/obj/usr/src/firmware-plan-$$
    atf_check -s exit:0 -o save:firmware.jsonl -e empty "$tool" plan secureboot-test --test-case firmware --test-firmware-code "$PWD/code.fd" --test-firmware-vars "$PWD/vars.fd" --qemu /usr/bin/true --uefi-vars-tool /usr/bin/true --qemu-data "$PWD" --output "$output" --format json
    [ ! -e "$output" ] || atf_fail 'plan created output'
    atf_check -s exit:0 -o empty -e empty python3.12 - <<'PYTEST'
import json
rows = [json.loads(line) for line in open('firmware.jsonl')]
assert rows[0]['verification_scope'] == 'firmware-only'
for field in ('system_image_verification', 'root_protection_verification', 'bootstrap_integrity_verification', 'program_compatibility_verification'):
    assert rows[0][field] == 'not-performed'
assert [r['name'] for r in rows[1:]] == ['secureboot-loader-clean', 'secureboot-loader', 'secureboot-firmware-probe', 'secureboot-firmware-update-probe', 'secureboot-firmware-evidence-tests', 'secureboot-firmware-vm']
args = rows[-1]['argv']
assert args[2] == '/usr/src/tools/test/secureboot/firmware/suite.py'
assert '--root' not in args and '--capsign' not in args
assert '--update-probe' in args
assert args[args.index('--firmware')+1].endswith('/code.fd')
assert args[args.index('--variables')+1].endswith('/vars.fd')
assert all(arg in args for arg in ('--makefs', '--mkimg', '--openssl', '--uefisign'))
assert not any('/tools/test/secureboot/run.py' in r['argv'] for r in rows[1:])
PYTEST
    atf_check -s not-exit:0 -o empty -e match:'require explicit' "$tool" plan secureboot-test --test-case firmware --qemu /usr/bin/true --uefi-vars-tool /usr/bin/true
    atf_check -s not-exit:0 -o empty -e match:'firmware inputs require' "$tool" plan kernel --test-firmware-code "$PWD/code.fd"
}

atf_test_case bazel_plan
bazel_plan_body()
{
    setup
    output=/usr/obj/usr/src/bazel-plan-$$
    printf '{}\n' > modules.json
    atf_check -s exit:0 -o save:plan.jsonl -e empty "$tool" plan bazel-test --bazel /usr/bin/true --bazel-modules "$PWD/modules.json" --jobs 3 --output "$output" --format json
    [ ! -e "$output" ] || atf_fail 'plan created output'
    atf_check -s exit:0 -o empty -e empty python3.12 - "$output" "$PWD/modules.json" <<'PYTHON'
import json, sys
rows = [json.loads(line) for line in open('plan.jsonl')]
assert rows[0]['verification_scope'] == 'bazel-compile-comparison'
assert rows[0]['make_install_reference'] == 'requested'
assert rows[0]['bazel_minimum_major'] == 9
assert rows[0]['module_resolution'] == 'offline-pinned-lockfile'
assert rows[0]['build_backend'] == 'bsd-make'
assert rows[0]['jobs'] == 3
assert rows[0]['boot_verification'] == 'not-performed'
assert len(rows) == 2
assert rows[1]['name'] == 'bazel-qualification'
assert rows[1]['argv'] == ['/usr/local/bin/python3.12', '/usr/src/tools/build/bazel/qualify.py', '--src', '/usr/src', '--objtop', '/usr/obj/usr/src/amd64.amd64', '--bazel', '/usr/bin/true', '--output', sys.argv[1], '--jobs', '3', '--bzlmod-inputs', sys.argv[2]]
PYTHON
    atf_check -s exit:0 -o match:'bazel=9-or-later module-resolution=offline-pinned-lockfile' -e empty "$tool" plan bazel-test --bazel /usr/bin/true --bazel-modules "$PWD/modules.json"
    # Without --bazel the bazel9 package's /usr/local/bin/bazel is selected.
    if [ -f /usr/local/bin/bazel ] && [ ! -L /usr/local/bin/bazel ]; then
        atf_check -s exit:0 -o match:"--bazel /usr/local/bin/bazel " -e empty "$tool" plan bazel-test --bazel-modules "$PWD/modules.json"
    elif [ ! -e /usr/local/bin/bazel ]; then
        atf_check -s not-exit:0 -o empty -e match:'bazel9 package' "$tool" plan bazel-test --bazel-modules "$PWD/modules.json"
    fi
    printf '{}\n' > native-inputs.json
    atf_check -s exit:0 -o save:native-plan.jsonl -e empty "$tool" plan bazel-test --bazel /usr/bin/true --bazel-inputs "$PWD/native-inputs.json" --jobs 3 --output "$output" --format json
    atf_check -s exit:0 -o empty -e empty python3.12 - "$PWD/native-inputs.json" <<'PYTEST'
import json, sys
rows = [json.loads(line) for line in open('native-plan.jsonl')]
assert rows[0]['verification_scope'] == 'native-configured-qualification'
assert rows[0]['make_install_reference'] == 'not-performed'
assert rows[0]['build_backend'] == 'bsd-make'
assert rows[1]['argv'][1] == '/usr/src/tools/build/bazel/native-qualify.py'
assert rows[1]['argv'][-4:] == ['--inputs', sys.argv[1], '--target-arch', 'amd64']
PYTEST
    for selection in arm64 riscv64; do
        atf_check -s exit:0 -o save:cross-plan.jsonl -e empty "$tool" plan bazel-test --arch "$selection" --bazel /usr/bin/true --bazel-inputs "$PWD/native-inputs.json" --output "$output" --format json
        atf_check -s exit:0 -o empty -e empty python3.12 - "$selection" <<'PYTEST'
import json, sys
rows = [json.loads(line) for line in open('cross-plan.jsonl')]
arch = {'arm64': 'aarch64', 'riscv64': 'riscv64'}[sys.argv[1]]
assert rows[0]['target_arch'] == arch
assert rows[0]['verification_scope'] == 'cross-configured-qualification'
assert rows[1]['argv'][-2:] == ['--target-arch', arch]
# Object root is the execution SDK, not a pretend cross-userland SDK.
assert rows[1]['argv'][rows[1]['argv'].index('--objtop') + 1] == '/usr/obj/usr/src/amd64.amd64'
PYTEST
    done
    [ ! -e "$output" ] || atf_fail 'native plan created output'
    atf_check -s not-exit:0 -o empty -e match:'only to bazel-test' "$tool" plan world --bazel-inputs "$PWD/native-inputs.json"
    atf_check -s not-exit:0 -o empty -e match:'only to bazel-test' "$tool" plan world --bazel-modules "$PWD/modules.json"
    atf_check -s not-exit:0 -o empty -e match:'requires --bazel-modules' "$tool" plan bazel-test --bazel /usr/bin/true
    atf_check -s not-exit:0 -o empty -e match:'native --bazel-inputs names its own' "$tool" plan bazel-test --bazel /usr/bin/true --bazel-inputs "$PWD/native-inputs.json" --bazel-modules "$PWD/modules.json"
    atf_check -s not-exit:0 -o empty -e match:'cross-target bazel-test requires explicit' "$tool" plan bazel-test --bazel /usr/bin/true --bazel-modules "$PWD/modules.json" --arch arm64
    atf_check -s not-exit:0 -o empty -e match:'only to bazel-test' "$tool" plan world --bazel /usr/bin/true
    atf_check -s not-exit:0 -o empty -e match:'fresh qualification' "$tool" plan bazel-test --bazel /usr/bin/true --bazel-modules "$PWD/modules.json" --incremental
    atf_check -s not-exit:0 -o empty -e match:'fixed comparison configuration' "$tool" plan bazel-test --bazel /usr/bin/true --bazel-modules "$PWD/modules.json" --src-conf /dev/null
    cp /usr/bin/true noexec
    chmod 644 noexec
    atf_check -s not-exit:0 -o empty -e match:'must be executable' "$tool" plan bazel-test --bazel "$(pwd)/noexec" --bazel-modules "$PWD/modules.json"
}

atf_test_case application_selection_plan
application_selection_plan_head()
{
    atf_set descr 'Application selection reaches combined publication without installation'
    atf_set require.progs python3.12
}
application_selection_plan_body()
{
    setup
    printf '%s\n' '{"format":1,"archives":[]}' > selected.json
    selection=$(pwd)/selected.json
    atf_check -s exit:0 -o save:application.jsonl -e empty "$tool" plan packages --application-selection "$selection" --format json
    atf_check -s exit:0 -o empty -e empty python3.12 - "$selection" <<'PYTHON'
import json, sys
rows = [json.loads(line) for line in open('application.jsonl')]
publication = next(row for row in rows[1:] if row['name'] == 'system-packages')
assert 'APPLICATION_PACKAGE_SELECTION=' + sys.argv[1] in publication['argv']
assert 'REPODIR=/usr/obj/usr/src/repo' in publication['argv']
assert not any(row['name'] in ('deploy', 'media') for row in rows[1:])
PYTHON
    atf_check -s exit:0 -o save:backend -e empty make -C /usr/src -f release/Makefile.hardware -n publish-packages BASE_REPOSITORY=/usr/obj/base-plan HARDWARE_REPO=/usr/obj/hardware-plan COMPLETE_REPOSITORY=/usr/obj/complete-plan APPLICATION_PACKAGE_SELECTION="$selection"
    atf_check -s exit:0 -o ignore grep -F -- "--application-selection $selection" backend
    printf 'application_selection=%s\n' "$selection" > configured.conf
    atf_check -s exit:0 -o save:configured -e empty "$tool" plan build --config configured.conf
    atf_check -s exit:0 -o ignore grep -F "APPLICATION_PACKAGE_SELECTION=$selection" configured
    cp selected.json override.json
    atf_check -s exit:0 -o save:override -e empty "$tool" plan packages --config configured.conf --application-selection "$(pwd)/override.json"
    atf_check -s exit:0 -o ignore grep -F "APPLICATION_PACKAGE_SELECTION=$(pwd)/override.json" override
    atf_check -s exit:0 -o save:ordinary -e empty "$tool" plan packages
    atf_check -s exit:1 -o empty grep APPLICATION_PACKAGE_SELECTION ordinary
    atf_check -s not-exit:0 -o empty -e match:'only to build or packages' "$tool" plan world --application-selection "$selection"
    ln -s selected.json selection-link
    atf_check -s not-exit:0 -o empty -e match:'not a symlink' "$tool" plan packages --application-selection "$(pwd)/selection-link"
    cp selected.json 'unsafe selection.json'
    atf_check -s not-exit:0 -o empty -e match:'safe characters' "$tool" plan packages --application-selection "$(pwd)/unsafe selection.json"
    atf_check -s not-exit:0 -o empty -e not-empty "$tool" plan packages --application-selection "$(pwd)/missing.json"
}

atf_init_test_cases()
{
    atf_add_test_case native_capsule_validation
    atf_add_test_case state_storage_inputs
    atf_add_test_case state_storage_plan
    atf_add_test_case repository_snapshot_plan
    atf_add_test_case configuration_composition_plan
    atf_add_test_case ucl_policy_normalization
    atf_add_test_case configuration_composition
    atf_add_test_case boot_observation_plan
    atf_add_test_case retired_bip_options
    atf_add_test_case firmware_plan
    atf_add_test_case bazel_plan
    atf_add_test_case secureboot_plan
    atf_add_test_case secureboot_generation_plan
    atf_add_test_case security_scope
    atf_add_test_case optional_integrity_profile
    atf_add_test_case publication_destination
    atf_add_test_case json_plan
    atf_add_test_case hardware_inputs
    atf_add_test_case kernel_identity_only
    atf_add_test_case hardware_profile_grammar
    atf_add_test_case boards
    atf_add_test_case build_profiles
    atf_add_test_case media_orchestration
    atf_add_test_case installer_lifecycle
    atf_add_test_case deployment_reconciliation_plan
    atf_add_test_case deploy_lifecycle
    atf_add_test_case package_closure
    atf_add_test_case package_inventory
    atf_add_test_case generation_reconciliation
    atf_add_test_case inventory_plan
    atf_add_test_case inventory_audit
    atf_add_test_case inventory_audit_plan
    atf_add_test_case reconciliation_plan
    atf_add_test_case payload_extraction
    atf_add_test_case construction_plan
    atf_add_test_case loader_build_configuration
    atf_add_test_case boot_transport
    atf_add_test_case boot_check_plan
    atf_add_test_case image_validation
    atf_add_test_case image_plan
    atf_add_test_case module_policy
    atf_add_test_case installation_policy
    atf_add_test_case library_policy
    atf_add_test_case signing_custody
    atf_add_test_case elf_feature_build
    atf_add_test_case elf_dependency_metadata
    atf_add_test_case certificate_policy
    atf_add_test_case construction_execution
    atf_add_test_case database_preflight
    atf_add_test_case database_payload
    atf_add_test_case architectures
    atf_add_test_case configuration
    atf_add_test_case package_tool_plan
    atf_add_test_case candidate_publication_plan
    atf_add_test_case bootstrap_pkg_plan
    atf_add_test_case application_selection_plan
    atf_add_test_case plans
    atf_add_test_case production_loader_plan
    atf_add_test_case make_object_environment
    atf_add_test_case make_clean_options
    atf_add_test_case invalid_options
    atf_add_test_case path_preflight
    atf_add_test_case failure_stops_pipeline
    atf_add_test_case successful_stage
}
