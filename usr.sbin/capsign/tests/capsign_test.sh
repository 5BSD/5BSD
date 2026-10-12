# SPDX-License-Identifier: BSD-2-Clause
setup()
{
    capsign=$(atf_config_get capsign /usr/sbin/capsign)
    [ -x "$capsign" ] || atf_skip "capsign not installed"
    atf_check -s exit:0 -o ignore -e ignore openssl genpkey -algorithm ed25519 -out key
    atf_check -s exit:0 -o ignore -e ignore openssl pkey -in key -pubout -out public
    printf 'program = "demo"; activation { exec = true; }\n' > policy
    printf 'int main(void) { return 17; }\n' > demo.c
    atf_check -s exit:0 "$capsign" note -m policy -o policy.S
    atf_check -s exit:0 -o ignore -e ignore cc demo.c policy.S -o demo
}
atf_test_case resign_image
resign_image_head() { atf_set require.progs 'cc openssl'; }
resign_image_body()
{
    setup
    chmod 751 demo
    atf_check -s exit:0 "$capsign" sign -k key -o signed demo
    cp signed original
    atf_check -s exit:0 -o ignore -e ignore openssl genpkey -algorithm ed25519 -out new-key
    atf_check -s exit:0 -o ignore -e ignore openssl pkey -in new-key -pubout -out new-public
    atf_check -s exit:0 "$capsign" resign -k new-key -p public -o rotated signed
    atf_check -s exit:0 -o ignore "$capsign" verify -p new-public rotated
    atf_check -s not-exit:0 -o empty -e ignore "$capsign" verify -p public rotated
    atf_check -s exit:0 -o file:policy "$capsign" show -p new-public rotated
    atf_check -s exit:0 -o inline:'751\n' stat -f %Lp rotated
    atf_check -s exit:0 "$capsign" remove -o unsigned rotated
    atf_check -s exit:0 cmp demo unsigned
    atf_check -s exit:0 cmp original signed
    atf_check -s exit:0 -o match:'no output published' "$capsign" resign -n -k new-key -p public -o signed signed
    atf_check -s exit:0 cmp original signed
    atf_check -s not-exit:0 -o empty -e ignore "$capsign" resign -k new-key -p new-public -o wrong signed
    atf_check -s not-exit:0 -o empty -e ignore "$capsign" resign -k new-key -p public -o missing demo
    cp signed damaged
    printf x >> damaged
    atf_check -s not-exit:0 -o empty -e ignore "$capsign" resign -k new-key -p public -o rejected damaged
    atf_check -s not-exit:0 -o empty -e ignore "$capsign" resign -k new-key -p public -o signed signed
    atf_check -s exit:0 cmp original signed
    atf_check -s exit:64 -o empty -e match:usage "$capsign" resign -k new-key -p public -m policy -o replaced signed
    for output in wrong missing rejected replaced; do
        [ ! -e "$output" ] || atf_fail 'published rejected rotation'
    done
    set -- ./*.tmp.*
    [ ! -e "$1" ] || atf_fail 'leaked temporary signing image'
}
atf_test_case inspection
inspection_head() { atf_set require.progs 'cc openssl'; }
inspection_body()
{
    setup
    atf_check -s exit:0 "$capsign" sign -k key -o signed demo
    atf_check -s exit:0 -o save:inspection "$capsign" inspect -p public signed
    id=$("$capsign" key-id -p public)
    atf_check -s exit:0 -o ignore grep -F '"schema": "org.5bsd.capsign.image.v1"' inspection
    atf_check -s exit:0 -o ignore grep -F "\"key_id\": \"$id\"" inspection
    atf_check -s exit:0 -o ignore grep -F "\"policy_bytes\": $(wc -c < policy | tr -d ' ')," inspection
    atf_check -s exit:0 -o save:verified "$capsign" verify -p public signed
    digest=$(sed 's/.*digest=//' verified)
    atf_check -s exit:0 -o ignore grep -F "\"signed_digest\": \"$digest\"" inspection
    atf_check -s not-exit:0 -o empty -e ignore "$capsign" inspect -p public demo
    printf x >> signed
    atf_check -s not-exit:0 -o empty -e ignore "$capsign" inspect -p public signed
}
atf_test_case command_options
command_options_head() { atf_set require.progs 'cc openssl'; }
command_options_body()
{
    setup
    atf_check -s exit:64 -o empty -e match:usage "$capsign" sign -k key -p public -o unexpected demo
    [ ! -e unexpected ] || atf_fail 'ignored inapplicable signing option'
    atf_check -s exit:64 -o empty -e match:usage "$capsign" note -k key -m policy -o unexpected
    [ ! -e unexpected ] || atf_fail 'ignored inapplicable note option'
    atf_check -s exit:64 -o empty -e match:usage "$capsign" verify -r -d ignored missing-tree
    atf_check -s exit:64 -o empty -e match:usage "$capsign" bundle-sign -k key -o unexpected missing-tree
    atf_check -s exit:64 -o empty -e match:usage "$capsign" inspect -r -p public demo
    atf_check -s exit:64 -o empty -e match:usage "$capsign" check -k key -p public -d example -s missing demo
}
atf_test_case copy_limits
copy_limits_head() { atf_set require.progs 'cc openssl truncate'; }
copy_limits_body()
{
    setup
    atf_check -s exit:0 truncate -s 536870913 oversized
    atf_check -s not-exit:0 -e match:'invalid input size/type' "$capsign" sign -k key -o rejected oversized
    [ ! -e rejected ] || atf_fail 'published oversized input'
    # Append during the first copy read deterministically. The tool must not
    # follow an expanding input indefinitely or publish its partial snapshot.
    cat > change.c <<'EOF'
#include <sys/types.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
ssize_t pread(int fd, void *data, size_t size, off_t offset)
{
    static ssize_t (*real_pread)(int, void *, size_t, off_t);
    if (real_pread == NULL) real_pread = dlsym(RTLD_NEXT, "pread");
    ssize_t n = real_pread(fd, data, size, offset);
    const char *path = getenv("CAPSIGN_TEST_CHANGE");
    if (path != NULL && offset == 0 && size == 16384 && n == 16384) {
        int target = open(path, O_WRONLY | O_APPEND);
        if (target < 0 || write(target, "x", 1) != 1) _exit(90);
        close(target);
        unsetenv("CAPSIGN_TEST_CHANGE");
    }
    return n;
}
EOF
    atf_check -s exit:0 -o ignore -e ignore cc -shared -fPIC change.c -o change.so
    atf_check -s exit:0 truncate -s 1048576 demo
    atf_check -s not-exit:0 -e match:'source changed while copying' env \
        LD_PRELOAD="$(pwd)/change.so" CAPSIGN_TEST_CHANGE=demo \
        "$capsign" sign -k key -o rejected demo
    [ ! -e rejected ] || atf_fail 'published concurrently changed input'
    for temporary in rejected.tmp.*; do
        [ ! -e "$temporary" ] || atf_fail 'left signing temporary after failure'
    done
}
atf_test_case batch_verify
batch_verify_head() { atf_set require.progs 'cc openssl'; }
batch_verify_body()
{
    setup
    atf_check -s exit:0 "$capsign" sign -k key -o signed demo
    cp signed tampered
    printf x >> tampered
    atf_check -s exit:1 -o empty -e match:missing "$capsign" verify -p public missing signed
    atf_check -s exit:1 -o match:'verified signed;' -e save:errors "$capsign" verify --continue -p public missing signed tampered
    atf_check -s exit:0 -o ignore grep missing errors
    atf_check -s exit:0 -o ignore grep tampered errors
    atf_check -s exit:0 -o ignore "$capsign" verify -c -p public signed signed
    atf_check -s exit:64 -o empty -e match:usage "$capsign" verify -c -r -p public missing
}
atf_test_case validate_policy
validate_policy_body()
{
    capsign=$(atf_config_get capsign /usr/sbin/capsign)
    [ -x "$capsign" ] || atf_skip 'capsign not installed'
    printf 'program = "demo"; activation { exec = true; } attributes = ["test.demo"];\n' > policy
    cp policy before
    atf_check -s exit:0 -o match:'valid unit policy; bytes=' -e empty "$capsign" validate-policy policy
    atf_check -s exit:0 cmp before policy
    printf 'program = "demo";\n' > missing-activation
    atf_check -s not-exit:0 -o empty -e match:'manifest requires an activation object' "$capsign" validate-policy missing-activation
    for bad in \
        'program = "../escape";' \
        'program = "/bin/demo";' \
        'program = "demo"; program = "other";' \
        'progarm = "demo";' \
        'activation { exec = "yes"; }' \
        'attributes = ["invalid attribute"];' \
        '.include "policy"' \
        'program = {'; do
        printf '%s\n' "$bad" > bad-policy
        atf_check -s not-exit:0 -o empty -e ignore "$capsign" validate-policy bad-policy
    done
    printf 'program = "demo";\000unknown = true;\n' > nul-policy
    atf_check -s not-exit:0 -o empty -e match:non-NUL "$capsign" validate-policy nul-policy
    : > empty
    atf_check -s not-exit:0 -o empty -e ignore "$capsign" validate-policy empty
    atf_check -s exit:0 -o ignore -e ignore truncate -s 1048577 oversized
    atf_check -s not-exit:0 -o empty -e ignore "$capsign" validate-policy oversized
    ln -s policy link
    atf_check -s not-exit:0 -o empty -e ignore "$capsign" validate-policy link
    mkdir directory
    mkfifo fifo
    atf_check -s not-exit:0 -o empty -e ignore "$capsign" validate-policy directory
    atf_check -s not-exit:0 -o empty -e ignore "$capsign" validate-policy fifo
    atf_check -s exit:64 -o empty -e match:usage "$capsign" validate-policy -p public policy
    atf_check -s exit:64 -o empty -e match:usage "$capsign" validate-policy -o output policy
    atf_check -s exit:64 -o empty -e match:usage "$capsign" validate-policy
    [ ! -e output ] || atf_fail 'validation published output'
}
atf_test_case dry_run
dry_run_head() { atf_set require.progs 'cc openssl'; }
dry_run_body()
{
    setup
    cp demo before
    atf_check -s exit:0 -o match:'no output published' "$capsign" sign --dry-run -k key demo
    atf_check -s exit:0 -o match:'no output published' "$capsign" sign -n -k key -o planned demo
    [ ! -e planned ] || atf_fail 'dry-run published output'
    atf_check -s exit:0 cmp before demo
    printf sentinel > existing
    atf_check -s exit:0 -o match:'no output published' "$capsign" sign -n -k key -o existing demo
    atf_check -s exit:0 -o inline:sentinel cat existing
    atf_check -s not-exit:0 -o empty -e ignore "$capsign" sign -n -k missing-key -o planned demo
    printf 'program = "different";\n' > different
    atf_check -s not-exit:0 -o empty -e match:'policy differs' "$capsign" sign -n -k key -m different -o planned demo
    for temporary in planned.tmp.* existing.tmp.*; do
        [ ! -e "$temporary" ] || atf_fail 'dry-run left a temporary file'
    done
    atf_check -s not-exit:0 -o empty -e match:'source must be a real directory' "$capsign" sign -n -r -k key -o tree demo
    [ ! -e tree ] || atf_fail 'dry-run published invalid tree'
}
atf_test_case executable
executable_head() { atf_set "require.progs" "cc openssl"; }
executable_body()
{
    setup
    atf_check -s exit:0 "$capsign" sign -k key -o signed demo
    atf_check -s exit:0 -o save:keyid "$capsign" key-id -p public
    atf_check -s exit:0 -o match:"key=$(cat keyid);" "$capsign" verify -p public signed
    atf_check -s exit:0 -o match:'verified .*policy_bytes=' "$capsign" verify -p public signed
    atf_check -s exit:0 -o file:policy "$capsign" show -p public signed
    atf_check -s exit:17 ./signed
}
atf_test_case strip_order
strip_order_head() { atf_set "require.progs" "cc openssl strip"; }
strip_order_body()
{
    setup
    atf_check -s exit:0 strip --keep-section=.5bsd.policy demo
    atf_check -s exit:0 "$capsign" sign -k key -o signed demo
    atf_check -s exit:0 -o ignore "$capsign" verify -p public signed
    printf 'x' >> signed
    atf_check -s not-exit:0 -e ignore "$capsign" verify -p public signed
}
atf_test_case no_clobber
no_clobber_head() { atf_set "require.progs" "cc openssl"; }
no_clobber_body()
{
    setup
    printf sentinel > signed
    atf_check -s not-exit:0 -e match:'publish' "$capsign" sign -k key -o signed demo
    atf_check -s exit:0 -o inline:sentinel cat signed
    atf_check -s not-exit:0 -e ignore "$capsign" note -m policy -o policy.S
}
atf_test_case detached
 detached_head() { atf_set "require.progs" "cc openssl"; }
detached_body()
{
    setup
    atf_check -s exit:0 "$capsign" seal -k key -d example.one -o seal policy
    atf_check -s exit:0 -o ignore "$capsign" check -p public -d example.one -s seal policy
    atf_check -s not-exit:0 -e match:'invalid or untrusted' "$capsign" check -p public -d example.two -s seal policy
}
bundle_setup()
{
    setup
    mkdir -p Demo.cap/Units/demo.unit/bin
    cat > Demo.cap/Bundle.ucl <<EOF
schema = "org.5bsd.capability-bundle";
bundle_id = "org.test.demo";
version = "1.0";
sequence = 1;
author = "Test";
publisher = "org.test";
units = ["demo"];
EOF
    cp policy Demo.cap/Units/demo.unit/Unit.ucl
    atf_check -s exit:0 "$capsign" sign -k key -o Demo.cap/Units/demo.unit/bin/demo demo
}
atf_test_case bundle_no_tmp
bundle_no_tmp_head() { atf_set require.progs 'cc openssl'; }
bundle_no_tmp_body()
{
    bundle_setup
    cat > no-tmp.c <<'EOF'
#include <errno.h>
#include <stdio.h>
FILE *tmpfile(void) { errno = EROFS; return NULL; }
EOF
    atf_check -s exit:0 -o ignore -e ignore cc -shared -fPIC no-tmp.c -o no-tmp.so
    atf_check -s exit:0 env LD_PRELOAD="$(pwd)/no-tmp.so" "$capsign" bundle-sign -k key Demo.cap
    atf_check -s exit:0 -o ignore env LD_PRELOAD="$(pwd)/no-tmp.so" "$capsign" bundle-verify -p public Demo.cap
}
atf_test_case bundle
bundle_head() { atf_set "require.progs" "cc openssl"; }
bundle_body()
{
    bundle_setup
    atf_check -s exit:0 "$capsign" bundle-sign -k key Demo.cap
    atf_check -s exit:0 -o ignore "$capsign" bundle-verify -p public Demo.cap
    printf 'x' >> Demo.cap/Units/demo.unit/bin/demo
    atf_check -s not-exit:0 -e ignore "$capsign" bundle-verify -p public Demo.cap
}
atf_test_case bundle_policy
bundle_policy_head() { atf_set "require.progs" "cc openssl"; }
bundle_policy_body()
{
    bundle_setup
    printf 'invalid external policy; program = "wrong"; {{{\n' > Demo.cap/Units/demo.unit/Unit.ucl
    atf_check -s exit:0 "$capsign" bundle-sign -k key Demo.cap
    atf_check -s exit:0 -o ignore "$capsign" bundle-verify -p public Demo.cap
    atf_check -s exit:0 -o file:policy "$capsign" show -p public Demo.cap/Units/demo.unit/bin/demo
}
atf_test_case bundle_embedded_only
bundle_embedded_only_head() { atf_set "require.progs" "cc openssl"; }
bundle_embedded_only_body()
{
    bundle_setup
    rm Demo.cap/Units/demo.unit/Unit.ucl
    mkdir Demo.cap/Units/demo.unit/bin/.debug
    printf debug > Demo.cap/Units/demo.unit/bin/.debug/demo.debug
    atf_check -s exit:0 "$capsign" bundle-sign -k key Demo.cap
    atf_check -s exit:0 -o ignore "$capsign" bundle-verify -p public Demo.cap
}
atf_test_case bundle_resources
bundle_resources_head() { atf_set "require.progs" "cc openssl"; }
bundle_resources_body()
{
    bundle_setup
    atf_check -s exit:0 "$capsign" bundle-sign -k key Demo.cap
    printf '# changed\n' >> Demo.cap/Bundle.ucl
    atf_check -s not-exit:0 -e ignore "$capsign" bundle-verify -p public Demo.cap
}
atf_test_case bundle_profiles
bundle_profiles_head() { atf_set "require.progs" "cc openssl"; }
bundle_profiles_body()
{
    bundle_setup
    rm demo policy.S Demo.cap/Units/demo.unit/bin/demo
    printf 'profiles { "org.test.demo/demo" { program = "demo"; activation { exec = true; } } }\n' > profiles
    atf_check -s exit:0 "$capsign" note -m profiles -o policy.S
    atf_check -s exit:0 -o ignore -e ignore cc demo.c policy.S -o demo
    atf_check -s exit:0 "$capsign" sign -k key -o Demo.cap/Units/demo.unit/bin/demo demo
    atf_check -s exit:0 "$capsign" bundle-sign -k key Demo.cap
    atf_check -s exit:0 -o ignore "$capsign" bundle-verify -p public Demo.cap
}
stage_mode_setup()
{
    unset CAPIMAGE_SIGNING_MODE CAPIMAGE_SIGNING_KEY CAPIMAGE_DEVELOPMENT_KEY
    unset CAPIMAGE_BUILD_CACHE CAPIMAGE_BUILD_LAYOUT CAPIMAGE_TARGET_ARCH
    unset CAPIMAGE_REQUIRE_SIGNATURES CAPIMAGE_CACHE_LIST
    bundle_setup
    # Model installworld's unsigned build-input executable, not a sealed output.
    cp demo Demo.cap/Units/demo.unit/bin/demo
    prepare="$(atf_get_srcdir)/prepare-stage.sh"
}
stage_mode_copy()
{
    mkdir -p "$1/Capabilities/System"
    cp -R Demo.cap "$1/Capabilities/System/"
    printf './Capabilities/System/Demo.cap/Bundle.ucl type=file uname=root gname=wheel mode=0444 tags=package=runtime\n' > "$1/METALOG"
}
atf_test_case stage_modes_unsigned
stage_modes_unsigned_head() { atf_set require.progs 'cc openssl'; }
stage_modes_unsigned_body()
{
    stage_mode_setup
    stage_mode_copy stage
    cp stage/METALOG before
    atf_check -s exit:0 -o match:'mode=unsigned' -e empty env CAPSIGN=/missing-tool sh "$prepare" -r stage
    atf_check -s exit:0 cmp before stage/METALOG
    atf_check -s exit:0 cmp demo stage/Capabilities/System/Demo.cap/Units/demo.unit/bin/demo
    [ -f stage/Capabilities/System/Demo.cap/Units/demo.unit/Unit.ucl ] || atf_fail 'removed development manifest'
    atf_check -s not-exit:0 -o empty -e match:'cache requires' env CAPIMAGE_BUILD_CACHE=yes sh "$prepare" -r stage
    atf_check -s not-exit:0 -o empty -e match:'cannot require signatures' env CAPIMAGE_SIGNING_MODE=unsigned CAPIMAGE_REQUIRE_SIGNATURES=yes sh "$prepare" -r stage
    [ ! -e stage/etc/capability/keys ] || atf_fail 'created a key in unsigned mode'
}
atf_test_case stage_modes_keys
stage_modes_keys_head() { atf_set require.progs 'cc openssl'; }
stage_modes_keys_body()
{
    stage_mode_setup
    stage_mode_copy existing
    # Auto with an existing key retains the previous package-staging opt-in.
    atf_check -s exit:0 -o match:'mode=signed' -e empty env CAPSIGN="$capsign" CAPIMAGE_SIGNING_KEY="$(pwd)/key" sh "$prepare" -r existing
    [ -f existing/etc/capability/require-signatures ] || atf_fail 'missing strict marker'
    atf_check -s exit:0 -o ignore "$capsign" bundle-verify -p public existing/Capabilities/System/Demo.cap
    stage_mode_copy development
    devkey="$(pwd)/development-keys/private.pem"
    atf_check -s exit:0 -o match:'generated development key' -e ignore env CAPSIGN="$capsign" CAPIMAGE_SIGNING_MODE=development CAPIMAGE_DEVELOPMENT_KEY="$devkey" sh "$prepare" -r development
    atf_check -s exit:0 -o inline:'600\n' stat -f %Lp "$devkey"
    cp "$devkey" saved-key
    atf_check -s exit:0 -o ignore -e ignore openssl pkey -in "$devkey" -pubout -out dev-public
    atf_check -s exit:0 -o ignore "$capsign" bundle-verify -p dev-public development/Capabilities/System/Demo.cap
    stage_mode_copy reused
    atf_check -s exit:0 -o save:reuse.out -e empty env CAPSIGN="$capsign" CAPIMAGE_SIGNING_MODE=development CAPIMAGE_REQUIRE_SIGNATURES=no CAPIMAGE_DEVELOPMENT_KEY="$devkey" sh "$prepare" -r reused
    atf_check -s exit:1 -o empty grep 'generated development key' reuse.out
    atf_check -s exit:0 cmp saved-key "$devkey"
    [ ! -e reused/etc/capability/require-signatures ] || atf_fail 'ignored relaxed test mode'
    atf_check -s exit:0 -o ignore "$capsign" bundle-verify -p dev-public reused/Capabilities/System/Demo.cap
    for stage in existing development reused; do
        atf_check -s exit:1 -o empty grep -R -l 'BEGIN PRIVATE KEY' "$stage"
        [ ! -e "$stage/Capabilities/System/Demo.cap/Units/demo.unit/Unit.ucl" ] || atf_fail 'retained duplicate signed policy'
    done
}
atf_test_case stage_modes_reject
stage_modes_reject_head() { atf_set require.progs 'cc openssl'; }
stage_modes_reject_body()
{
    stage_mode_setup
    stage_mode_copy stage
    atf_check -s not-exit:0 -o empty -e match:'requires CAPIMAGE_SIGNING_KEY' env CAPIMAGE_SIGNING_MODE=signed sh "$prepare" -r stage
    atf_check -s not-exit:0 -o empty -e match:'cannot accept a signing key' env CAPIMAGE_SIGNING_MODE=unsigned CAPIMAGE_SIGNING_KEY=key sh "$prepare" -r stage
    atf_check -s not-exit:0 -o empty -e match:'must be auto' env CAPIMAGE_SIGNING_MODE=unknown sh "$prepare" -r stage
    atf_check -s not-exit:0 -o empty -e match:'outside the staged image' env CAPSIGN="$capsign" CAPIMAGE_SIGNING_MODE=development CAPIMAGE_DEVELOPMENT_KEY="$(pwd)/stage/private.pem" sh "$prepare" -r stage
    [ ! -e stage/private.pem ] || atf_fail 'generated a private key inside image'
    chmod 644 key
    atf_check -s not-exit:0 -o empty -e match:'accessible to group or others' env CAPSIGN="$capsign" CAPIMAGE_SIGNING_KEY=key sh "$prepare" -r stage
    chmod 600 key
    ln -s key link-key
    atf_check -s not-exit:0 -o empty -e match:'not a symlink' env CAPSIGN="$capsign" CAPIMAGE_SIGNING_KEY=link-key sh "$prepare" -r stage
    mkdir -p stage/Capabilities/System/Demo.cap/Signature
    atf_check -s not-exit:0 -o empty -e match:'fresh stage' env CAPIMAGE_SIGNING_MODE=unsigned sh "$prepare" -r stage
    [ -f stage/Capabilities/System/Demo.cap/Units/demo.unit/Unit.ucl ] || atf_fail 'changed rejected stage'
}
atf_test_case stage_sign
stage_sign_head() { atf_set "require.progs" "cc openssl"; }
stage_sign_body()
{
    bundle_setup
    elfcache=$(atf_config_get elfcache /usr/sbin/elfcache)
    [ -x "$elfcache" ] || atf_skip "elfcache not installed"
    mkdir -p stage/Capabilities/System stage/lib stage/usr/lib
    mv Demo.cap stage/Capabilities/System/
    printf './Capabilities/System/Demo.cap/Bundle.ucl type=file uname=root gname=wheel mode=0444 tags=package=runtime\n' > stage/METALOG
    printf 'int value(void) { return 9; }\n' > library.c
    atf_check -s exit:0 -o ignore -e ignore cc -shared -fPIC -nostdlib library.c -o stage/lib/libdemo.so.1
    printf "/lib/libdemo.so.1\n" > selected
    atf_check -s exit:0 -o ignore -e ignore env CAPSIGN="$capsign" ELFCACHE="$elfcache" \
        sh "$(atf_get_srcdir)/sign-stage.sh" -c -e -l selected -r stage -k key
    [ ! -e stage/Capabilities/System/Demo.cap/Units/demo.unit/Unit.ucl ] || atf_fail 'runtime policy file retained'
    [ -f stage/etc/capability/require-signatures ] || atf_fail 'no enforcement marker'
    [ ! -e stage/key ] || atf_fail 'private key copied into stage'
    id=$("$capsign" key-id -p public)
    atf_check -s exit:0 cmp public "stage/etc/capability/keys/$id.pub"
    atf_check -s exit:0 -o ignore "$capsign" bundle-verify -p public stage/Capabilities/System/Demo.cap
    atf_check -s exit:0 -o ignore "$elfcache" verify -p public stage/usr/libdata/5bsd/cache/elf.cache
    atf_check -s not-exit:0 -e match:'already has a cache' env CAPSIGN="$capsign" ELFCACHE="$elfcache" \
        sh "$(atf_get_srcdir)/sign-stage.sh" -c -e -r stage -k key
}
atf_test_case stage_symlink_preflight
stage_symlink_preflight_head() { atf_set require.progs 'cc openssl'; }
stage_symlink_preflight_body()
{
    stage_mode_setup
    signer="$(atf_get_srcdir)/sign-stage.sh"
    keyid=$("$capsign" key-id -p public)
    for kind in capabilities system units bin etc var usr usr-libdata usr-5bsd usr-cache metalog cache public-key private-key marker; do
        stage=stage-$kind
        outside="$(pwd)/outside-$kind"
        stage_mode_copy "$stage"
        mkdir "$outside"
        printf 'outside sentinel\n' > "$outside/sentinel"
        cp "$stage/METALOG" "$outside/original-metalog"
        case "$kind" in
        capabilities) component=Capabilities;;
        system) component=Capabilities/System;;
        units) component=Capabilities/System/Demo.cap/Units;;
        bin) component=Capabilities/System/Demo.cap/Units/demo.unit/bin;;
        etc|var) component=$kind; mkdir "$stage/$component";;
        usr) component=usr; mkdir -p "$stage/$component";;
        usr-libdata) component=usr/libdata; mkdir -p "$stage/$component";;
        usr-5bsd) component=usr/libdata/5bsd; mkdir -p "$stage/$component";;
        usr-cache) component=usr/libdata/5bsd/cache; mkdir -p "$stage/$component";;
        *) component=;;
        esac
        if [ -n "$component" ]; then
            mv "$stage/$component" "$outside/tree"
            ln -s "$outside/tree" "$stage/$component"
        fi
        case "$kind" in
        metalog)
            rm "$stage/METALOG"
            ln -s "$outside/original-metalog" "$stage/METALOG";;
        cache)
            mkdir -p "$stage/usr/libdata/5bsd/cache"
            ln -s "$outside/nonexistent" "$stage/usr/libdata/5bsd/cache/elf.cache";;
        public-key)
            mkdir -p "$stage/etc/capability/keys"
            ln -s "$outside/sentinel" "$stage/etc/capability/keys/$keyid.pub";;
        private-key) cp key "$stage/private.pem";;
        marker) mkdir -p "$stage/etc/capability"; : > "$stage/etc/capability/require-signatures";;
        esac
        signing_key=key
        [ "$kind" != private-key ] || signing_key="$stage/private.pem"
        atf_check -s not-exit:0 -o ignore -e ignore env CAPSIGN="$capsign" sh "$signer" -r "$stage" -k "$signing_key"
        atf_check -s exit:0 cmp demo "$stage/Capabilities/System/Demo.cap/Units/demo.unit/bin/demo"
        atf_check -s exit:0 cmp "$outside/original-metalog" "$stage/METALOG"
        atf_check -s exit:0 -o inline:'outside sentinel\n' cat "$outside/sentinel"
        [ ! -e "$stage/Capabilities/System/Demo.cap/Signature" ] || atf_fail 'sealed rejected stage'
        for scratch in "$stage".signing.*; do
            [ ! -e "$scratch" ] || atf_fail 'rejected stage left scratch'
        done
    done
}
atf_test_case stage_preflight
stage_preflight_head() { atf_set require.progs 'cc openssl'; }
stage_preflight_body()
{
    bundle_setup
    mkdir -p stage/Capabilities/System
    mv Demo.cap stage/Capabilities/System/
    unit=stage/Capabilities/System/Demo.cap/Units/demo.unit
    cp "$unit/bin/demo" before-image
    printf './Capabilities/System/Demo.cap/Bundle.ucl type=file uname=root gname=wheel mode=0444 tags=package=runtime\n' > stage/METALOG
    cp stage/METALOG before-metalog
    mkdir -p stage/Capabilities/System/Demo.cap/Units/zzbad.unit/bin
    atf_check -s exit:0 -o ignore -e ignore cc demo.c -o stage/Capabilities/System/Demo.cap/Units/zzbad.unit/bin/missing-policy
    atf_check -s not-exit:0 -o ignore -e match:'cannot sign staged image: .*zzbad.unit/bin/missing-policy' \
        env CAPSIGN="$capsign" sh "$(atf_get_srcdir)/sign-stage.sh" -e -r stage -k key
    atf_check -s exit:0 cmp before-image "$unit/bin/demo"
    atf_check -s exit:0 cmp before-metalog stage/METALOG
    atf_check -s exit:0 cmp policy "$unit/Unit.ucl"
    [ ! -e stage/Capabilities/System/Demo.cap/Signature ] || atf_fail 'sealed incomplete stage'
    [ ! -e stage/etc/capability/require-signatures ] || atf_fail 'enabled incomplete stage'
}
atf_test_case direct_binary
direct_binary_head() { atf_set require.progs 'cc openssl'; }
direct_binary_body()
{
    setup
    atf_check -s exit:0 -o ignore -e ignore cc demo.c -o plain
    atf_check -s exit:0 "$capsign" sign --manifest policy -k key -o signed plain
    atf_check -s exit:0 -o file:policy "$capsign" show -p public signed
    atf_check -s exit:17 ./signed
    atf_check -s exit:0 "$capsign" sign -m policy -k key -o again signed
    atf_check -s exit:0 cmp signed again
    atf_check -s exit:0 -o ignore "$capsign" verify -p public signed again
    printf 'program = "different";\n' > different
    atf_check -s not-exit:0 -e match:'policy differs' "$capsign" sign -m different -k key -o replaced signed
    [ ! -e replaced ] || atf_fail 'published mismatched policy'
    printf x >> signed
    atf_check -s not-exit:0 -e ignore "$capsign" verify -p public signed
}
atf_test_case remove_signature
remove_signature_head() { atf_set require.progs 'cc openssl'; }
remove_signature_body()
{
    setup
    atf_check -s exit:0 "$capsign" sign -k key -o signed demo
    atf_check -s exit:0 "$capsign" remove -o unsigned signed
    atf_check -s exit:0 cmp demo unsigned
    atf_check -s exit:17 ./unsigned
    atf_check -s not-exit:0 -e ignore "$capsign" verify -p public unsigned
    atf_check -s exit:0 -o ignore "$capsign" verify -p public signed
    atf_check -s not-exit:0 -e ignore "$capsign" remove -o unsigned signed
    atf_check -s not-exit:0 -e ignore "$capsign" remove -o absent demo
    [ ! -e absent ] || atf_fail 'published unsigned input as removed signature'
    atf_check -s exit:0 -o ignore -e ignore cc demo.c -o plain
    atf_check -s exit:0 "$capsign" sign -m policy -k key -o signed-plain plain
    atf_check -s exit:0 "$capsign" remove -o restored-plain signed-plain
    atf_check -s exit:0 cmp plain restored-plain
}
atf_test_case recursive_bundle
recursive_bundle_head() { atf_set require.progs 'cc openssl'; }
recursive_bundle_body()
{
    bundle_setup
    rm Demo.cap/Units/demo.unit/bin/demo
    atf_check -s exit:0 -o ignore -e ignore cc demo.c -o Demo.cap/Units/demo.unit/bin/demo
    chmod 0555 Demo.cap/Units/demo.unit/bin/demo
    mkdir -p Demo.cap/Units/helper.unit/bin Demo.cap/Shared
    sed 's/units = \["demo"\]/units = ["demo", "helper"]/' Demo.cap/Bundle.ucl > bundle.ucl
    mv bundle.ucl Demo.cap/Bundle.ucl
    printf 'program = "helper"; activation { exec = true; } attributes = ["test.helper"];\n' > Demo.cap/Units/helper.unit/Unit.ucl
    atf_check -s exit:0 -o ignore -e ignore cc demo.c -o Demo.cap/Units/helper.unit/bin/helper
    mkdir collection
    cp -R Demo.cap collection/First.cap
    cp -R Demo.cap collection/Second.cap
    cp -R Demo.cap collection/First.cap/Shared/Nested.cap
    atf_check -s exit:0 -o match:'verified bundles=3' "$capsign" sign --recursive -k key -o signed-tree collection
    atf_check -s exit:0 -o match:'verified bundles=3' "$capsign" verify --recursive -p public signed-tree
    atf_check -s exit:0 -o file:Demo.cap/Units/helper.unit/Unit.ucl "$capsign" show -p public signed-tree/First.cap/Units/helper.unit/bin/helper
    atf_check -s exit:0 -o inline:'555\n' stat -f %Lp signed-tree/First.cap/Units/demo.unit/bin/demo
    [ ! -e signed-tree/First.cap/Units/demo.unit/Unit.ucl ] || atf_fail 'runtime policy file retained'
    [ -f collection/First.cap/Units/demo.unit/Unit.ucl ] || atf_fail 'removed source manifest'
    [ ! -e collection/First.cap/Signature ] || atf_fail 'modified source tree'
    atf_check -s not-exit:0 -o ignore -e ignore "$capsign" sign -r -k key -o signed-tree collection
    atf_check -s exit:0 -o ignore -e ignore openssl genpkey -algorithm ed25519 -out new-key
    atf_check -s exit:0 -o ignore -e ignore openssl pkey -in new-key -pubout -out new-public
    atf_check -s exit:0 -o ignore "$capsign" resign -r -p public -k new-key -o resigned-tree signed-tree
    atf_check -s exit:0 -o match:'verified bundles=3' "$capsign" verify -r -p new-public resigned-tree
    atf_check -s exit:0 -o file:Demo.cap/Units/helper.unit/Unit.ucl "$capsign" show -p new-public resigned-tree/First.cap/Units/helper.unit/bin/helper
    atf_check -s not-exit:0 -o ignore -e ignore "$capsign" verify -r -p public resigned-tree
    atf_check -s exit:0 -o match:'verified bundles=3' "$capsign" verify -r -p public signed-tree
    atf_check -s exit:0 -o match:'removed signatures=9' "$capsign" remove -r -o unsigned-tree signed-tree
    atf_check -s exit:0 cmp collection/First.cap/Units/demo.unit/bin/demo unsigned-tree/First.cap/Units/demo.unit/bin/demo
    [ ! -e unsigned-tree/First.cap/Signature ] || atf_fail 'outer seal retained'
    [ ! -e unsigned-tree/First.cap/Shared/Nested.cap/Signature ] || atf_fail 'nested seal retained'
    atf_check -s not-exit:0 -o ignore -e ignore "$capsign" verify -r -p public unsigned-tree
    atf_check -s exit:0 -o match:'verified bundles=3' "$capsign" verify -r -p public signed-tree
    printf x >> signed-tree/First.cap/Shared/Nested.cap/Bundle.ucl
    atf_check -s not-exit:0 -o ignore -e ignore "$capsign" verify -r -p public signed-tree
}
atf_test_case recursive_preview
recursive_preview_head() { atf_set require.progs 'cc openssl mtree'; }
recursive_preview_body()
{
    bundle_setup
    rm Demo.cap/Units/demo.unit/bin/demo
    atf_check -s exit:0 -o ignore -e ignore cc demo.c -o Demo.cap/Units/demo.unit/bin/demo
    mkdir -p collection/Outer.cap/Shared scratch
    cp -R Demo.cap/. collection/Outer.cap/
    cp -R Demo.cap collection/Outer.cap/Shared/Nested.cap
    chmod a-w collection/Outer.cap/Bundle.ucl collection/Outer.cap/Units/demo.unit/bin/demo
    mtree -c -k type,mode,size,sha256digest -p collection | sed '/^#/d' > before
    atf_check -s exit:0 -o match:'verified bundles=2' -e empty env TMPDIR="$(pwd)/scratch" "$capsign" sign -r -n -k key collection
    atf_check -s exit:0 -o empty ls -A scratch
    atf_check -s exit:0 -o match:'dry-run: no signed tree published' -e empty "$capsign" sign -r -n -k key -o scratch/new-tree collection
    atf_check -s exit:0 -o empty ls -A scratch
    mtree -c -k type,mode,size,sha256digest -p collection | sed '/^#/d' > after
    atf_check -s exit:0 -o empty diff before after
    atf_check -s exit:0 -o ignore "$capsign" sign -r -k key -o signed-tree collection
    atf_check -s exit:0 -o ignore -e ignore openssl genpkey -algorithm ed25519 -out next-key
    atf_check -s exit:0 -o ignore -e ignore openssl pkey -in next-key -pubout -out next-public
    atf_check -s exit:0 -o match:'dry-run: no signed tree published' -e empty env TMPDIR="$(pwd)/scratch" "$capsign" resign -r -n -k next-key -p public signed-tree
    atf_check -s exit:0 -o empty ls -A scratch
    atf_check -s exit:0 -o match:'verified bundles=2' "$capsign" verify -r -p public signed-tree
    atf_check -s not-exit:0 -o ignore -e ignore env TMPDIR="$(pwd)/scratch" "$capsign" resign -r -n -k next-key -p next-public signed-tree
    atf_check -s exit:0 -o empty ls -A scratch
    atf_check -s not-exit:0 -o ignore -e ignore "$capsign" sign -r -n -k key -o signed-tree collection
    atf_check -s not-exit:0 -o ignore -e ignore "$capsign" sign -r -n -k key -o scratch/wrong-suffix Demo.cap
    atf_check -s exit:0 -o empty ls -A scratch
    printf 'keep this file\n' > untouched
    ln -s "$(pwd)/untouched" collection/escape
    atf_check -s not-exit:0 -o ignore -e ignore env TMPDIR="$(pwd)/scratch" "$capsign" sign -r -n -k key collection
    atf_check -s exit:0 -o empty ls -A scratch
    atf_check -s exit:0 -o inline:'keep this file\n' cat untouched
}
atf_test_case recursive_reject
recursive_reject_head() { atf_set require.progs 'cc openssl'; }
recursive_reject_body()
{
    bundle_setup
    atf_check -s not-exit:0 -o ignore -e match:'outside the source tree' "$capsign" sign -r -k key -o Demo.cap/Inside.cap Demo.cap
    [ ! -e Demo.cap/Inside.cap ] || atf_fail 'created output inside source'
    atf_check -s not-exit:0 -o ignore -e match:'must end in .cap' "$capsign" sign -r -k key -o NotABundle Demo.cap
    [ ! -e NotABundle ] || atf_fail 'created invalid bundle output'
    atf_check -s not-exit:0 -o ignore -e match:'outside the source tree' "$capsign" sign -r -k key -o Root.cap /
    [ ! -e Root.cap ] || atf_fail 'started copying filesystem root'
    ln -s /etc/passwd Demo.cap/escape
    atf_check -s not-exit:0 -o ignore -e ignore "$capsign" sign -r -k key -o Signed.cap Demo.cap
    [ ! -e Signed.cap/Signature/Seal ] || atf_fail 'sealed escaping tree'
    atf_check -s not-exit:0 -o ignore -e ignore "$capsign" sign -r -m policy -k key -o Another.cap Demo.cap
}
atf_test_case verify_stage
verify_stage_head() { atf_set require.progs 'cc openssl'; }
verify_stage_body()
{
    bundle_setup
    helper=$(atf_config_get verify_stage "$(atf_get_srcdir)/verify-stage.sh")
    [ -f "$helper" ] || atf_fail 'missing stage verification helper'
    rm Demo.cap/Units/demo.unit/Unit.ucl
    atf_check -s exit:0 "$capsign" bundle-sign -k key Demo.cap
    mkdir -p stage/Capabilities/System stage/etc/capability
    : > stage/etc/capability/require-signatures
    cp -Rp Demo.cap stage/Capabilities/System/
    atf_check -s exit:0 -o match:'verified signed system bundles=1' -e empty env CAPSIGN="$capsign" sh "$helper" -r stage -p public
    atf_check -s exit:0 -o ignore -e ignore openssl genpkey -algorithm ed25519 -out wrong
    atf_check -s exit:0 -o ignore -e ignore openssl pkey -in wrong -pubout -out wrong-public
    atf_check -s not-exit:0 -o ignore -e ignore env CAPSIGN="$capsign" sh "$helper" -r stage -p wrong-public
    cp stage/Capabilities/System/Demo.cap/Units/demo.unit/bin/demo original
    printf corrupt >> stage/Capabilities/System/Demo.cap/Units/demo.unit/bin/demo
    atf_check -s not-exit:0 -o ignore -e ignore env CAPSIGN="$capsign" sh "$helper" -r stage -p public
    cp original stage/Capabilities/System/Demo.cap/Units/demo.unit/bin/demo
    rm stage/etc/capability/require-signatures
    atf_check -s not-exit:0 -o empty -e match:'does not require' env CAPSIGN="$capsign" sh "$helper" -r stage -p public
    : > stage/etc/capability/require-signatures
    mv stage/Capabilities/System outside
    ln -s ../../outside stage/Capabilities/System
    atf_check -s not-exit:0 -o empty -e match:'invalid stage directory' env CAPSIGN="$capsign" sh "$helper" -r stage -p public
}

atf_test_case stage_layout
stage_layout_head() { atf_set require.progs 'cc openssl'; }
stage_layout_body()
{
    [ "$(uname -p)" = amd64 ] || atf_skip 'layout generation currently supports amd64'
    stage_mode_setup
    stage_mode_copy stage
    elfcache=$(atf_config_get elfcache /usr/sbin/elfcache)
    [ -x "$elfcache" ] || atf_skip 'elfcache not installed'
    mkdir -p stage/lib stage/usr/lib stage/usr/libexec
    atf_check -s exit:0 -o ignore -e ignore cc demo.c -o stage/usr/libexec/elfcache-seed
    cp stage/usr/libexec/elfcache-seed seed-before
    printf 'int value(void) { return 9; }\n' > library.c
    atf_check -s exit:0 -o ignore -e ignore cc -shared -fPIC -nostdlib library.c -o stage/lib/libdemo.so.1
    printf '/lib/libdemo.so.1\n' > selected
    chmod 600 key
    # Validate unsupported inputs before any executable or key metadata changes.
    for target in aarch64 riscv64; do
        atf_check -s not-exit:0 -o empty -e match:'requires target amd64' env \
            CAPIMAGE_SIGNING_MODE=signed CAPIMAGE_SIGNING_KEY="$(pwd)/key" \
            CAPIMAGE_BUILD_CACHE=yes CAPIMAGE_BUILD_LAYOUT=yes CAPIMAGE_TARGET_ARCH="$target" \
            CAPSIGN="$capsign" ELFCACHE="$elfcache" sh "$prepare" -r stage
    done
    atf_check -s exit:0 cmp seed-before stage/usr/libexec/elfcache-seed
    atf_check -s exit:0 -o ignore -e ignore env \
        CAPIMAGE_SIGNING_MODE=signed CAPIMAGE_SIGNING_KEY="$(pwd)/key" \
        CAPIMAGE_BUILD_CACHE=yes CAPIMAGE_BUILD_LAYOUT=yes CAPIMAGE_TARGET_ARCH=amd64 \
        CAPIMAGE_CACHE_LIST="$(pwd)/selected" CAPSIGN="$capsign" ELFCACHE="$elfcache" \
        sh "$prepare" -r stage
    atf_check -s exit:0 -o ignore env CAPSIGN="$capsign" ELFCACHE="$elfcache" \
        sh "$(atf_get_srcdir)/verify-stage.sh" -r stage -p public
    grep '^./usr/libexec/elfcache-seed .*tags=package=elfcache$' stage/METALOG || atf_fail 'seed package metadata missing'
    grep '^./usr/libdata/5bsd/cache/elf.layout.sig .*tags=package=runtime$' stage/METALOG || atf_fail 'layout package metadata missing'
    cp stage/usr/libdata/5bsd/cache/elf.layout.sig seal
    chmod u+w stage/usr/libdata/5bsd/cache/elf.layout.sig
    printf x >> stage/usr/libdata/5bsd/cache/elf.layout.sig
    atf_check -s not-exit:0 -o ignore -e ignore env CAPSIGN="$capsign" ELFCACHE="$elfcache" \
        sh "$(atf_get_srcdir)/verify-stage.sh" -r stage -p public
    cp seal stage/usr/libdata/5bsd/cache/elf.layout.sig
    chmod u+w stage/usr/libexec/elfcache-seed
    printf x >> stage/usr/libexec/elfcache-seed
    atf_check -s not-exit:0 -o ignore -e ignore env CAPSIGN="$capsign" ELFCACHE="$elfcache" \
        sh "$(atf_get_srcdir)/verify-stage.sh" -r stage -p public
}

atf_init_test_cases()
{
    atf_add_test_case stage_layout
    atf_add_test_case verify_stage
    atf_add_test_case resign_image
    atf_add_test_case remove_signature
    atf_add_test_case direct_binary
    atf_add_test_case recursive_bundle
    atf_add_test_case recursive_preview
    atf_add_test_case recursive_reject
    atf_add_test_case executable
    atf_add_test_case inspection
    atf_add_test_case command_options
    atf_add_test_case copy_limits
    atf_add_test_case batch_verify
    atf_add_test_case validate_policy
    atf_add_test_case dry_run
    atf_add_test_case strip_order
    atf_add_test_case no_clobber
    atf_add_test_case detached
    atf_add_test_case bundle
    atf_add_test_case bundle_no_tmp
    atf_add_test_case bundle_policy
    atf_add_test_case bundle_embedded_only
    atf_add_test_case bundle_resources
    atf_add_test_case bundle_profiles
    atf_add_test_case stage_modes_unsigned
    atf_add_test_case stage_modes_keys
    atf_add_test_case stage_modes_reject
    atf_add_test_case stage_sign
    atf_add_test_case stage_symlink_preflight
    atf_add_test_case stage_preflight
}
