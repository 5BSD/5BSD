#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# 5BSD build orchestration. Installation is an explicit separate command.
set -eu
set -o pipefail
umask 077
usage()
{
    cat >&2 <<'USAGE'
usage: build-bsd [plan] build|stage|packages|verify|deploy|bsdinstall|media [options]
       build-bsd status run-directory
options: --config FILE --jobs COUNT|auto --kernel NAME
         --format text|json (plan only)
         --arch native|amd64|arm64|riscv64
         --board generic|rpi4|rpi5|rpi-zero2w
         --hardware-profile FILE --distfiles DIRECTORY (packages/build)
         --kernel-dir DIRECTORY --src-conf FILE --make-conf FILE
         --pkg-key RSA_PRIVATE.pem --production --incremental
         --build-profile production|development|debug
         --allow-debug-publication (test packages only)
         --output /usr/obj/new-stage
         --signing unsigned|development|signed --key private.pem
         --development-key private.pem --relaxed-signatures
         --cache [--cache-layout] [--library-list FILE] --ports DIRECTORY
         --publish-repository DIRECTORY (packages/build)
         --root DIRECTORY (verify/deploy) --public-key trusted-code.pem
         --repository GENERATION --pkg-public-key FILE (deploy/bsdinstall/media)
         --bootenv NAME (deploy)
         --media-format all|iso|memstick (media)
USAGE
    exit 64
}
fail() { echo "build-bsd: $*" >&2; exit 1; }
# Resolve existing ancestors without creating directories. Missing suffixes
# remain literal; traversal is rejected so symlinked parents cannot hide a
# stage/repository boundary until after the expensive build.
future_directory()
(
    candidate=$1
    suffix=
    case "$candidate/" in */../*|*/./*) fail 'path must not contain traversal';; esac
    while [ ! -e "$candidate" ] && [ ! -L "$candidate" ]; do
        suffix=/$(basename "$candidate")$suffix
        candidate=$(dirname "$candidate")
    done
    [ -d "$candidate" ] || fail 'path ancestor must be a directory'
    physical=$(cd "$candidate" && pwd -P)
    resolved=${physical%/}$suffix
    printf '%s\n' "${resolved:-/}"
)
check_key_permissions()
{
    [ -f "$1" ] && [ ! -L "$1" ] && [ -r "$1" ] || fail 'private key must be a readable regular file, not a symlink'
    permissions=$(stat -f %Lp "$1")
    [ $((0$permissions & 077)) = 0 ] || fail 'private key must not be accessible to group or others'
}
check_key_parent()
{
    if [ -d "$1" ]; then
        permissions=$(stat -f %Lp "$1")
        [ $((0$permissions & 022)) = 0 ] || fail 'private key directory must not be writable by group or others'
    fi
}
plan=no
plan_format=text
locked=no
action=
architecture=native
board=generic
kernel_selected=${KERNCONF:+yes}
kernel=${KERNCONF:-GENERIC}
jobs=auto
kernel_dir=
pkg_key=
verify_root=
public_key=
repository=
publish_repository=/usr/obj/usr/src/repo
publish_selected=no
pkg_public_key=
bootenv=
media_format=all
media_format_selected=no
src_conf=/etc/src.conf
make_conf=/etc/make.conf
config=
src_conf_selected=no
make_conf_selected=no
production=no
build_profile=auto
allow_debug_publication=no
clean=yes
stage=
mode=auto
key=
devkey=/usr/obj/usr/src/signing-keys/development.pem
enforce=
cache=no
cache_layout=no
libraries=
ports_selected=no
hardware_profile=
distfiles=
devkey_selected=no
ports=${PORTSDIR:-/usr/obj/5BSD-ports}
# This is data, never shell input. Exact key=value records, blank lines and
# whole-line comments; no expansion, quoting, includes, or duplicate settings.
load_config()
{
    [ -f "$1" ] && [ ! -L "$1" ] && [ -r "$1" ] || fail 'config must be a readable regular file, not a symlink'
    seen=' '
    line_number=0
    while IFS= read -r record || [ -n "$record" ]; do
        line_number=$((line_number + 1))
        case "$record" in ''|\#*) continue;; esac
        case "$record" in *[[:cntrl:]]*) fail "control character in config line $line_number";; esac
        case "$record" in *=*) ;; *) fail "expected key=value in config line $line_number";; esac
        setting=${record%%=*}
        value=${record#*=}
        [ -n "$value" ] || fail "empty config setting: $setting"
        case "$seen" in *" $setting "*) fail "duplicate config setting: $setting";; esac
        seen="$seen$setting "
        case "$setting" in
        build_profile) build_profile=$value;;
        board) board=$value;;
        arch) architecture=$value;;
        jobs) jobs=$value;;
        kernel) kernel=$value; kernel_selected=yes;;
        kernel_dir) kernel_dir=$value;;
        pkg_key) pkg_key=$value;;
        root) verify_root=$value;;
        public_key) public_key=$value;;
        repository) repository=$value;;
        publish_repository) publish_repository=$value; publish_selected=yes;;
        pkg_public_key) pkg_public_key=$value;;
        bootenv) bootenv=$value;;
        media_format) media_format=$value;;
        src_conf) src_conf=$value; src_conf_selected=yes;;
        make_conf) make_conf=$value; make_conf_selected=yes;;
        signing) mode=$value;;
        key) key=$value;;
        development_key) devkey=$value; devkey_selected=yes;;
        ports) ports=$value;;
        hardware_profile) hardware_profile=$value;;
        distfiles) distfiles=$value;;
        library_list) libraries=$value;;
        output) stage=$value;;
        allow_debug_publication|production|incremental|cache|cache_layout|relaxed_signatures)
            case "$value" in yes|no) ;; *) fail "$setting must be yes or no";; esac
            case "$setting" in
            allow_debug_publication) allow_debug_publication=$value;;
            production) if [ "$value" = yes ]; then build_profile=production; else build_profile=development; fi;;
            incremental) if [ "$value" = yes ]; then clean=no; else clean=yes; fi;;
            cache) cache=$value;;
            cache_layout) cache_layout=$value;;
            relaxed_signatures) if [ "$value" = yes ]; then enforce=no; else enforce=; fi;;
            esac;;
        *) fail "unknown config setting: $setting";;
        esac
    done < "$1"
}
# Load configuration before parsing options so CLI precedence is independent
# of where --config occurs. A second config is an error, not a hidden merge.
scan_config()
{
    while [ $# -gt 0 ]; do
        case "$1" in
        --config)
            [ $# -ge 2 ] && [ -n "$2" ] || usage
            [ -z "$config" ] || fail 'only one --config is allowed'
            config=$2
            shift 2;;
        --publish-repository|--format|--hardware-profile|--distfiles|--board|--build-profile|--media-format|--repository|--pkg-public-key|--bootenv|--arch|--root|--public-key|--pkg-key|--kernel-dir|--jobs|--src-conf|--make-conf|--kernel|--output|--signing|--key|--development-key|--library-list|--ports)
            [ $# -ge 2 ] || usage
            shift 2;;
        *) shift;;
        esac
    done
    [ -z "$config" ] || load_config "$config"
}
parse()
{
    [ "${1:-}" != --lock-held ] || { locked=yes; shift; }
    [ "${1:-}" != plan ] || { plan=yes; shift; }
    action=${1:-}
    [ $# -gt 0 ] || usage
    shift
    case "$action" in
    status)
        [ $# = 1 ] || usage
        [ -f "$1/status" ] || fail 'not a build run directory'
        cat "$1/status"
        exit 0
        ;;
    build|stage|packages|verify|deploy|bsdinstall|media) ;;
    *) usage;;
    esac
    while [ $# -gt 0 ]; do
        case "$1" in
        --production) build_profile=production; shift;;
        --allow-debug-publication) allow_debug_publication=yes; shift;;
        --incremental) clean=no; shift;;
        --relaxed-signatures) enforce=no; shift;;
        --cache) cache=yes; shift;;
        --cache-layout) cache_layout=yes; shift;;
        --publish-repository|--format|--hardware-profile|--distfiles|--board|--build-profile|--media-format|--repository|--pkg-public-key|--bootenv|--arch|--root|--public-key|--pkg-key|--kernel-dir|--config|--jobs|--src-conf|--make-conf|--kernel|--output|--signing|--key|--development-key|--library-list|--ports)
            [ $# -ge 2 ] && [ -n "$2" ] || usage
            case "$1" in
            --format) plan_format=$2;;
            --hardware-profile) hardware_profile=$2;;
            --distfiles) distfiles=$2;;
            --board) board=$2;;
            --build-profile) build_profile=$2;;
            --media-format) media_format=$2; media_format_selected=yes;;
            --publish-repository) publish_repository=$2; publish_selected=yes;;
            --repository) repository=$2;; --pkg-public-key) pkg_public_key=$2;; --bootenv) bootenv=$2;;
            --arch) architecture=$2;;
            --root) verify_root=$2;; --public-key) public_key=$2;;
            --pkg-key) pkg_key=$2;; --kernel-dir) kernel_dir=$2;;
            --config) :;; --jobs) jobs=$2;;
            --src-conf) src_conf=$2; src_conf_selected=yes;;
            --make-conf) make_conf=$2; make_conf_selected=yes;;
            --kernel) kernel=$2; kernel_selected=yes;; --output) stage=$2;; --signing) mode=$2;;
            --key) key=$2;; --development-key) devkey=$2; devkey_selected=yes;;
            --library-list) libraries=$2;; --ports) ports=$2; ports_selected=yes;;
            esac
            shift 2
            ;;
        *) usage;;
        esac
    done
}
# status has no build configuration side effects.
case "${1:-}" in status) ;; *) scan_config "$@";; esac
parse "$@"
case "$plan_format" in
    text) ;;
    json) [ "$plan" = yes ] || fail '--format json requires plan';;
    *) fail '--format must be text or json';;
esac
# System builds always complete the pkgbase pipeline. stage is exclusively
# a private VM/development image operation and never installs the host.
[ "$action" != build ] || action=packages
[ "$media_format_selected" = no ] || [ "$action" = media ] || fail '--media-format applies only to media'
if [ "$cache" = yes ]; then
    case "$action" in packages|stage) ;; *) fail '--cache applies only to build, packages or stage';; esac
fi
[ -z "$pkg_key" ] || [ "$action" = packages ] || fail '--pkg-key applies only to build or packages'
# Board selection controls build defaults; board boot-image qualification is separate.
case "$board" in
    generic) ;;
    rpi4|rpi5|rpi-zero2w)
        case "$architecture" in native|arm64|aarch64) architecture=arm64;;
        *) fail 'Raspberry Pi board profiles require arm64';; esac
        if [ "${kernel_selected:-}" != yes ]; then
            case "$board" in rpi5) kernel=GENERIC;; *) kernel=GENERIC-RPI;; esac
        fi
        case "$action" in
        stage|packages) ;;
        *) fail 'board image backend is not integrated yet; board selection currently applies to stage/build/packages only';;
        esac
        ;;
    *) fail '--board must be generic, rpi4, rpi5 or rpi-zero2w';;
esac
host_arch=$(uname -p)
[ "$architecture" != native ] || architecture=$host_arch
case "$architecture" in
amd64) target_machine=amd64; target_arch=amd64;;
arm64|aarch64) target_machine=arm64; target_arch=aarch64; architecture=arm64;;
riscv|riscv64) target_machine=riscv; target_arch=riscv64; architecture=riscv64;;
*) fail '--arch must be native, amd64, arm64, or riscv64';;
esac
cross=no
[ "$target_arch" = "$host_arch" ] || cross=yes
case "$build_profile" in
    auto) if [ "$action" = packages ]; then build_profile=production; else build_profile=development; fi;;
    production|development|debug) case "$action" in packages|stage) ;; *) fail '--build-profile applies only to build, packages or stage';; esac;;
    *) fail '--build-profile must be production, development or debug';;
esac
[ "$build_profile" != production ] || production=yes
if [ "$action" = packages ] && [ "$production" = no ]; then
    [ "$allow_debug_publication" = yes ] || fail 'development/debug publication requires --allow-debug-publication for a test generation'
fi
if [ "$allow_debug_publication" = yes ]; then
    [ "$action" = packages ] && [ "$production" = no ] || fail '--allow-debug-publication requires development/debug packages'
fi
# Use the adapter shipped with this frontend, never a backend path from the environment.
backend_dir=$(CDPATH= cd "$(dirname "$0")" && pwd -P)
if [ -f "$backend_dir/bsd-make.subr" ]; then
    . "$backend_dir/bsd-make.subr"
else
    . /usr/libexec/build-bsd/bsd-make.subr
fi
bsd_make_preflight
emit_plan()
{
    if [ -f "$backend_dir/plan-record.py" ]; then
        /usr/local/bin/python3.12 "$backend_dir/plan-record.py" "$@"
    else
        /usr/local/bin/python3.12 /usr/libexec/build-bsd/plan-record.py "$@"
    fi
}
case "$jobs" in
    auto) jobs=$(sysctl -n hw.ncpu);;
    ''|*[!0-9]*) fail '--jobs must be a positive integer or auto';;
esac
# Bound decimal input before shell arithmetic, including leading zeroes.
[ "${#jobs}" -le 6 ] && [ "$jobs" -gt 0 ] && [ "$jobs" -le 104857 ] || fail '--jobs is out of range'
for selected_conf in src_conf make_conf; do
    case "$selected_conf" in
    src_conf) conf_path=$src_conf; explicit=$src_conf_selected;;
    make_conf) conf_path=$make_conf; explicit=$make_conf_selected;;
    esac
    case "$conf_path" in /*) ;; *) fail 'world configuration paths must be absolute';; esac
    case "$conf_path" in *[[:cntrl:]]*) fail 'world configuration paths must not contain control characters';; esac
    if [ "$explicit" = yes ]; then
        [ "$conf_path" = /dev/null ] || { [ -f "$conf_path" ] && [ -r "$conf_path" ]; } || fail 'world configuration file is not readable'
    fi
done
[ -f /usr/src/Makefile ] || fail '/usr/src is required'
if [ "$action" = verify ]; then
    [ -n "$verify_root" ] && [ -d "$verify_root" ] && [ ! -L "$verify_root" ] || fail 'verify requires --root DIRECTORY'
    verify_root=$(realpath "$verify_root")
    [ "$verify_root" != / ] || fail 'verify requires an alternate root'
    [ -n "$public_key" ] && [ -r "$public_key" ] && [ -f "$public_key" ] || fail 'verify requires --public-key FILE'
    public_key=$(realpath "$public_key")
    [ -z "$stage" ] || fail '--output applies only to stage'
elif [ "$action" = deploy ] || [ "$action" = bsdinstall ] || [ "$action" = media ]; then
    if [ "$action" = deploy ]; then
        [ -n "$verify_root$bootenv" ] || fail 'deploy requires --root or --bootenv'
        [ -z "$verify_root" ] || [ -z "$bootenv" ] || fail '--root and --bootenv are mutually exclusive'
    elif [ "$action" = bsdinstall ]; then
        [ -z "$verify_root$bootenv" ] || fail 'bsdinstall selects target disks interactively; --root/--bootenv apply to deploy'
        [ "$cross" = no ] || fail 'bsdinstall requires the native architecture; use media for foreign targets'
        [ "$plan" = yes ] || [ "$(id -u)" = 0 ] || fail 'bsdinstall requires a root shell for disk setup and installation'
    else
        [ -z "$verify_root$bootenv" ] || fail 'media uses --output, not --root or --bootenv'
    fi
    [ -f "$public_key" ] && [ -r "$public_key" ] || fail 'deploy/bsdinstall/media requires --public-key'
    [ -f "$pkg_public_key" ] && [ -r "$pkg_public_key" ] || fail 'deploy/bsdinstall/media requires --pkg-public-key'
    public_key=$(realpath "$public_key")
    pkg_public_key=$(realpath "$pkg_public_key")
    [ -d "$repository" ] || fail 'deploy/bsdinstall/media requires --repository'
    repository=$(realpath "$repository")
    [ -f "$repository/publication.json" ] || fail 'repository is not a complete publication'
    [ "$action" = media ] || [ -z "$stage" ] || fail '--output applies only to stage or media'
else
    [ -z "$verify_root$public_key" ] || fail '--root and --public-key apply only to verify or deploy'
fi
[ "$action" = deploy ] || [ "$action" = bsdinstall ] || [ "$action" = media ] || [ -z "$repository$pkg_public_key$bootenv" ] || fail 'repository settings apply only to deploy, bsdinstall or media'
case "$kernel" in ''|*[!a-zA-Z0-9_.-]*) fail 'kernel must be a configuration name';; esac
if [ -n "$kernel_dir" ]; then
    kernel_dir=$(realpath "$kernel_dir") || fail 'kernel configuration directory is not accessible'
    [ -f "$kernel_dir/$kernel" ] && [ -r "$kernel_dir/$kernel" ] || fail 'selected kernel configuration is not readable'
fi
if [ -n "$pkg_key" ]; then
    case "$pkg_key" in *[!a-zA-Z0-9_./-]*) fail 'package key path must contain only letters, digits, underscore, dot, slash or hyphen';; esac
    check_key_permissions "$pkg_key"
    pkg_key=$(realpath "$pkg_key")
    check_key_parent "$(dirname "$pkg_key")"
    case "$pkg_key" in /usr/obj/usr/src/repo|/usr/obj/usr/src/repo/*) fail 'private keys must be outside the publication repository';; esac
    # The base package make target accepts the legacy RSA key-file argument.
    # Code-signing Ed25519 keys remain separate identities.
    openssl rsa -in "$pkg_key" -check -noout </dev/null >/dev/null 2>&1 || fail 'package signing requires an unencrypted RSA private key'
fi
case "$mode" in auto|unsigned|development|signed) ;; *) fail 'unknown signing mode';; esac
if [ "$mode" = auto ]; then
    if [ -n "$key" ]; then mode=signed; else mode=unsigned; fi
fi
case "$key$devkey" in *[[:cntrl:]]*) fail 'private key paths must not contain control characters';; esac
case "$mode" in
signed)
    [ -n "$key" ] && [ -f "$key" ] && [ ! -L "$key" ] && [ -r "$key" ] || fail 'signed mode requires a readable regular --key, not a symlink'
    key=$(realpath "$key")
    check_key_permissions "$key"
    check_key_parent "$(dirname "$key")"
    ;;
*) [ -z "$key" ] || fail '--key requires signed mode';;
esac
[ "$devkey_selected" = no ] || [ "$mode" = development ] || fail '--development-key requires development signing'
[ "$ports_selected" = no ] || [ "$action" = packages ] || fail '--ports applies only to packages'
case "$devkey" in /*) ;; *) fail '--development-key must be an absolute path';; esac
if [ "$mode" = development ]; then
    devparent=$(future_directory "$(dirname "$devkey")")
    devkey=${devparent%/}/$(basename "$devkey")
    case "$(basename "$devkey")" in .|..) fail 'invalid private key filename';; esac
    check_key_parent "$devparent"
    if [ -e "$devkey" ] || [ -L "$devkey" ]; then check_key_permissions "$devkey"; fi
fi
case "$key:$devkey" in /usr/obj/usr/src/repo:*|/usr/obj/usr/src/repo/*|*:/usr/obj/usr/src/repo|*:/usr/obj/usr/src/repo/*) fail 'private keys must be outside the publication repository';; esac
if [ -n "$libraries" ]; then libraries=$(realpath "$libraries") || fail 'library list is not accessible'; fi
[ "$publish_selected" = no ] || [ "$action" = packages ] || fail '--publish-repository applies only to packages/build'
case "$publish_repository" in /*) ;; *) fail 'publication destination must be absolute';; esac
publish_repository=$(future_directory "$publish_repository")
case "$publish_repository" in /|/usr|/usr/src|/usr/src/*|/home|/home/*)
    fail 'publication destination must be separate from source and home directories';;
esac
for signing_key in "$key" "$devkey" "$pkg_key"; do
    case "$signing_key" in "$publish_repository"|"$publish_repository"/*)
        fail 'private keys must be outside the publication destination';;
    esac
done
if [ "$mode" = unsigned ]; then
    [ "$cache" = no ] || fail '--cache requires development or signed mode'
    [ -z "$enforce" ] || fail '--relaxed-signatures applies to signed stages'
fi
if [ "$cache_layout" = yes ]; then
    [ "$cache" = yes ] || fail '--cache-layout requires --cache'
    [ "$target_arch" = amd64 ] || fail '--cache-layout currently requires amd64'
    case "$action" in packages|stage) ;; *) fail '--cache-layout applies only to packages or stage';; esac
fi
[ -z "$libraries" ] || { [ "$cache" = yes ] && [ -f "$libraries" ] && [ -r "$libraries" ]; } || fail '--library-list requires --cache and a readable file'
if [ "$action" = packages ]; then
    [ -z "$stage" ] || fail 'packages uses the maintained package staging directories'
fi
runid=$(date -u +%Y%m%dT%H%M%SZ)-$$
run=/usr/obj/usr/src/build-runs/$runid
native=$run/native-tools
case "$media_format" in all|iso|memstick) ;; *) fail '--media-format must be all, iso, or memstick';; esac
if [ "$action" = stage ] || [ "$action" = media ]; then
    if [ "$action" = media ]; then
        stage=${stage:-/usr/obj/usr/src/media/$runid}
    else
        stage=${stage:-/usr/obj/usr/src/stages/$runid}
    fi
    case "$stage" in /usr/obj/*) ;; *) fail 'staging must be under /usr/obj';; esac
    case "$stage/" in */../*|*/./*|*[[:space:]]*) fail 'stage path must be absolute and contain no traversal or whitespace';; esac
    [ ! -e "$stage" ] && [ ! -L "$stage" ] || fail 'output stage must be a new path'
    stageparent=$(future_directory "$(dirname "$stage")")
    stage=${stageparent%/}/$(basename "$stage")
    case "$stage" in /usr/obj/*) ;; *) fail 'stage parent resolves outside /usr/obj';; esac
    case "$key:$devkey" in "$stage":*|"$stage"/*|*:"$stage"|*:"$stage"/*) fail 'private keys must be outside the stage';; esac
fi
# Never let inherited make overrides redirect a build or repository into a
# live root or historical home-directory staging tree.
unset MAKEFLAGS MFLAGS MAKEOVERRIDES MAKELEVEL MAKEOBJDIRPREFIX DESTDIR DISTDIR
unset SRCCONF SRC_ENV_CONF __MAKE_CONF ALLOW_DEBUG_MALLOC TARGET TARGET_ARCH
unset PKG_REPO_SIGNING_KEY HARDWARE_SIGNING_KEY KERNCONFDIR
unset REPODIR PUBLISH_REPODIR BASE_REPOSITORY HARDWARE_REPO COMPLETE_REPOSITORY WSTAGEDIR KSTAGEDIR SSTAGEDIR
if [ "$plan" = no ] && [ "$locked" = no ]; then
    mkdir -p /usr/obj/usr/src || fail 'OS permissions prevent writing /usr/obj; run with appropriate privileges'
    exec lockf -t 0 /usr/obj/usr/src/.bsd-build.lock /bin/sh "$0" --lock-held "$@"
fi
step=initializing
number=0
if [ "$plan" = no ]; then
    mkdir -p /usr/obj/usr/src/build-runs || fail 'OS permissions prevent creating build logs under /usr/obj'
    mkdir "$run"
    finish()
    {
        result=$?
        if [ "$result" != 0 ]; then
            printf 'failed step=%s exit=%s logs=%s\n' "$step" "$result" "$run" > "$run/status"
            cat "$run/status" >&2
        fi
    }
    trap finish EXIT
fi
run_step()
{
    step=$1
    shift
    number=$((number + 1))
    if [ "$plan_format" = json ]; then
        emit_plan step "$number" "$step" "$@"
        return
    fi
    printf '%s:' "$step"
    printf ' %s' "$@"
    printf '\n'
    [ "$plan" = no ] || return 0
    printf 'running step=%s logs=%s\n' "$step" "$run" > "$run/status"
    if [ "$step" = bsdinstall ]; then
        # Preserve the terminal for dialogs. The helper retains bsdinstall's
        # own log beside its verified snapshot and recovery files.
        "$@"
    else
        "$@" 2>&1 | tee "$run/$(printf '%02d' "$number")-$step.log"
    fi
}
make_step()
{
    bsd_make_build "$@"
}
if [ "$plan_format" = json ]; then
    emit_plan request "$action" "$target_machine" "$target_arch" "$kernel" "$board" "$build_profile" "$mode" "$jobs" bsd-make native-ports
else
printf 'build-bsd: action=%s cpus=%s kernel=%s production=%s clean=%s signing=%s arch=%s target=%s/%s cross=%s board=%s\n' "$action" "$jobs" "$kernel" "$production" "$clean" "$mode" "$architecture" "$target_machine" "$target_arch" "$cross" "$board"
fi
if [ "$action" = verify ] || [ "$action" = deploy ] || [ "$action" = bsdinstall ] || [ "$action" = media ] || [ "$mode" != unsigned ]; then
    run_step host-tools-directory mkdir -p "$native"
    run_step host-tools make -C "$native" -f /usr/src/tools/build/capimage/host-tools.mk -j "$jobs" SRCTOP=/usr/src
fi
if [ "$action" = verify ]; then
    run_step verify env CAPSIGN="$native/capsign" ELFCACHE="$native/elfcache" sh /usr/src/tools/build/capimage/verify-stage.sh -r "$verify_root" -p "$public_key"
    if [ "$plan" = no ]; then
        printf 'complete action=verify logs=%s root=%s\n' "$run" "$verify_root" > "$run/status"
        cat "$run/status"
    fi
    exit 0
fi
if [ "$action" = deploy ]; then
    if [ -n "$bootenv" ]; then set -- --bootenv "$bootenv"; else set -- --root "$verify_root"; fi
    run_step deploy /usr/local/bin/python3.12 /usr/src/tools/build/capimage/deploy.py --repository "$repository" --pkg-public-key "$pkg_public_key" --public-key "$public_key" --kernel "$kernel" --capsign "$native/capsign" --elfcache "$native/elfcache" "$@"
    if [ "$plan" = no ]; then
        printf 'complete action=deploy logs=%s root=%s bootenv=%s\n' "$run" "$verify_root" "$bootenv" > "$run/status"
        cat "$run/status"
    fi
    exit 0
fi
if [ "$action" = bsdinstall ]; then
    run_step bsdinstall /usr/local/bin/python3.12 /usr/src/tools/build/capimage/installer.py --repository "$repository" --pkg-public-key "$pkg_public_key" --public-key "$public_key" --kernel "$kernel" --capsign "$native/capsign" --elfcache "$native/elfcache"
    if [ "$plan" = no ]; then
        printf 'complete action=bsdinstall logs=%s\n' "$run" > "$run/status"
        cat "$run/status"
    fi
    exit 0
fi
if [ "$action" = media ]; then
    run_step media-code-key "$native/capsign" key-id -p "$public_key"
    run_step media-parent mkdir -p "$(dirname "$stage")"
    run_step media-directory mkdir "$stage"
    case "$media_format" in
    all) set -- disc1.iso memstick.img;;
    iso) set -- disc1.iso;;
    memstick) set -- memstick.img;;
    esac
    bsd_make_media "$@"
    if [ "$plan" = no ]; then
        case "$media_format" in all) set -- disc1.iso memstick.img;; iso) set -- disc1.iso;; memstick) set -- memstick.img;; esac
        for artifact do
            [ -s "$stage/$artifact" ] || fail "release did not produce $artifact"
        done
        (cd "$stage" && sha256 "$@") > "$stage/CHECKSUM.SHA256"
        (cd "$stage" && sha512 "$@") > "$stage/CHECKSUM.SHA512"
        printf 'complete action=media logs=%s output=%s\n' "$run" "$stage" > "$run/status"
        cat "$run/status"
    fi
    exit 0
fi
clean_option=WITH_CLEAN=yes
[ "$clean" = yes ] || clean_option=WITHOUT_CLEAN=yes
make_step buildworld "$clean_option"
make_step buildkernel "$clean_option"
signing_step()
{
    target=$1
    shift
    make_step "$target" "$@" CAPIMAGE_SIGNING_MODE="$mode" CAPIMAGE_SIGNING_KEY="$key" \
        CAPIMAGE_DEVELOPMENT_KEY="$devkey" CAPIMAGE_REQUIRE_SIGNATURES="$enforce" \
        CAPIMAGE_BUILD_CACHE="$cache" CAPIMAGE_BUILD_LAYOUT="$cache_layout" CAPIMAGE_CACHE_LIST="$libraries" \
        CAPSIGN_HOST="$native/capsign" ELFCACHE_HOST="$native/elfcache"
}
case "$action" in
stage)
    run_step stage-parent mkdir -p "$(dirname "$stage")"
    if [ "$plan" = no ]; then
        physical=$(cd "$(dirname "$stage")" && pwd -P)
        case "$physical" in /usr/obj|/usr/obj/*) ;; *) fail 'stage parent resolves outside /usr/obj';; esac
        stage=$physical/$(basename "$stage")
    fi
    run_step stage-directory mkdir "$stage"
    make_step installworld NO_ROOT=yes DESTDIR="$stage"
    make_step distribution NO_ROOT=yes DESTDIR="$stage"
    make_step installkernel NO_ROOT=yes DESTDIR="$stage"
    signing_step capimage-stage NO_ROOT=yes DESTDIR="$stage"
    ;;
packages)
    if [ -n "$pkg_key" ]; then
        signing_step system-packages PORTSDIR="$ports" HARDWARE_PORT_LIST="$hardware_profile" DISTDIR="$distfiles" REPODIR=/usr/obj/usr/src/repo PUBLISH_REPODIR="$publish_repository" PKG_REPO_SIGNING_KEY="$pkg_key" HARDWARE_SIGNING_KEY="$pkg_key"
    else
        signing_step system-packages PORTSDIR="$ports" HARDWARE_PORT_LIST="$hardware_profile" DISTDIR="$distfiles" REPODIR=/usr/obj/usr/src/repo PUBLISH_REPODIR="$publish_repository"
    fi
    ;;
esac
if [ "$plan" = no ]; then
    printf 'complete action=%s logs=%s stage=%s\n' "$action" "$run" "$stage" > "$run/status"
    cat "$run/status"
fi
