#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Finalize a private NO_ROOT stage after stripping. Never run on a live root.
set -eu
usage() { echo 'usage: sign-stage.sh [-e] -r stage -k private.pem' >&2; exit 64; }
stage= key= enforce=0
while getopts er:k: flag; do
    case "$flag" in e) enforce=1;; r) stage=$OPTARG;; k) key=$OPTARG;; *) usage;; esac
done
shift $((OPTIND - 1))
[ $# = 0 ] && [ -n "$stage" ] && [ -n "$key" ] || usage
stage=$(cd "$stage" && pwd -P)
[ "$stage" != / ] && [ -f "$stage/METALOG" ] && [ ! -L "$stage/METALOG" ] || { echo 'a private NO_ROOT stage is required' >&2; exit 1; }
case "$stage" in *'
'*|*'\t'*) echo 'stage path contains a control character' >&2; exit 1;; esac
capsign=${CAPSIGN:-capsign}
# Reject all mutable-output ancestors before signing or replacing any image.
# Checking only the final component would follow an intermediate symlink into
# another tree, including a live system, before later bundle validation.
for directory in Capabilities Capabilities/System etc etc/capability etc/capability/keys; do
    [ ! -L "$stage/$directory" ] || { echo "symlinked stage directory: $directory" >&2; exit 1; }
    [ ! -e "$stage/$directory" ] || [ -d "$stage/$directory" ] || {
        echo "stage directory is not a directory: $directory" >&2; exit 1;
    }
done
for artifact in etc/capability/require-signatures; do
    [ ! -L "$stage/$artifact" ] || { echo "symlinked stage artifact: $artifact" >&2; exit 1; }
done
if [ -d "$stage/Capabilities/System" ]; then
    links=$(find "$stage/Capabilities/System" -type l -print) || exit 1
    [ -z "$links" ] || { echo 'symlink in staged bundle tree' >&2; exit 1; }
fi
[ -f "$key" ] && [ ! -L "$key" ] || { echo 'signing key must be a regular file, not a symlink' >&2; exit 1; }
key=$(realpath "$key")
case "$key" in "$stage"|"$stage"/*) echo 'private key must be outside the staged image' >&2; exit 1;; esac
[ ! -e "$stage/etc/capability/require-signatures" ] || {
    echo 'stage already has signature enforcement; use a fresh generation' >&2; exit 1;
}
count=0
for bundle in "$stage"/Capabilities/System/*.cap; do
    [ -d "$bundle" ] && [ ! -L "$bundle" ] || continue
    [ ! -e "$bundle/Signature" ] && [ ! -L "$bundle/Signature" ] || {
        echo "bundle already sealed: $bundle" >&2; exit 1;
    }
    count=$((count + 1))
done
[ "$count" -gt 0 ] || { echo 'no system bundles in stage' >&2; exit 1; }
scratch=$(mktemp -d "${stage}.signing.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
trap 'exit 1' HUP INT TERM
openssl pkey -in "$key" -pubout -out "$scratch/public.pem"
keyid=$("$capsign" key-id -p "$scratch/public.pem")
[ "${#keyid}" = 64 ] || { echo 'invalid signing key identifier' >&2; exit 1; }
case "$keyid" in *[!0-9a-f]*) echo 'invalid signing key identifier' >&2; exit 1;; esac
[ ! -L "$stage/etc/capability/keys/$keyid.pub" ] || {
    echo 'symlinked stage public-key destination' >&2; exit 1;
}
# Prepare every image before replacing any staged executable. The scratch
# directory is outside the signed bundle inventory.
n=0
: > "$scratch/images"
for bundle in "$stage"/Capabilities/System/*.cap; do
    [ -d "$bundle" ] && [ ! -L "$bundle" ] || continue
    for image in "$bundle"/Units/*.unit/bin/*; do
        [ -f "$image" ] && [ ! -L "$image" ] || continue
        case "$image" in *'
'*) echo 'image path contains a newline' >&2; exit 1;; esac
        n=$((n + 1))
        if ! "$capsign" sign -k "$key" -o "$scratch/$n" "$image"; then
            echo "cannot sign staged image: $image" >&2
            exit 1
        fi
        "$capsign" verify -p "$scratch/public.pem" "$scratch/$n"
        printf '%s\n' "$image" >> "$scratch/images"
    done
done
[ "$n" -gt 0 ] || { echo 'no native unit programs' >&2; exit 1; }
n=0
while IFS= read -r image; do
    n=$((n + 1))
    mv "$scratch/$n" "$image"
done < "$scratch/images"
# All mutations are confined to this unpublished stage. A failure here leaves
# it incomplete; discard it instead of publishing or attempting an upgrade.
record_dir()
{
    printf './%s type=dir uname=root gname=wheel mode=0755 tags=%s\n' "$1" "$2" >> "$stage/METALOG"
}
record_file()
{
    printf './%s type=file uname=root gname=wheel mode=0444 size=%s tags=%s\n' \
        "$1" "$(stat -f %z "$stage/$1")" "$2" >> "$stage/METALOG"
}
for bundle in "$stage"/Capabilities/System/*.cap; do
    [ -d "$bundle" ] && [ ! -L "$bundle" ] || continue
    for manifest in "$bundle"/Units/*.unit/Unit.ucl; do
        [ -f "$manifest" ] && [ ! -L "$manifest" ] || continue
        manifest_relative=${manifest#"$stage"/}
        rm "$manifest"
        awk -v p="./$manifest_relative" '$1 != p' "$stage/METALOG" > "$scratch/METALOG"
        mv "$scratch/METALOG" "$stage/METALOG"
    done
    "$capsign" bundle-sign -k "$key" "$bundle"
    "$capsign" bundle-verify -p "$scratch/public.pem" "$bundle"
    relative=${bundle#"$stage"/}
    tag=$(awk -v p="./$relative/Bundle.ucl" '$1 == p {
        for (i=2; i<=NF; i++) if ($i ~ /^tags=/) {
            n=split(substr($i,6), t, ",")
            for (j=1; j<=n; j++) if (t[j] ~ /^package=/) tag=t[j]
        }
    } END { print tag }' "$stage/METALOG")
    [ -n "$tag" ] || { echo "no package metadata for $bundle" >&2; exit 1; }
    for image in "$bundle"/Units/*.unit/bin/*; do
        [ -f "$image" ] && [ ! -L "$image" ] || continue
        image_relative=${image#"$stage"/}
        # Replace the pre-signing size; consumers must never truncate the
        # appended signature by selecting an older METALOG record.
        awk -v p="./$image_relative" '$1 != p' "$stage/METALOG" > "$scratch/METALOG"
        mv "$scratch/METALOG" "$stage/METALOG"
        printf './%s type=file uname=root gname=wheel mode=%s size=%s tags=%s\n' \
            "$image_relative" "$(stat -f %Lp "$image")" "$(stat -f %z "$image")" "$tag" >> "$stage/METALOG"
    done
    record_dir "$relative/Signature" "$tag"
    record_file "$relative/Signature/Seal" "$tag"
done
for directory in etc/capability etc/capability/keys; do
    [ ! -L "$stage/$directory" ] || { echo "symlinked stage directory: $directory" >&2; exit 1; }
    mkdir -p "$stage/$directory"
    record_dir "$directory" package=runtime
done
install -m 0444 "$scratch/public.pem" "$stage/etc/capability/keys/$keyid.pub"
record_file "etc/capability/keys/$keyid.pub" package=runtime
if [ "$enforce" = 1 ]; then
    install -m 0444 /dev/null "$stage/etc/capability/require-signatures"
    record_file etc/capability/require-signatures package=runtime
fi
printf 'Signed %s native images in %s bundles; key=%s; enforcement=%s\n' "$n" "$count" "$keyid" "$enforce"
