#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Match staged world plists to the active package makefiles, not old archives.
set -eu
if [ "$#" -lt 3 ]; then
    echo "usage: $0 worldstage packages-source make [make-variable=value ...]" >&2
    exit 64
fi
stage=$1
packages=$2
shift 2
[ -d "$stage" ] && [ -d "$packages" ] || exit 1
work=$(mktemp -d "${TMPDIR:-/tmp}/world-package-coverage.XXXXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
names() {
    awk '{ for (i = 1; i <= NF; i++) {
        if ($i !~ /^[A-Za-z0-9][A-Za-z0-9_.+-]*$/) exit 1
        print $i
    }}'
}

jobs=$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null) || jobs=1
case $jobs in
''|*[!0-9]*|0) jobs=1 ;;
esac

# Print the package names of the directories listed on standard input.  Each
# directory needs its own make evaluation, so run them side by side.  Every
# evaluation is waited for by process: one that is lost, not only one that
# reports an error, must fail the check rather than shorten the list.
query() {
    rm -rf "$work/query"
    mkdir "$work/query"
    pids=
    running=0
    failed=0
    while IFS= read -r directory; do
        "$@" -C "$packages/$directory" -V '${_ALLPACKAGES}' \
            > "$work/query/$directory" &
        pids="$pids $!"
        running=$((running + 1))
        if [ "$running" -ge "$jobs" ]; then
            for pid in $pids; do
                wait "$pid" || failed=1
            done
            pids=
            running=0
        fi
    done
    for pid in $pids; do
        wait "$pid" || failed=1
    done
    if [ "$failed" -ne 0 ]; then
        echo "cannot evaluate the package makefiles" >&2
        return 1
    fi
    for output in "$work/query"/*; do
        [ -f "$output" ] || continue
        names < "$output"
    done
}

"$@" -C "$packages" -V '${SUBDIR}' > "$work/subdirs.raw"
names < "$work/subdirs.raw" > "$work/subdirs"
[ -s "$work/subdirs" ] || { echo "empty active package directory list" >&2; exit 1; }
query "$@" < "$work/subdirs" > "$work/expected"
LC_ALL=C sort "$work/expected" > "$work/sorted"
LC_ALL=C uniq -d "$work/sorted" > "$work/duplicates"
if [ -s "$work/duplicates" ]; then
    echo "duplicate active world package targets:" >&2
    cat "$work/duplicates" >&2
    exit 1
fi
: > "$work/staged"
for plist in "$stage"/*.plist; do
    [ -e "$plist" ] || [ -L "$plist" ] || continue
    [ -f "$plist" ] && [ ! -L "$plist" ] || { echo "invalid staged plist: $plist" >&2; exit 1; }
    # pkg accepts repeated directory declarations but discards later entries.
    # Exact repeats are harmless; contradictory metadata must not disappear
    # during archive creation. Check each package before invoking pkg.
    awk '
        /^@dir([ (]|$)/ {
            path = $0
            attributes = $0
            if (sub(/^@dir\([^)]*\) /, "", path)) {
                sub(/\) .*/, ")", attributes)
            } else if (sub(/^@dir /, "", path)) {
                attributes = "@dir"
            } else {
                printf "%s:%d: invalid directory declaration\n", FILENAME, FNR > "/dev/stderr"
                failed = 1
                next
            }
            if (path == "" || (path in seen && seen[path] != attributes)) {
                printf "%s:%d: conflicting or empty directory declaration: %s\n", FILENAME, FNR, path > "/dev/stderr"
                failed = 1
            }
            seen[path] = attributes
        }
        END { exit failed }
    ' "$plist"
    name=${plist##*/}
    printf '%s\n' "${name%.plist}" >> "$work/staged"
done
[ -s "$work/staged" ] || { echo "no staged world package plists" >&2; exit 1; }
LC_ALL=C sort "$work/staged" > "$work/staged.sorted"
LC_ALL=C comm -23 "$work/staged.sorted" "$work/sorted" > "$work/unpackaged"
# A plist of directories alone, for a package that exists in the tree but is
# not built for this target, carries no payload.  The include mtree creates
# /usr/include/libipt for libipt-dev on every architecture, while the libipt
# package is built only on amd64.  Accept exactly that case; an orphan for a
# package that exists nowhere (a mistyped tag) still fails, directories or not.
: > "$work/missing"
: > "$work/dironly"
while IFS= read -r name; do
    if grep -qv '^@dir([^)]*) ' "$stage/$name.plist"; then
        printf '%s\n' "$name" >> "$work/missing"
    else
        printf '%s\n' "$name" >> "$work/dironly"
    fi
done < "$work/unpackaged"
# The inactive package directories matter only to a directory-only orphan.
: > "$work/inactive"
if [ -s "$work/dironly" ]; then
    : > "$work/inactive-dirs"
    for makefile in "$packages"/*/Makefile; do
        directory=${makefile%/Makefile}
        directory=${directory##*/}
        grep -qxF "$directory" "$work/subdirs" && continue
        printf '%s\n' "$directory" >> "$work/inactive-dirs"
    done
    query "$@" < "$work/inactive-dirs" > "$work/inactive"
fi
while IFS= read -r name; do
    if grep -qxF "$name" "$work/inactive"; then
        echo "$name: package not built for this target (only @dir entries staged)" >&2
    else
        printf '%s\n' "$name" >> "$work/missing"
    fi
done < "$work/dironly"
if [ -s "$work/missing" ]; then
    echo "staged payloads lack active world package targets:" >&2
    LC_ALL=C sort "$work/missing" >&2
    exit 1
fi
echo "WORLD_PACKAGE_COVERAGE verified active targets for staged plists"
