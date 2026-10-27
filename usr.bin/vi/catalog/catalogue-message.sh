# SPDX-License-Identifier: BSD-2-Clause
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
sort -u "$1" > "$work/sorted"
awk '{
    if ($1 == 1) {
        print "MESSAGE NUMBER 1 IS NOT LEGAL" > "/dev/stderr";
        exit 1;
    }
    if (++nline > $1) {
        print "DUPLICATE MESSAGE NUMBER " $1 > "/dev/stderr";
        exit 1;
    }
    print $0;
}' "$work/sorted" > "$work/checked"
sed -e '1s/^/$set 1~$quote "~/; 1y/~/\n/' "$work/checked"
