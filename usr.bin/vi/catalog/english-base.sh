# SPDX-License-Identifier: BSD-2-Clause
set -eu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
dump "$@" > "$work/extracted"
sed -e '/|/!d' -e 's/|/ "/' -e 's/^"//' "$work/extracted" > "$work/messages"
sort -nu "$work/messages"
