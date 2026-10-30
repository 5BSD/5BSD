#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# The upstream editor modifies its input; stage only this action's scratch copy.
set -eu
[ "$#" -eq 3 ] || exit 64
scratch=term-header.$$
trap 'rm -f "$scratch"' EXIT
trap 'exit 1' HUP INT TERM
ulimit -c 0
cat "$1" > "$scratch"
# Upstream treats any nonzero cmp status as different; detect broken tools first.
cmp -s "$scratch" "$scratch"
sh "$3" "$2" "$scratch" >&2
cat "$scratch"
