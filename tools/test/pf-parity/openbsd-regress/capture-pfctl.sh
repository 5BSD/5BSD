#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Capture raw pfctl -nv output for every pfNN.in/pfailNN.in of the imported
# corpus (parse only, no kernel changes) for offline gap classification.
# usage: capture-pfctl.sh REGRESSDIR OUTDIR [extra pfctl flags]
set -u
d=$1 o=$2; shift 2
mkdir -p "$o"
cd "$d" || exit 1
for f in pf[0-9]*.in pfail[0-9]*.in; do
	n=${f%.in}
	pfctl -o none -nv "$@" -f - < "$f" > "$o/$n.out" 2> "$o/$n.err"
	echo $? > "$o/$n.rc"
done
echo CAPTURE_DONE
