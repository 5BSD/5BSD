#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Compile the tagged v0.1.0 source state machine and pair it with the current
# destination over a local socket.  No VM, root privileges, or network listener.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
srctop=$(git -C "$here" rev-parse --show-toplevel)
tag_commit=$(git -C "$srctop" rev-parse 'v0.1.0^{commit}')
if [ "$tag_commit" != c0c7cf9223624d7c494c3ba2718bf116a79ea1b7 ]; then
	echo "v0.1.0 tag does not identify the qualified release" >&2
	exit 2
fi
work=$(mktemp -d /tmp/bhyve-v010-interop.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM

for name in migration_session.c migration_session.h migration_precopy.h \
    migration_dirty.h; do
	git -C "$srctop" show "v0.1.0:usr.sbin/bhyve/$name" > "$work/$name"
done

cc -std=gnu17 -Wall -Wextra -Werror -I"$work" \
    "$here/oldsrc.c" -lz -lpthread -o "$work/oldsrc"
cc -std=gnu17 -Wall -Wextra -Werror -Wno-unused-function \
    -I"$srctop/usr.sbin/bhyve" "$here/newdst.c" -lz -lpthread \
    -o "$work/newdst"

if command -v python3 >/dev/null 2>&1; then
	python=python3
elif command -v python3.12 >/dev/null 2>&1; then
	python=python3.12
else
	echo "Python 3 is required for the socketpair launcher" >&2
	exit 2
fi

"$python" - "$work/oldsrc" "$work/newdst" <<'PY'
import os
import socket
import subprocess
import sys

for opt_in in (False, True):
    left, right = socket.socketpair()
    env = os.environ.copy()
    env.pop("V010_DISABLE_OPTIN", None)
    if not opt_in:
        env["V010_DISABLE_OPTIN"] = "1"
    source = subprocess.Popen(
        [sys.argv[1], str(left.fileno())], pass_fds=(left.fileno(),),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    dest = subprocess.Popen(
        [sys.argv[2], str(right.fileno())], pass_fds=(right.fileno(),),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    left.close()
    right.close()
    for name, process in (("v0.1.0 source", source),
                          ("current destination", dest)):
        stdout, stderr = process.communicate(timeout=12)
        print(f"opt-in={opt_in} {name}: {stdout.strip()}")
        if stderr:
            print(stderr.strip(), file=sys.stderr)
        if process.returncode:
            raise SystemExit(f"{name} failed: {process.returncode}")
PY
