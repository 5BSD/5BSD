#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
set -eu
: "${CPP:?declared compiler command required}"
# The generator API supplies a shell-word command, as in the real ncurses script.
$CPP -P "$1"
