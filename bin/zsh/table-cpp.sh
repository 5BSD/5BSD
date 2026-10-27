#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
set -eu
# CPP is the declared target toolchain command supplied by bsd_script_output.
exec $CPP -x c "$1"
