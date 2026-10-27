#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
set -eu
exec $CPP -D_h_tc_const -x c "$1"
