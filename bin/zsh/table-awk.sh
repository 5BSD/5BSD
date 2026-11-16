#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# Each stage is a separate Bazel action; preserve AWK failures directly.
set -eu
exec awk -f "$1" "$2"
