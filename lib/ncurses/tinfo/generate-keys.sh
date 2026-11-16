#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard
#
# Match the maintained key-list pipeline; a failed generator must fail the action.
set -eu
set -o pipefail
sh "$@" | sort
