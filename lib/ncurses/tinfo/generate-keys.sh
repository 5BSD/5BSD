#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Match the maintained key-list pipeline; a failed generator must fail the action.
set -eu
set -o pipefail
sh "$@" | sort
