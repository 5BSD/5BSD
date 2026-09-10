#!/bin/sh

echo "$*" >> "${SWITCHBOARD_PKG_RECLAIM_TRACE:?missing trace path}"
[ "${SWITCHBOARD_PKG_RECLAIM_FAIL:-no}" = "yes" ] && exit 1
exit 0
