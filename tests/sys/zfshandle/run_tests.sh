#!/bin/sh
# Convenience wrapper: run the TrustedZFS handle tests with kyua and show
# the report.  Requires root and the zfs module with handle support loaded.
set -e
cd "$(dirname "$0")"
kyua test || true
kyua report --verbose
