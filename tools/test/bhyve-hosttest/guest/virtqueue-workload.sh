#!/bin/sh
# Read-only raw I/O avoids a filesystem-cache-only tracing test.
set -eu
dd if=/dev/vtbd0 of=/dev/null bs=1m count=16
echo VIRTQUEUE-WORK-DONE
