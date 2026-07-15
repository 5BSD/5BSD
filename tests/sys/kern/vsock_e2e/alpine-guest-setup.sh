#!/bin/sh
# Run as root inside Alpine once.  The host copies gvsock.py separately so the
# installed helper is exactly the source under test.
set -eu

apk add --no-cache python3
modprobe vsock
modprobe vmw_vsock_virtio_transport
python3 -c 'import socket; s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM); s.close()'
echo "Alpine virtio-vsock guest prerequisites are ready"
