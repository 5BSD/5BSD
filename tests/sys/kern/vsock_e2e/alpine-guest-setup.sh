#!/bin/sh
# Run as root inside Alpine once.  The host copies gvsock.py separately so the
# installed helper is exactly the source under test.
set -eu

release=$(cut -d. -f1,2 /etc/alpine-release)
repository="https://dl-cdn.alpinelinux.org/alpine/v${release}/main"
printf '%s\n' "$repository" > /etc/apk/repositories
apk add --no-cache python3
modprobe vsock
modprobe vmw_vsock_virtio_transport
python3 -c 'import socket; s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM); s.close()'
printf 'Alpine %s virtio-vsock prerequisites are ready with ' \
    "$(cat /etc/alpine-release)"
python3 --version
