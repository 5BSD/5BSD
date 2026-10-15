#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# /dev/pf descriptor helper for the 5BSD seam tests (vnet_dev.sh).
#
#   pf_devhelper.py send SOCKPATH
#	Open /dev/pf in the caller's VNET, connect to the unix socket SOCKPATH
#	and pass the descriptor over it (SCM_RIGHTS).
#   pf_devhelper.py recv-start SOCKPATH READYFILE
#	Listen on SOCKPATH, create READYFILE once listening, receive one
#	descriptor and issue DIOCSTART on it.  Prints "started" on success or
#	"errno N" if the ioctl fails.
#   pf_devhelper.py exhaust
#	Open /dev/pf until open(2) fails.  Prints "opened N errno E", closes
#	every descriptor and prints "reopen ok" if one more open then succeeds.

import fcntl
import os
import resource
import socket
import sys

# _IO('D', 1): DIOCSTART in OpenBSD pfvar.h.
DIOCSTART = 0x20004401


def send(path):
    fd = os.open("/dev/pf", os.O_RDWR)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(path)
    socket.send_fds(s, [b"F"], [fd])
    s.close()
    os.close(fd)
    return 0


def recv_start(path, ready):
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)
    srv.settimeout(30)
    open(ready, "w").close()
    conn, _ = srv.accept()
    _, fds, _, _ = socket.recv_fds(conn, 1, 1)
    conn.close()
    srv.close()
    if len(fds) != 1:
        print("no descriptor received")
        return 1
    try:
        fcntl.ioctl(fds[0], DIOCSTART)
    except OSError as e:
        print("errno %d" % e.errno)
        return 1
    finally:
        os.close(fds[0])
    print("started")
    return 0


def exhaust():
    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = 4096 if hard == resource.RLIM_INFINITY else min(hard, 4096)
    resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
    fds = []
    err = 0
    while len(fds) < want - 16:
        try:
            fds.append(os.open("/dev/pf", os.O_RDWR))
        except OSError as e:
            err = e.errno
            break
    print("opened %d errno %d" % (len(fds), err))
    for fd in fds:
        os.close(fd)
    try:
        os.close(os.open("/dev/pf", os.O_RDWR))
        print("reopen ok")
    except OSError as e:
        print("reopen errno %d" % e.errno)
    return 0


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "send":
        return send(sys.argv[2])
    if len(sys.argv) == 4 and sys.argv[1] == "recv-start":
        return recv_start(sys.argv[2], sys.argv[3])
    if len(sys.argv) == 2 and sys.argv[1] == "exhaust":
        return exhaust()
    print("usage: pf_devhelper.py send SOCK | recv-start SOCK READY | exhaust",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
