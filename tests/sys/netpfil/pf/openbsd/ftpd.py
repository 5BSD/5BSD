#!/usr/bin/env python3
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
#
# Minimal anonymous FTP server for the ftp-proxy tests: serves one file in
# passive (PASV, EPSV) and active (PORT, EPRT) mode.  Not for any other use.

import socket
import sys

ADDR, PORT, FILE, DATA = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
CONTENT = open(DATA, 'rb').read()
fam = socket.AF_INET6 if ':' in ADDR else socket.AF_INET


def serve(c):
    f = c.makefile('rwb', buffering=0)

    def reply(s):
        f.write((s + '\r\n').encode())

    reply('220 test ftpd')
    pasv = None
    active = None
    while True:
        line = f.readline()
        if not line:
            return
        cmd, _, arg = line.decode().strip().partition(' ')
        cmd = cmd.upper()
        if cmd == 'USER':
            reply('331 password please')
        elif cmd == 'PASS':
            reply('230 logged in')
        elif cmd == 'SYST':
            reply('215 UNIX Type: L8')
        elif cmd in ('TYPE', 'MODE', 'STRU'):
            reply('200 ok')
        elif cmd == 'PWD':
            reply('257 "/"')
        elif cmd == 'CWD':
            reply('250 ok')
        elif cmd == 'FEAT':
            reply('211-Features:\r\n EPSV\r\n EPRT\r\n SIZE\r\n211 End')
        elif cmd == 'SIZE':
            if arg.lstrip('/') == FILE:
                reply('213 %d' % len(CONTENT))
            else:
                reply('550 no such file')
        elif cmd in ('PASV', 'EPSV'):
            pasv = socket.socket(fam, socket.SOCK_STREAM)
            pasv.bind((ADDR, 0))
            pasv.listen(1)
            port = pasv.getsockname()[1]
            if cmd == 'EPSV':
                reply('229 Entering Extended Passive Mode (|||%d|)' % port)
            else:
                h = ADDR.replace('.', ',')
                reply('227 Entering Passive Mode (%s,%d,%d)' %
                      (h, port >> 8, port & 255))
            active = None
        elif cmd == 'PORT':
            p = arg.split(',')
            active = ('.'.join(p[:4]), int(p[4]) * 256 + int(p[5]))
            pasv = None
            reply('200 PORT ok')
        elif cmd == 'EPRT':
            d = arg[0]
            _, af, host, port, _ = arg.split(d)
            active = (host, int(port))
            pasv = None
            reply('200 EPRT ok')
        elif cmd == 'RETR':
            if arg.lstrip('/') != FILE:
                reply('550 no such file')
                continue
            reply('150 opening data connection')
            if pasv is not None:
                d, _ = pasv.accept()
                pasv.close()
                pasv = None
            elif active is not None:
                d = socket.create_connection(active)
            else:
                reply('425 no data connection')
                continue
            d.sendall(CONTENT)
            d.close()
            reply('226 transfer complete')
        elif cmd == 'QUIT':
            reply('221 bye')
            return
        else:
            reply('502 not implemented')


s = socket.socket(fam, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((ADDR, PORT))
s.listen(4)
print('READY', flush=True)
while True:
    c, _ = s.accept()
    try:
        serve(c)
    except (OSError, ValueError):
        pass
    c.close()
