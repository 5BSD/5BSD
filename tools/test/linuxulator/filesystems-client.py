# Run inside Linux GDB's embedded Python in the disposable BSD guest.
import ctypes
import os
import socket
import stat

paths = ['/sys/devices/system/cpu/online', '/sys/class/net/lo/address',
         '/proc/self/mountinfo', '/proc/self/mounts']
for path in paths:
    expected = open(path, 'rb').read()
    with open(path, 'rb', buffering=0) as f:
        assert b''.join(iter(lambda: f.read(1), b'')) == expected, path
        f.seek(0)
        assert f.read(3) == expected[:3], path
assert 'lo' in os.listdir('/sys/class/net')
print('PYTHON_FS_READ_PASS')

libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                      ctypes.c_ulong, ctypes.c_char_p]
libc.mount.restype = ctypes.c_int
libc.umount.argtypes = [ctypes.c_char_p]
libc.umount.restype = ctypes.c_int
path = b'/tmp/python fs'
os.makedirs(path, exist_ok=True)
assert libc.mount(b'tmpfs', path, b'tmpfs', 0, b'size=2M,mode=0700') == 0, ctypes.get_errno()
try:
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o700
    with open(path + b'/data', 'wb') as f:
        f.write(b'filesystem client')
    assert open(path + b'/data', 'rb').read() == b'filesystem client'
    assert b'/tmp/python\\040fs ' in open('/proc/self/mountinfo', 'rb').read()
finally:
    assert libc.umount(path) == 0, ctypes.get_errno()
print('PYTHON_FS_MOUNT_PASS')

counter = '/sys/class/net/lo/statistics/rx_bytes'
before = int(open(counter).read())
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rx:
    rx.bind(('127.0.0.1', 0))
    rx.settimeout(5)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tx:
        for i in range(32):
            tx.sendto(b'filesystem client', rx.getsockname())
            assert rx.recv(128) == b'filesystem client'
assert int(open(counter).read()) > before
print('PYTHON_FS_NETWORK_PASS')
