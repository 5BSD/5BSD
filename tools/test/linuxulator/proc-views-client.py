# Execute using Linux Python, including GDB's embedded Python, inside a guest.
import ctypes
import os
import threading

libc = ctypes.CDLL(None, use_errno=True)
ready = threading.Event()
release = threading.Event()
result = {}


def worker():
    try:
        assert libc.prctl(15, ctypes.c_char_p(b"python-worker"), 0, 0, 0) == 0
        tid = threading.get_native_id()
        result["tid"] = tid
        assert os.readlink("/proc/thread-self") == f"{os.getpid()}/task/{tid}"
        with open("/proc/thread-self/status") as f:
            status = f.read()
        assert "Name:\tpython-worker\n" in status
        assert f"Pid:\t{tid}\n" in status
    except BaseException as error:
        result["error"] = repr(error)
    finally:
        ready.set()
    release.wait(20)


t = threading.Thread(target=worker)
t.start()
assert ready.wait(20), "worker did not become ready"
try:
    assert "error" not in result, result
    tid = result["tid"]
    assert str(tid) in os.listdir("/proc/self/task")
    with open(f"/proc/self/task/{tid}/status") as f:
        status = f.read()
    assert f"Tgid:\t{os.getpid()}\n" in status
    assert "Name:\tpython-worker\n" in status
    with open(f"/proc/self/task/{tid}/comm", "w") as f:
        f.write("python-renamed")
    with open(f"/proc/self/task/{tid}/comm") as f:
        assert f.read() == "python-renamed\n"
    for name in ["cmdline", "limits", "auxv", "environ"]:
        with open(f"/proc/self/task/{tid}/{name}", "rb") as f:
            data = f.read()
        with open(f"/proc/self/{name}", "rb") as f:
            assert f.read() == data
finally:
    release.set()
    t.join(20)
assert not t.is_alive()
assert str(tid) not in os.listdir("/proc/self/task")
print("PYTHON_PROC_THREADS_PASS", flush=True)

with open("/proc/filesystems") as f:
    filesystems = f.read()
assert "nodev\tproc\n" in filesystems
assert "nodev\tsysfs\n" in filesystems
with open("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list") as f:
    siblings = f.read().strip()
assert siblings
print("PYTHON_PROC_DISCOVERY_PASS", flush=True)

import tempfile
with tempfile.TemporaryFile() as f:
    f.write(b"descriptor contents")
    f.flush()
    f.seek(4)
    fd = f.fileno()
    assert str(fd) in os.listdir("/proc/self/fd")
    assert str(fd) in os.listdir("/proc/thread-self/fdinfo")
    with open(f"/proc/self/fdinfo/{fd}") as info:
        fields = dict(line.strip().split(":", 1) for line in info)
    assert int(fields["pos"]) == 4
    assert int(fields["ino"]) == os.fstat(fd).st_ino
    assert int(fields["mnt_id"]) > 0
    with open(f"/proc/self/fd/{fd}", "rb") as reopened:
        assert reopened.read() == b"descriptor contents"
    assert f.tell() == 4
print("PYTHON_PROC_DESCRIPTORS_PASS", flush=True)

# Linux runtime consumers must be able to correlate sockets with procfs.
import socket
import select
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    inode = os.fstat(listener.fileno()).st_ino
    assert os.readlink(f"/proc/self/fd/{listener.fileno()}") == f"socket:[{inode}]"
    with open("/proc/net/tcp") as table:
        rows = [line.split() for line in table.readlines()[1:]]
    row, = [row for row in rows if int(row[9]) == inode]
    assert row[3] == "0A"
    assert int(row[1].split(":")[1], 16) == listener.getsockname()[1]
    with select.epoll() as poller:
        poller.register(listener, select.EPOLLIN)
        with open(f"/proc/self/fdinfo/{poller.fileno()}") as info:
            interests = [line.split() for line in info if line.startswith("tfd:")]
        assert len(interests) == 1
        assert int(interests[0][1]) == listener.fileno()
        assert int(interests[0][3], 16) == select.EPOLLIN | select.EPOLLERR | select.EPOLLHUP
print("PYTHON_PROC_SOCKETS_PASS", flush=True)

for leaf in ("cwd", "root", "exe"):
    assert os.readlink(f"/proc/self/task/{os.getpid()}/{leaf}") == os.readlink(f"/proc/self/{leaf}")
print("PYTHON_PROC_TASKLINKS_PASS", flush=True)
