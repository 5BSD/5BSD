# Run using Linux Python (including GDB's embedded Python) in a disposable VM.
# Finite application workloads; this is not Electron qualification.
def compatibility_workloads():
    import array
    import ctypes
    import os
    import select
    import socket
    import sqlite3
    import struct
    import tempfile
    import threading
    import time

    with tempfile.TemporaryDirectory(prefix='compat-workload-') as root:
        path = root + '/database'
        db = sqlite3.connect(path)
        assert db.execute('pragma journal_mode=wal').fetchone()[0] == 'wal'
        db.execute('pragma synchronous=full')
        db.execute('create table data(worker integer, value integer, primary key(worker,value))')
        db.commit()
        errors = []

        def writer(worker):
            try:
                connection = sqlite3.connect(path, timeout=30)
                for batch in range(20):
                    with connection:
                        connection.executemany('insert into data values (?,?)',
                            [(worker, batch * 20 + value) for value in range(20)])
                connection.close()
            except BaseException as error:
                errors.append(repr(error))

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(90)
            assert not thread.is_alive(), 'SQLite writer timed out'
        assert not errors, errors
        assert db.execute('select count(*) from data').fetchone()[0] == 1600
        db.execute('begin immediate')
        db.execute('insert into data values (99,99)')
        db.close()  # Uncommitted work must be rolled back.
        db = sqlite3.connect(path)
        assert db.execute('select count(*) from data').fetchone()[0] == 1600
        assert db.execute('pragma integrity_check').fetchone()[0] == 'ok'
        assert db.execute('pragma wal_checkpoint(truncate)').fetchone()[0] == 0
        db.close()
        print('WORKLOAD_SQLITE_WAL_PASS', flush=True)

        libc = ctypes.CDLL(None, use_errno=True)
        before = len(os.listdir('/proc/self/fd'))
        cycles = 0
        start = time.monotonic()
        # Exercise repeated teardown for at least two minutes, not just one pass.
        while cycles < 1000 or time.monotonic() - start < 120:
            watched = root + '/watch'
            os.mkdir(watched)
            fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
            assert fd >= 0
            wd = libc.inotify_add_watch(fd, ctypes.c_char_p(os.fsencode(watched)), 0x100 | 0x200)
            assert wd >= 0
            file = os.open(watched + '/item', os.O_CREAT | os.O_RDWR, 0o600)
            os.write(file, b'payload')
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client, select.epoll() as ep:
                name = b'\0python-soak-' + str(os.getpid()).encode() + b'\0' + str(cycles).encode()
                server.bind(name)
                client.connect(name)
                ep.register(server, select.EPOLLIN)
                rights = array.array('i', [file])
                client.sendmsg([b'x'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
                assert ep.poll(5) == [(server.fileno(), select.EPOLLIN)]
                message, ancillary, flags, peer = server.recvmsg(1, socket.CMSG_SPACE(rights.itemsize))
                assert message == b'x' and flags == 0
                assert len(ancillary) == 1
                level, kind, data = ancillary[0]
                assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
                received = array.array('i')
                received.frombytes(data)
                assert len(received) == 1
                assert os.pread(received[0], 7, 0) == b'payload'
                os.close(received[0])
            os.close(file)
            os.unlink(watched + '/item')
            data = os.read(fd, 4096)
            offset = 0
            masks = []
            while offset < len(data):
                event_wd, mask, cookie, size = struct.unpack_from('iIII', data, offset)
                assert event_wd == wd
                masks.append(mask)
                offset += 16 + size
            assert masks == [0x100, 0x200], masks
            assert libc.inotify_rm_watch(fd, wd) == 0
            os.close(fd)
            os.rmdir(watched)
            cycles += 1
            if cycles % 100 == 0:
                assert len(os.listdir('/proc/self/fd')) == before
        assert len(os.listdir('/proc/self/fd')) == before
        print('WORKLOAD_IPC_WATCH_SOAK_PASS cycles=%d seconds=%.1f' %
              (cycles, time.monotonic() - start), flush=True)

compatibility_workloads()
