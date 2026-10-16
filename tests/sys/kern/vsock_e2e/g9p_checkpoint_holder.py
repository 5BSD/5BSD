#!/usr/bin/env python3
"""Keep one 9P file descriptor open and read through it on SIGUSR1."""

import os
import signal
import sys


def main() -> int:
    if len(sys.argv) != 5:
        return 2
    path, expected, ready, result = sys.argv[1:]
    fd = os.open(path, os.O_RDONLY)

    def probe(_signum: int, _frame: object) -> None:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            actual = os.read(fd, len(expected.encode()) + 1)
            status = b"ok" if actual == expected.encode() else b"mismatch"
        except OSError:
            status = b"error"
        pending = result + ".pending"
        with open(pending, "wb") as output:
            output.write(status)
        os.replace(pending, result)

    signal.signal(signal.SIGUSR1, probe)
    with open(ready, "wb") as output:
        output.write(str(fd).encode())
    while True:
        signal.pause()


if __name__ == "__main__":
    sys.exit(main())
