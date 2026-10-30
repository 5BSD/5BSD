# SPDX-License-Identifier: BSD-2-Clause
"""Native syscall interface policy, independent of Make evaluation.

The complete syscall inventory is generated from syscalls.master. These lists
select ABI wrappers and architecture implementations, not syscall numbers.
"""
INTERPOSED_SYSCALLS = [
    "accept",
    "accept4",
    "aio_suspend",
    "clock_nanosleep",
    "close",
    "connect",
    "fcntl",
    "fdatasync",
    "fsync",
    "fork",
    "kevent",
    "msync",
    "nanosleep",
    "open",
    "openat",
    "pdfork",
    "pdwait",
    "poll",
    "ppoll",
    "pselect",
    "ptrace",
    "read",
    "readv",
    "recvfrom",
    "recvmsg",
    "select",
    "sendmsg",
    "sendto",
    "setcontext",
    "sigaction",
    "sigprocmask",
    "sigsuspend",
    "sigtimedwait",
    "sigwait",
    "sigwaitinfo",
    "swapcontext",
    "wait4",
    "wait6",
    "write",
    "writev",
]

PSEUDO_SYSCALLS = [
    "__realpathat", "clock_gettime", "getlogin", "gettimeofday", "sched_getcpu",
] + INTERPOSED_SYSCALLS

AMD64_HANDWRITTEN_SYSCALLS = ["vfork", "cerror", "getcontext"]
