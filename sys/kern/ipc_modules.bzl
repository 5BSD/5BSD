# SPDX-License-Identifier: BSD-2-Clause
"""Original IPC module sources and target option dependencies."""
IPC_MODULES = [
    struct(name = "mqueuefs", srcs = ["uipc_mqueue.c"], options = ["posix", "capsicum"]),
    struct(name = "sem", srcs = ["uipc_sem.c"], options = ["posix"]),
    struct(name = "sysvmsg", srcs = ["sysv_msg.c"], options = ["sysvipc"]),
    struct(name = "sysvsem", srcs = ["sysv_sem.c"], options = ["sysvipc"]),
    struct(name = "sysvshm", srcs = ["sysv_shm.c"], options = ["sysvipc"]),
]
