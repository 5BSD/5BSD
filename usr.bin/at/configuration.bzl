# SPDX-License-Identifier: BSD-2-Clause
"""Shared native build policy for at and atrun (Makefile.inc counterpart)."""
AT_POLICY = {
    "LOCKFILE": ".lockfile",
    "ATSPOOL_DIR": "/var/at/spool",
    "ATJOB_DIR": "/var/at/jobs",
    "ATLIB_DIR": "/usr/libexec",
    "LOADAVG_MX": "1.5",
    "DAEMON_GID": "1",
    "DAEMON_UID": "1",
    "DEFAULT_BATCH_QUEUE": "E",
    "DEFAULT_AT_QUEUE": "c",
    "PERM_PATH": "/var/at",
}
def at_defines(policy = AT_POLICY):
    return [
        'ATJOB_DIR=\\"' + policy["ATJOB_DIR"] + '/\\"',
        'LFILE=\\"' + policy["ATJOB_DIR"] + '/' + policy["LOCKFILE"] + '\\"',
        'ATSPOOL_DIR=\\"' + policy["ATSPOOL_DIR"] + '\\"',
        'PERM_PATH=\\"' + policy["PERM_PATH"] + '/\\"',
        "DEFAULT_BATCH_QUEUE=\\'" + policy["DEFAULT_BATCH_QUEUE"] + "\\'",
        "DEFAULT_AT_QUEUE=\\'" + policy["DEFAULT_AT_QUEUE"] + "\\'",
    ] + [key + "=" + policy[key] for key in ["LOADAVG_MX", "DAEMON_UID", "DAEMON_GID"]]
