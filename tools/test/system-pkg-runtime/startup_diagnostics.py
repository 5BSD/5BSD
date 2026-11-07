# SPDX-License-Identifier: BSD-2-Clause
"""Fatal diagnostics for normal-system qualification, including service startup."""
import re

FAILURE_DIAGNOSTICS = re.compile(
    rb"panic:|Fatal trap|lock order reversal|non-sleepable locks held|"
    rb"[A-Za-z_][A-Za-z0-9_]*: parameter not set|"
    rb"startup: (?:failed to launch|system service launch failed)|"
    rb"on_demand: failed to launch|runtime container:|runtime cleanup:"
)


def reject_failures(data):
    match = FAILURE_DIAGNOSTICS.search(data)
    if match:
        raise RuntimeError("guest kernel, shell or service failure: " +
                           match.group().decode(errors="replace") +
                           "; see serial.log")
