# SPDX-License-Identifier: BSD-2-Clause
"""OVMF console evidence for a guest with exactly one bootable EFI disk."""
import re


def console_lines(text):
    # OVMF clears its console before BdsDxe reports boot attempts.
    return re.sub(r'\x1b\[[0-9;=?]*[A-Za-z]', '', text).splitlines()


def execution(text, secure):
    lines = console_lines(text)
    expected = {
        'FIRMWARE_PROBE_EXECUTED',
        'FIRMWARE_PROBE SecureBoot=' + ('1' if secure else '0'),
        'FIRMWARE_PROBE SetupMode=' + ('0' if secure else '1'),
    }
    actual = [line for line in lines if 'FIRMWARE_PROBE' in line]
    return len(actual) == 3 and set(actual) == expected


def rejection(text):
    lines = console_lines(text)
    if any('FIRMWARE_PROBE' in line or 'BdsDxe: starting ' in line for line in lines):
        return False
    attempts = [line for line in lines if line.startswith('BdsDxe: loading ')]
    failures = [line for line in lines if line.startswith('BdsDxe: failed to load ')]
    if len(attempts) != 1 or len(failures) != 1:
        return False
    target = attempts[0].removeprefix('BdsDxe: loading ')
    # Bind the denial to the observed attempt, without fixing a Boot#### number
    # or a PCI address. A different device's error cannot satisfy this check.
    if not re.fullmatch(r'Boot[0-9A-Fa-f]{4} "[^"\r\n]+" from .+', target):
        return False
    if failures[0] != 'BdsDxe: failed to load ' + target + ': Access Denied':
        return False
    terminal = 'BdsDxe: No bootable option or device was found.'
    return (lines.count(terminal) == 1 and
            lines.index(attempts[0]) < lines.index(failures[0]) < lines.index(terminal))


def authenticated_update(text):
    required = ['AUTH_UPDATE_UNAUTHORIZED_REJECTED', 'AUTH_UPDATE_ACCEPTED',
                'AUTH_UPDATE_REPLAY_REJECTED', 'AUTH_UPDATE_PASS']
    actual = [line for line in console_lines(text) if 'AUTH_UPDATE' in line]
    return actual == required


def authenticated_replay(text):
    required = ['AUTH_PERSISTED_REPLAY_REJECTED', 'AUTH_NEWER_UPDATE_ACCEPTED',
                'AUTH_NEWER_REPLAY_REJECTED', 'AUTH_REPLAY_PASS']
    actual = [line for line in console_lines(text) if 'AUTH_' in line]
    return actual == required
