# SPDX-License-Identifier: BSD-2-Clause
"""Build time-authenticated UEFI test updates; never submit host variables.

UEFI 2.11 section 8.2.6 specifies the signed message and authentication wrapper.
This helper uses replacement writes, not APPEND_WRITE, so replay tests exercise
the firmware's timestamp checks. Authorization is a separate firmware test.
"""
import datetime
from pathlib import Path
import struct
import subprocess
import tempfile
import uuid

GLOBAL = uuid.UUID('8be4df61-93ca-11d2-aa0d-00e098032b8c')
DATABASE = uuid.UUID('d719b2cb-3d3a-4596-a3bc-dad00e67656f')
PKCS7 = uuid.UUID('4aafd29d-68df-49ee-8aa9-347d375665a7')
ATTRIBUTES = 0x27  # NON_VOLATILE | BOOTSERVICE | RUNTIME | TIME_AUTHENTICATED


def serialize(variable, timestamp, payload):
    if variable not in ('PK', 'KEK', 'db', 'dbx'):
        raise ValueError('unsupported Secure Boot variable')
    if timestamp.tzinfo != datetime.timezone.utc or timestamp.microsecond:
        raise ValueError('timestamp must be UTC at whole-second precision')
    if not 1900 <= timestamp.year <= 9999:
        raise ValueError('timestamp outside EFI_TIME range')
    # Padding, nanoseconds, timezone and daylight are zero per section 8.2.6.
    stamp = struct.pack('<HBBBBBBIhBB', timestamp.year, timestamp.month,
                        timestamp.day, timestamp.hour, timestamp.minute,
                        timestamp.second, 0, 0, 0, 0, 0)
    guid = GLOBAL if variable in ('PK', 'KEK') else DATABASE
    message = (variable.encode('utf-16le') + guid.bytes_le +
               struct.pack('<I', ATTRIBUTES) + stamp + payload)
    return stamp, message


def create(openssl, variable, timestamp, payload, key, certificate, output):
    """Write a new .auth file after independent detached signature verification."""
    stamp, message = serialize(variable, timestamp, payload)
    with tempfile.TemporaryDirectory(prefix='5bsd-auth-update-') as directory:
        directory = Path(directory)
        content, signature = directory / 'content', directory / 'signature'
        content.write_bytes(message)
        subprocess.run([str(openssl), 'cms', '-sign', '-binary', '-noattr',
                        '-md', 'sha256', '-signer', str(certificate), '-inkey', str(key),
                        '-in', str(content), '-outform', 'DER', '-out', str(signature)],
                       check=True, capture_output=True)
        # -noverify skips certificate-chain trust only. Signature/content
        # verification still runs; firmware later decides PK/KEK authorization.
        verified = subprocess.run([str(openssl), 'cms', '-verify', '-binary',
                                   '-inform', 'DER', '-in', str(signature),
                                   '-content', str(content), '-noverify'],
                                  check=True, capture_output=True)
        if verified.stdout != message:
            raise ValueError('detached verification returned different content')
        signed = signature.read_bytes()
    wrapper = struct.pack('<IHH', 24 + len(signed), 0x0200, 0x0EF1) + PKCS7.bytes_le
    with Path(output).open('xb') as stream:
        stream.write(stamp + wrapper + signed + payload)
