# SPDX-License-Identifier: BSD-2-Clause
"""Audit private firmware test stores exported by virt-fw-vars (JSON v2)."""
import struct
import uuid

DATABASE_GUID = 'd719b2cb-3d3a-4596-a3bc-dad00e67656f'
X509 = uuid.UUID('a5c059a1-94e4-4aa7-87b5-ab155c2bf072').bytes_le


def signatures(data):
    """Parse bounded EFI_SIGNATURE_LIST records, preserving owner and headers."""
    entries = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 28:
            raise ValueError('truncated signature list')
        kind = data[offset:offset + 16]
        size, header_size, entry_size = struct.unpack_from('<III', data, offset + 16)
        if (size > len(data) - offset or size < 28 or header_size > size - 28 or
                entry_size <= 16 or (size - 28 - header_size) % entry_size):
            raise ValueError('invalid signature-list bounds')
        start = offset + 28 + header_size
        if start == offset + size:
            raise ValueError('empty signature list')
        header = data[offset + 28:start]
        for position in range(start, offset + size, entry_size):
            entries.append((kind, header, data[position:position + entry_size]))
        offset += size
    return entries


def variables(document):
    if document.get('version') != 2 or not isinstance(document.get('variables'), list):
        raise ValueError('unsupported variable export')
    result = {}
    for value in document['variables']:
        key = (value['guid'], value['name'])
        if key in result:
            raise ValueError('duplicate variable')
        result[key] = value
    return result


def check_revocation(before, after, revoked_certificate, surviving_certificate):
    a, b = variables(before), variables(after)
    db, dbx = (DATABASE_GUID, 'db'), (DATABASE_GUID, 'dbx')
    if {key for key in a.keys() | b.keys() if a.get(key) != b.get(key)} != {dbx}:
        raise ValueError('revocation must change only dbx')
    if b[db]['attr'] != 39 or b[dbx]['attr'] != 39:
        raise ValueError('databases must retain authenticated-write attributes')
    allowed = signatures(bytes.fromhex(b[db]['data']))
    def find_certificate(cert):
        found = [item for item in allowed if item[0] == X509 and
                 item[1] == b'' and item[2][16:] == cert]
        if len(found) != 1:
            raise ValueError('expected one enrolled certificate')
        return found[0]
    primary = find_certificate(revoked_certificate)
    secondary = find_certificate(surviving_certificate)
    original = signatures(bytes.fromhex(a[dbx]['data']))
    updated = signatures(bytes.fromhex(b[dbx]['data']))
    if primary == secondary or primary in original or secondary in updated:
        raise ValueError('invalid revocation controls')
    if updated != original + [primary]:
        raise ValueError('dbx change is not exactly the enrolled certificate append')
