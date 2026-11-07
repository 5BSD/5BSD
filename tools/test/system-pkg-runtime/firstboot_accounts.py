# SPDX-License-Identifier: BSD-2-Clause
"""Check the declared local-account provisioning against its complete baseline."""
FIELDS = ('name', 'password', 'uid', 'gid', 'class', 'change', 'expire',
          'gecos', 'home', 'shell')


def rows(text, width):
    if not text.endswith('\n'):
        raise ValueError('canonical newline-terminated account input required')
    result = {}
    for line in text.splitlines():
        row = line.split(':')
        if len(row) != width or not row[0] or row[0] in result:
            raise ValueError('unique canonical local account records required')
        result[row[0]] = row
    return result


def validate(master, group, observed_master, observed_group, observed_public,
             changes, group_additions, authenticated_accounts):
    """Password salts may vary only for accounts with positive AND negative
    authentication already exercised. The caller must additionally compare both
    actual password DBs to private pwd_mkdb regeneration of this checked master.
    All other fields, accounts, memberships and the public projection are exact.
    """
    original = rows(master, 10)
    actual = rows(observed_master, 10)
    if set(changes) != set(authenticated_accounts):
        raise ValueError('every provisioned password requires exercised authentication')
    expected = {name: list(row) for name, row in original.items()}
    used_uids = {row[2] for row in original.values()}
    for name, fields in changes.items():
        if (not isinstance(fields, dict) or not fields or
                set(fields) - (set(FIELDS) - {'name', 'password'})):
            raise ValueError('explicit account field changes required')
        if name not in expected:
            if set(fields) != set(FIELDS) - {'name', 'password'}:
                raise ValueError('every field of a new local account must be declared')
            if fields['uid'] in used_uids or fields['uid'] == '0':
                raise ValueError('new account requires an unused non-root UID')
            used_uids.add(fields['uid'])
            expected[name] = [name, ''] + [''] * 8
        if name not in actual:
            raise ValueError('declared provisioned account is missing')
        for key, value in fields.items():
            if not isinstance(value, str) or any(c in value for c in ':\n\r\0'):
                raise ValueError('canonical account field value required')
            if key in ('uid', 'gid', 'change', 'expire') and (not value.isdecimal() or str(int(value)) != value):
                raise ValueError('canonical nonnegative account ID/time required')
            expected[name][FIELDS.index(key)] = value
        password = actual[name][1]
        if not password.startswith('$') or len(password) < 10 or any(c.isspace() for c in password):
            raise ValueError('provisioned account requires its authenticated encoded password')
        expected[name][1] = password
    if list(actual.values()) != list(expected.values()):
        raise ValueError('unexplained account content or order changes')
    expected_groups = rows(group, 4)
    for name, additions in group_additions.items():
        if (name not in expected_groups or not isinstance(additions, list) or
                not additions or len(additions) != len(set(additions)) or
                set(additions) - set(changes)):
            raise ValueError('explicit memberships in existing groups required')
        members = expected_groups[name][3].split(',') if expected_groups[name][3] else []
        if set(members) & set(additions):
            raise ValueError('membership already present in baseline')
        expected_groups[name][3] = ','.join(members + additions)
    if list(rows(observed_group, 4).values()) != list(expected_groups.values()):
        raise ValueError('unexplained group content or order changes')
    public = [[row[0], '*', row[2], row[3], row[7], row[8], row[9]] for row in expected.values()]
    if list(rows(observed_public, 7).values()) != public:
        raise ValueError('public passwd differs from checked master projection')
    return dict(accounts=len(expected), groups=len(expected_groups),
                authenticated_password_accounts=sorted(changes))
