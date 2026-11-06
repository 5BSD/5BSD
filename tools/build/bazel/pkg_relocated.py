# SPDX-License-Identifier: BSD-2-Clause
"""Explicit host paths for an alternate-root pkg operation; no host defaults."""
from pathlib import Path


def root_command(pkg, root, config, repositories, *, dbdir=None, cachedir=None):
    """-r relocates defaults; explicit -o paths are already absolute host paths."""
    root = Path(root)
    dbdir = root / "var/db/pkg" if dbdir is None else Path(dbdir)
    cachedir = root / "var/cache/pkg" if cachedir is None else Path(cachedir)
    if any(not Path(path).is_absolute() for path in (pkg, root, config, repositories, dbdir, cachedir)):
        raise ValueError("explicit absolute pkg/root/config/repository/database/cache paths required")
    return [str(pkg), "-r", str(root), "-C", str(config), "-R", str(repositories),
            "-o", "PKG_DBDIR=" + str(dbdir), "-o", "PKG_CACHEDIR=" + str(cachedir),
            "-o", "RUN_SCRIPTS=no", "-o", "PKG_ENABLE_PLUGINS=no",
            "-o", "PKG_TRIGGERS_ENABLE=no", "-o", "REPO_AUTOUPDATE=no", "-o", "SYSLOG=no"]
