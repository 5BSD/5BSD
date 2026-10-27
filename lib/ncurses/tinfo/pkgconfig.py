# SPDX-License-Identifier: BSD-2-Clause
"""Render ncurses pkg-config metadata from declared target inputs."""
import argparse
import json
import re
from pathlib import Path


def render(template, version_source, settings):
    version = []
    for component in ("MAJOR", "MINOR", "PATCH"):
        found = re.findall(r"^NCURSES_" + component + r"\s*=\s*([0-9]+)\s*$", version_source, re.MULTILINE)
        if len(found) != 1:
            raise ValueError("expected one ncurses version component: " + component)
        version.append(found[0])
    values = dict(settings)
    values.update(MAJOR=version[0], RELEASE=".".join(version[:2]), VERSION=".".join(version))
    if any(not isinstance(v, str) or any(c in v for c in "\r\n@") for v in values.values()):
        raise ValueError("invalid substitution value")
    fields = set(re.findall(r"@([A-Z_]+)@", template))
    if fields != set(values):
        raise ValueError("template fields differ from declared substitutions")
    return re.sub(r"@([A-Z_]+)@", lambda m: values[m[1]], template)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("template", "version", "settings", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    args.output.write_text(render(args.template.read_text(), args.version.read_text(), json.loads(args.settings.read_text())))
