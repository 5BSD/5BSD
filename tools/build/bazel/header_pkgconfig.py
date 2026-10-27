# SPDX-License-Identifier: BSD-2-Clause
"""Render pkg-config metadata using a version captured from a declared header."""
import argparse
import json
import re
from pathlib import Path


def render(template, header, patterns, substitutions, version_field="VERSION"):
    if not patterns:
        raise ValueError("at least one version expression required")
    parts = []
    for pattern in patterns:
        expression = re.compile(pattern, re.MULTILINE)
        if expression.groups != 1:
            raise ValueError("version expression must have exactly one capture")
        matches = expression.findall(header)
        if len(matches) != 1 or not matches[0]:
            raise ValueError("expected exactly one nonempty header version component")
        parts.append(matches[0])
    if version_field in substitutions:
        raise ValueError("version field must come from the header")
    values = dict(substitutions)
    values[version_field] = ".".join(parts)
    if any(not isinstance(v, str) or any(c in v for c in "\r\n@") for v in values.values()):
        raise ValueError("invalid pkg-config substitution")
    if set(re.findall(r"@([A-Za-z_][A-Za-z_0-9]*)@", template)) != set(values):
        raise ValueError("template fields differ from declared substitutions")
    return re.sub(r"@([A-Za-z_][A-Za-z_0-9]*)@", lambda m: values[m[1]], template)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("template", "header", "patterns", "substitutions", "output", "version-field"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    Path(args.output).write_text(render(Path(args.template).read_text(),
        Path(args.header).read_text(), json.loads(args.patterns), json.loads(args.substitutions), args.version_field))


if __name__ == "__main__":
    main()
