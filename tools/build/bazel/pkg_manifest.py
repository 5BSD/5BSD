# SPDX-License-Identifier: BSD-2-Clause
"""Compose declared pkgbase fields and run the maintained UCL generator."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def generate(request, output):
    # Keep source UCL semantics in the maintained parser, not a Python UCL clone.
    fields = request["fields"]
    template = Path(request["template"])
    with tempfile.TemporaryDirectory(prefix="pkg-manifest-", dir=output.parent) as temporary:
        combined = Path(temporary) / "manifest.ucl.in"
        content = template.read_text() + "\n"
        content += "\n".join(key + " = " + json.dumps(value) + ";" for key, value in fields.items()) + "\n"
        combined.write_text(content)
        argv = [request["flua"], request["generator"]]
        for key, value in request["variables"].items():
            argv.extend([key, value])
        argv.extend([str(combined), str(output)])
        subprocess.run(argv, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    generate(json.loads(args.request.read_text()), args.output)


if __name__ == "__main__":
    main()
