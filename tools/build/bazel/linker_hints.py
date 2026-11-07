# SPDX-License-Identifier: BSD-2-Clause
"""Run native kldxref on declared regular copies; never scan an installed OS."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    request = json.loads(Path(sys.argv[1]).read_text())
    if type(request.get("format")) is not int or request["format"] != 1:
        raise ValueError("supported linker-hints request required")
    output = Path(sys.argv[2]).absolute()
    tool = Path(request["tool"]).resolve(strict=True)
    runtime = [Path(path).resolve(strict=True) for path in request["runtime"]]
    sources = [(row["name"], Path(row["source"]).resolve(strict=True)) for row in request["inputs"]]
    names = [name for name, source in sources]
    if not sources or names != sorted(set(names)) or any(
            not name or name in (".", "..", output.name) or "/" in name or "\\" in name
            for name in names):
        raise ValueError("distinct sorted input basenames required")
    env = dict(os.environ, LC_ALL="C", LD_LIBRARY_PATH=":".join(dict.fromkeys(str(path.parent) for path in runtime)))
    # Input copies are streamed and confined to this action's output filesystem.
    # kldxref's explicit API deliberately rejects symlinks and never discovers files.
    with tempfile.TemporaryDirectory(prefix=".kldxref-", dir=output.parent) as temp:
        directory = Path(temp)
        files = []
        for name, source in sources:
            target = directory / name
            shutil.copyfile(source, target)
            files.append(str(target))
        generated = directory / output.name
        subprocess.run([str(tool), "-o", str(generated), *files], env=env, check=True)
        os.replace(generated, output)


if __name__ == "__main__":
    main()
