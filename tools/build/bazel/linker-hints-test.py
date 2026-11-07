# SPDX-License-Identifier: BSD-2-Clause
"""Compare complete native hints with original directory behavior and failure paths."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

root = Path(os.environ["TEST_SRCDIR"]) / os.environ["TEST_WORKSPACE"]
request = json.loads(Path(sys.argv[1]).read_text())
tool = (root / request["tool"]).resolve(strict=True)
runtime = [(root / path).resolve(strict=True).parent for path in request["runtime"]]
env = dict(os.environ, LC_ALL="C", LD_LIBRARY_PATH=":".join(dict.fromkeys(map(str, runtime))))
expected = (root / request["hints"]).read_bytes()
commands = []


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(args, success=True):
    result = subprocess.run([str(tool), *map(str, args)], env=env, capture_output=True, text=True)
    commands.append(dict(arguments=list(map(str, args)), status=result.returncode, stdout=result.stdout, stderr=result.stderr))
    assert (result.returncode == 0) == success, commands[-1]


with tempfile.TemporaryDirectory(prefix="linker-hints-test-", dir=os.environ["TEST_TMPDIR"]) as temp:
    stage = Path(temp)
    files = []
    hashes = {}
    for name, source in sorted(request["inputs"].items()):
        path = stage / name
        shutil.copyfile(root / source, path)
        files.append(path)
        hashes[name] = digest(path)
    for name, target in request["aliases"].items():
        (stage / name).symlink_to(target)
    (stage / "ignored.debug").write_text("Not an ELF input; ordinary kldxref must skip this.\n")
    run([stage])
    assert (stage / "linker.hints").read_bytes() == expected, "directory and declared-input hints differ"
    output = stage / "explicit.hints"
    run(["-o", output, *files])
    assert output.read_bytes() == expected
    with files[0].open("rb") as stream:
        ident = stream.read(6)
    assert ident[:4] == b"\x7fELF" and ident[5] in (1, 2)
    assert len(expected) > 4 and struct.unpack(("<" if ident[5] == 1 else ">") + "I", expected[:4])[0] == 1
    # Extra files do not enter explicit mode, and declared corruption fails atomically.
    extra = stage / "undeclared.ko"
    extra.write_text("not ELF\n")
    run(["-o", output, *files])
    assert output.read_bytes() == expected
    run(["-o", output, *files, extra], success=False)
    assert output.read_bytes() == expected
    run(["-o", output, files[0], files[0]], success=False)
    alias = stage / "explicit-probe.ko"
    alias.symlink_to(files[0].name)
    run(["-o", output, alias], success=False)
    assert output.read_bytes() == expected
    assert not list(stage.glob("lhint.*")), "failed explicit tool left temporary output"
    for path in files:
        assert digest(path) == hashes[path.name], "input was modified"
    print("LINKER_HINTS=" + json.dumps(dict(inputs=len(files), aliases=len(request["aliases"]),
        input_bytes=sum(path.stat().st_size for path in files), hints_bytes=len(expected),
        hints_sha256=hashlib.sha256(expected).hexdigest(), commands=commands), sort_keys=True))
