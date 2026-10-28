# SPDX-License-Identifier: BSD-2-Clause
"""Apply the maintained export transform's options without a shell or xargs."""
from pathlib import Path
import re
import subprocess
import sys

objcopy, options, source, output = sys.argv[1:]
flags = Path(options).read_text().splitlines()
for flag in flags:
    if not re.fullmatch(r'-[LN][^\s\x00]+', flag):
        raise ValueError('invalid module export option: ' + repr(flag))
# LLVM response syntax uses one quoted argument per line. Keep option ordering
# explicit and avoid ARG_MAX limits for modules with many local symbols.
response = Path(output + '.rsp')
response.write_text(''.join('"' + flag.replace('\\', '\\\\').replace('"', '\\"') + '"\n' for flag in flags))
try:
    subprocess.run([objcopy, '@' + str(response), source, output], check=True)
finally:
    response.unlink(missing_ok=True)
