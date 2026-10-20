#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# This entry point is installed only in a disposable test image.
set -eu
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin
export PATH
test -f /root/pf-parity-disposable || exit 1
trap 'rc=$?; echo PF_PARITY_EXIT "$rc"; sync; /sbin/halt -p' EXIT
mount -uw /
mount -t devfs devfs /dev 2>/dev/null || true
chmod 1777 /tmp
ifconfig lo0 127.0.0.1/8 up
echo PF_PARITY_BEGIN
uname -a
sysctl hw.ncpu
while IFS= read -r artifact; do sha256 "$artifact"; done < /root/pf-artifacts
if [ -f /root/python-artifacts.json ]; then
    ldconfig -m /usr/local/lib
    python3 - <<'PYVERIFY'
import hashlib, json
from pathlib import Path
manifest = json.loads(Path('/root/python-artifacts.json').read_text())
for name, expected in manifest.items():
    assert hashlib.sha256(Path(name).read_bytes()).hexdigest() == expected, name
from scapy.all import Ether
print('PF_PARITY_PYTHON_ARTIFACTS', len(manifest))
PYVERIFY
fi
for module in pf pflog dummynet if_epair if_bridge; do
    kldstat -q -m "$module" || kldload "$module"
done
if kldstat -q -m ipfw; then echo UNEXPECTED_IPFW_MODULE; exit 1; fi
sh /root/pf-parser-corpus.sh
# Report every test even if a baseline regression is expected to fail.
while IFS= read -r testcase; do
    database="/root/parity-${testcase%:*}-${testcase#*:}.db"
    rc=0
    kyua test -k /usr/tests/sys/netpfil/pf/Kyuafile -r "$database" "$testcase" || rc=$?
    kyua report --verbose --results-filter=passed,skipped,xfail,broken,failed -r "$database"
    echo PF_PARITY_CASE "$testcase" "$rc"
done < /root/pf-cases
zpool sync
zpool status -x
echo PF_PARITY_DONE
