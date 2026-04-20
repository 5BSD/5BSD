#!/bin/sh
#
# deploy-cmi.sh — build and deploy 5BSD kernel with CMI to a test VM.
#
# Usage:
#   ./deploy-cmi.sh              # build kernel + modules + tests, deploy all
#   ./deploy-cmi.sh test         # run tests on the VM (no build/deploy)
#
# Environment:
#   CMI_VM             SSH target    (default: root@192.168.6.113)
#   MAKEOBJDIRPREFIX   obj tree      (default: ${SRCDIR}-obj)
#   NCPU               parallel jobs (default: hw.ncpu)
#

set -e

die() { echo "FAIL: $1" >&2; exit 1; }
info() { echo "==> $1"; }

SRCDIR=$(cd "$(dirname "$0")" && pwd)
OBJDIR="${MAKEOBJDIRPREFIX:-${SRCDIR}-obj}"
NCPU="${NCPU:-$(sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
VM="${CMI_VM:-root@192.168.6.113}"
VM_TESTDIR="/tmp/cmi-tests"

cd "$SRCDIR"

# ---------------------------------------------------------------
# test — just run on VM
# ---------------------------------------------------------------
if [ "$1" = "test" ]; then
    info "Running tests on $VM"
    exec ssh "$VM" "$VM_TESTDIR/run-tests.sh"
fi

# ---------------------------------------------------------------
# Build
# ---------------------------------------------------------------
info "Building kernel + modules (-j$NCPU)"
MAKEOBJDIRPREFIX="$OBJDIR" make -j"$NCPU" buildkernel \
    || die "buildkernel failed"

STAGING=$(mktemp -d)
trap 'doas rm -rf "$STAGING"' EXIT

info "Installing kernel to staging ($STAGING)"
doas env MAKEOBJDIRPREFIX="$OBJDIR" make DESTDIR="$STAGING" installkernel \
    || die "installkernel failed"

info "Building tests"
(cd tests/sys/cmi && make clean >/dev/null 2>&1; make SRCTOP="$SRCDIR") \
    || die "test build failed"

# ---------------------------------------------------------------
# Verify
# ---------------------------------------------------------------
info "Verifying build artifacts"
for f in kernel cmi.ko cmi_keystore.ko cmi_pair.ko cmi_namespace.ko; do
    [ -e "$STAGING/boot/kernel/$f" ] || die "$f missing from staging"
done
for f in cmi_test smoke_test; do
    [ -f "tests/sys/cmi/$f" ] || die "$f not built"
done

# ---------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------
info "Checking VM ($VM)"
ssh -o ConnectTimeout=5 -o BatchMode=yes "$VM" true 2>/dev/null \
    || die "Cannot reach $VM — set CMI_VM=user@host"

info "Deploying kernel + modules"
(cd "$STAGING" && doas tar cf - boot) 2>/dev/null | ssh "$VM" 'cd / && tar xf -' \
    || die "kernel deploy failed"

info "Deploying tests"
ssh "$VM" "mkdir -p $VM_TESTDIR"
scp -q tests/sys/cmi/cmi_test tests/sys/cmi/smoke_test "$VM:$VM_TESTDIR/"
[ -f tests/sys/cmi/cmi_exec_helper ] && \
    scp -q tests/sys/cmi/cmi_exec_helper "$VM:$VM_TESTDIR/"

cat <<'EOF' | ssh "$VM" "cat > $VM_TESTDIR/run-tests.sh && chmod +x $VM_TESTDIR/run-tests.sh"
#!/bin/sh
set -e

echo "=== Unloading stale modules ==="
for m in cmi_namespace cmi_pair cmi_keystore cmi; do
    kldunload "$m" 2>/dev/null || true
done

echo "=== Loading CMI ==="
kldload cmi         || { echo "FAIL: kldload cmi"; exit 1; }
kldload cmi_keystore || { echo "FAIL: kldload cmi_keystore"; exit 1; }
kldload cmi_pair    || { echo "FAIL: kldload cmi_pair"; exit 1; }
kldload cmi_namespace || { echo "FAIL: kldload cmi_namespace"; exit 1; }

echo "=== Verifying ==="
kldstat -m cmi
sysctl kern.cmi.services kern.cmi.instances
[ -c /dev/cmi ] || { echo "FAIL: /dev/cmi missing"; exit 1; }

echo "=== Smoke test ==="
/tmp/cmi-tests/smoke_test || { echo "FAIL: smoke_test"; exit 1; }

echo "=== ATF tests ==="
/tmp/cmi-tests/cmi_test || { echo "FAIL: cmi_test"; exit 1; }

echo "=== Unloading ==="
kldunload cmi_namespace
kldunload cmi_pair
kldunload cmi_keystore
kldunload cmi
[ ! -c /dev/cmi ] || { echo "FAIL: /dev/cmi still exists"; exit 1; }

echo "=== All tests passed ==="
EOF

info "Done. Reboot the VM, then run tests:"
echo ""
echo "  ssh $VM reboot"
echo "  ./deploy-cmi.sh test"
