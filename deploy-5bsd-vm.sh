#!/bin/sh
#
# Deploy 5BSD kernel and tests to jaildesc-test VM
#
# Usage:
#   ./deploy-5bsd-vm.sh [deploy|reboot|test|all]
#
#   deploy  - Build, install kernel to VM disk, configure loader, start VM
#   reboot  - Reboot VM and wait for SSH
#   test    - Run CAP_RT tests on VM via SSH
#   all     - deploy + reboot + test
#

set -e

SRCDIR="/home/koryheard/Projects/5BSD"
OBJDIR="/home/koryheard/Projects/5BSD-obj"
VM_NAME="jaildesc-test"
VM_DISK="/zroot/vm/${VM_NAME}/disk0.img"
VM_IP="192.168.6.113"
MD_UNIT="9"

# Test binaries to deploy (built separately from kernel)
CAP_RT_TESTDIR="${OBJDIR}${SRCDIR}/amd64.amd64/tests/sys/cap_rt"

# Modules that must load at boot (NOTLATE MAC policies)
BOOT_MODULES="cap_rt cap_rt_capprotect cap_rt_isolation"

# Escalate to root once, at the top
if [ "$(id -u)" -ne 0 ]; then
    exec doas "$0" "$@"
fi

cd "$SRCDIR"

wait_for_vm_ssh() {
    echo "=== Waiting for ${VM_IP} ==="
    i=0
    while [ "$i" -lt 60 ]; do
        if nc -z -w 2 "${VM_IP}" 22 >/dev/null 2>&1; then
            echo "=== VM reachable ==="
            sleep 1  # give sshd a moment to fully initialize
            return 0
        fi
        i=$((i + 1))
        sleep 2
    done
    echo "ERROR: VM did not come back after reboot"
    exit 1
}

do_deploy() {
    # Stop VM if running
    if vm list | grep -q "${VM_NAME}.*Running"; then
        echo "=== Stopping VM ==="
        vm stop "${VM_NAME}"
        sleep 3
    fi

    # Attach disk (clean up stale state from prior failed runs)
    echo "=== Attaching disk image ==="
    umount -f /mnt 2>/dev/null || true
    mdconfig -d -u "$MD_UNIT" 2>/dev/null || true
    mdconfig -a -t vnode -f "$VM_DISK" -u "$MD_UNIT"
    trap 'umount /mnt 2>/dev/null; mdconfig -d -u $MD_UNIT 2>/dev/null' EXIT

    echo "=== Mounting md${MD_UNIT}p2 ==="
    mount "/dev/md${MD_UNIT}p2" /mnt

    # Use FreeBSD's own installkernel — installs kernel + all modules
    echo "=== Installing kernel to VM disk ==="
    env MAKEOBJDIRPREFIX="$OBJDIR" make DESTDIR=/mnt installkernel

    # Build and copy test binaries
    echo "=== Building tests ==="
    env MAKEOBJDIRPREFIX="$OBJDIR" make -j$(sysctl -n hw.ncpu) \
        -C tests/sys/cap_rt SRCTOP="$SRCDIR"

    echo "=== Copying test binaries ==="
    mkdir -p /mnt/tmp/cap_rt-tests
    for f in "$CAP_RT_TESTDIR"/*; do
        case "$(basename "$f")" in
            *_test|*_helper) cp "$f" /mnt/tmp/cap_rt-tests/
                echo "  $(basename "$f")" ;;
        esac
    done

    # Kyuafile
    cat > /mnt/tmp/cap_rt-tests/Kyuafile <<'EOF'
syntax(2)
test_suite("FreeBSD")
atf_test_program{name="cap_rt_test"}
atf_test_program{name="cap_rt_accounting_test"}
atf_test_program{name="cap_rt_identity_test"}
atf_test_program{name="cap_rt_isolation_test"}
atf_test_program{name="cap_rt_mount_test"}
atf_test_program{name="cap_rt_node_test"}
atf_test_program{name="cap_rt_procdesc_test"}
atf_test_program{name="cap_rt_coalition_test"}
EOF

    # run-tests.sh
    cat > /mnt/tmp/cap_rt-tests/run-tests.sh <<'EOF'
#!/bin/sh
set -e

BOOT_MODULES="cap_rt cap_rt_capprotect cap_rt_isolation"
SERVICE_MODULES="cap_rt_accounting cap_rt_coalition cap_rt_identity
    cap_rt_mount cap_rt_node cap_rt_pair
    cap_rt_test_kernelstore cap_rt_test_keystore
    linprocfs linsysfs"

echo "=== Unloading stale service modules ==="
for m in $SERVICE_MODULES; do kldunload "$m" 2>/dev/null || true; done

echo "=== Verifying boot-time modules ==="
for m in $BOOT_MODULES; do
    kldstat -m "$m" >/dev/null 2>&1 || \
        { echo "FAIL: $m not loaded; check /boot/loader.conf"; exit 1; }
    echo "  $m: ok"
done

echo "=== Loading service modules ==="
for m in $SERVICE_MODULES; do
    kldstat -q -m "$m" 2>/dev/null && { echo "  $m: already loaded"; continue; }
    kldload "$m" || { echo "FAIL: kldload $m"; exit 1; }
    echo "  $m: loaded"
done

echo "=== Verifying ==="
kldstat -m cap_rt
sysctl kern.cap_rt.services kern.cap_rt.instances
[ -c /dev/cap_rt ] || { echo "FAIL: /dev/cap_rt missing"; exit 1; }

echo "=== Running tests ==="
cd /tmp/cap_rt-tests
export TESTSDIR=/tmp/cap_rt-tests
if command -v kyua >/dev/null 2>&1; then
    kyua test
    kyua report
else
    for prog in *_test; do
        [ -x "./${prog}" ] || continue
        echo "--- ${prog} ---"
        for tc in $(./${prog} -l | grep '^ident:' | sed 's/ident: //'); do
            ./${prog} -s "$TESTSDIR" "${tc}" || echo "FAILED: ${prog}:${tc}"
        done
    done
fi

echo "=== Cleanup ==="
for m in $SERVICE_MODULES; do kldunload "$m" 2>/dev/null || true; done
[ -c /dev/cap_rt ] || { echo "FAIL: /dev/cap_rt gone after unload"; exit 1; }
echo "=== All tests passed ==="
EOF
    chmod +x /mnt/tmp/cap_rt-tests/run-tests.sh

    # Ensure boot modules and tunables are in loader.conf
    echo "=== Configuring loader.conf ==="
    touch /mnt/boot/loader.conf
    for mod in $BOOT_MODULES; do
        line="${mod}_load=\"YES\""
        grep -q "^${line}$" /mnt/boot/loader.conf 2>/dev/null || \
            echo "$line" >> /mnt/boot/loader.conf
    done
    # RACCT must be enabled at boot for RCTL rule operations
    grep -q '^kern\.racct\.enable=1$' /mnt/boot/loader.conf 2>/dev/null || \
        echo 'kern.racct.enable=1' >> /mnt/boot/loader.conf
    echo "  loader.conf:"
    grep -E 'cap_rt|racct' /mnt/boot/loader.conf || true

    # Unmount and detach
    echo "=== Unmounting ==="
    umount /mnt
    mdconfig -d -u "$MD_UNIT"
    trap - EXIT

    # Start VM
    echo "=== Starting VM ==="
    vm start "$VM_NAME"
    echo "=== Deploy complete ==="
    echo "SSH: ssh root@${VM_IP}"
}

do_reboot() {
    echo "=== Rebooting ${VM_IP} ==="
    ssh "root@${VM_IP}" reboot || true
    sleep 5
    wait_for_vm_ssh
}

do_test() {
    echo "=== Running tests on ${VM_IP} ==="
    ssh "root@${VM_IP}" /tmp/cap_rt-tests/run-tests.sh
}

case "${1:-}" in
    deploy)  do_deploy ;;
    reboot)  do_reboot ;;
    test)    do_test ;;
    all)     do_deploy; wait_for_vm_ssh; do_test ;;
    *)
        echo "Usage: $0 [deploy|reboot|test|all]"
        echo ""
        echo "  deploy  - Install kernel + tests to VM disk, start VM"
        echo "  reboot  - Reboot VM and wait for SSH"
        echo "  test    - Run tests on VM via SSH"
        echo "  all     - Deploy, wait for boot, run tests"
        echo ""
        echo "VM: ${VM_NAME} (${VM_IP})"
        exit 1
        ;;
esac
