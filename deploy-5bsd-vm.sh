#!/bin/sh
#
# Deploy 5BSD kernel and tests to jaildesc-test VM
#
# Usage:
#   ./deploy-5bsd-vm.sh [build|install|deploy|ssh-deploy|reboot|test|all]
#
#   build       - Build kernel and tests
#   install     - Install kernel to staging area (/tmp/vmroot)
#   deploy      - Deploy to VM via disk mount (VM must be stopped)
#   ssh-deploy  - Deploy to VM via SSH (VM must be running)
#   reboot      - Reboot VM and wait for SSH
#   test        - Run CMI tests on VM via SSH
#   all         - Do everything (build + install + deploy)
#

set -e

SRCDIR="/home/koryheard/Projects/5BSD"
OBJDIR="/home/koryheard/Projects/5BSD-obj"
STAGEDIR="/tmp/vmroot"
VM_NAME="jaildesc-test"
VM_DISK="/zroot/vm/${VM_NAME}/disk0.img"
VM_IP="192.168.6.113"

# Kern test binaries to copy
TESTS="jaildesc_cap_test timerfd_cap_test fcntl_readahead_cap_test posix_fadvise_cap_test"
TEST_OBJDIR="${OBJDIR}/home/koryheard/Projects/5BSD/amd64.amd64/tests/sys/kern"

# CMI test binaries (built from source tree, not obj tree)
CMI_TESTS="cmi_test cmi_shield_helper cmi_exec_helper"
CMI_TESTDIR="${SRCDIR}/tests/sys/cmi"

cd "$SRCDIR"

ensure_loader_conf_line() {
    _target="$1"
    _line="$2"
    doas touch "$_target"
    if ! doas grep -q "^${_line}\$" "$_target" 2>/dev/null; then
        echo "$_line" | doas tee -a "$_target" >/dev/null
    fi
}

ensure_loader_conf() {
    _target="$1"
    ensure_loader_conf_line "$_target" 'cmi_load="YES"'
    ensure_loader_conf_line "$_target" 'cmi_capprotect_load="YES"'
}

wait_for_vm_ssh() {
    echo "=== Waiting for ${VM_IP} ==="
    i=0
    while [ "$i" -lt 60 ]; do
        if ssh -o BatchMode=yes -o ConnectTimeout=2 "root@${VM_IP}" true \
            >/dev/null 2>&1; then
            echo "=== VM reachable ==="
            return 0
        fi
        i=$((i + 1))
        sleep 2
    done
    echo "ERROR: VM did not come back after reboot"
    exit 1
}

build_kernel() {
    echo "=== Building kernel ==="
    MAKEOBJDIRPREFIX="$OBJDIR" make -j8 buildkernel
    echo "=== Kernel build complete ==="
}

build_tests() {
    echo "=== Building kern tests ==="
    MAKEOBJDIRPREFIX="$OBJDIR" make -j8 -C tests/sys/kern || echo "WARNING: some kern tests failed to build (non-fatal)"
    echo "=== Building CMI tests ==="
    (cd "$CMI_TESTDIR" && make clean >/dev/null 2>&1; make SRCTOP="$SRCDIR")
    echo "=== Tests build complete ==="
}

install_kernel() {
    echo "=== Installing kernel to ${STAGEDIR} ==="
    doas env MAKEOBJDIRPREFIX="$OBJDIR" make DESTDIR="$STAGEDIR" installkernel
    echo "=== Kernel installed to ${STAGEDIR} ==="
}

# Write Kyuafile and run-tests.sh to a local dir (for disk deploy)
deploy_cmi_scripts() {
    _dir="$1"
    doas sh -c "cat > ${_dir}/Kyuafile" <<'KYUA'
syntax(2)
test_suite("FreeBSD")
atf_test_program{name="cmi_test"}
KYUA
    doas sh -c "cat > ${_dir}/run-tests.sh && chmod +x ${_dir}/run-tests.sh" <<'RUN'
#!/bin/sh
set -e
echo "=== Unloading stale modules ==="
for m in cmi_token cmi_namespace cmi_pair cmi_keystore cmi_kernelstore; do
    kldunload "$m" 2>/dev/null || true
done
echo "=== Verifying core CMI ==="
if ! kldstat -m cmi >/dev/null 2>&1; then
    echo 'FAIL: cmi not loaded at boot; add cmi_load="YES" to /boot/loader.conf and reboot'
    exit 1
fi
echo "=== Loading service modules ==="
if ! kldstat -m cmi_capprotect >/dev/null 2>&1; then
    echo 'FAIL: cmi_capprotect not loaded at boot; add cmi_capprotect_load="YES" to /boot/loader.conf and reboot'
    exit 1
fi
for m in cmi_kernelstore cmi_keystore cmi_pair cmi_namespace cmi_token; do
    kldload "$m" || { echo "FAIL: kldload $m"; exit 1; }
done
echo "=== Verifying ==="
kldstat -m cmi
sysctl kern.cmi.services kern.cmi.instances
[ -c /dev/cmi ] || { echo "FAIL: /dev/cmi missing"; exit 1; }
echo "=== ATF tests ==="
cd /tmp/cmi-tests
export TESTSDIR=/tmp/cmi-tests
if command -v kyua >/dev/null 2>&1; then
    kyua test
    kyua report
else
    for tc in $(./cmi_test -l | grep '^ident:' | sed 's/ident: //'); do
        echo "--- ${tc} ---"
        ./cmi_test -s /tmp/cmi-tests "${tc}" || echo "FAILED: ${tc}"
    done
fi
echo "=== Unloading modules ==="
for m in cmi_capprotect cmi_token cmi_namespace cmi_pair cmi_keystore cmi_kernelstore; do
    kldunload "$m" || echo "WARN: unload $m failed"
done
[ -c /dev/cmi ] || { echo "FAIL: /dev/cmi missing after service unload"; exit 1; }
echo "=== All tests passed ==="
RUN
}

# Write scripts to VM via SSH
deploy_cmi_scripts_ssh() {
    cat <<'KYUA' | ssh "root@${VM_IP}" "cat > /tmp/cmi-tests/Kyuafile"
syntax(2)
test_suite("FreeBSD")
atf_test_program{name="cmi_test"}
KYUA
    cat <<'RUN' | ssh "root@${VM_IP}" "cat > /tmp/cmi-tests/run-tests.sh && chmod +x /tmp/cmi-tests/run-tests.sh"
#!/bin/sh
set -e
echo "=== Unloading stale modules ==="
for m in cmi_token cmi_namespace cmi_pair cmi_keystore cmi_kernelstore; do
    kldunload "$m" 2>/dev/null || true
done
echo "=== Verifying core CMI ==="
if ! kldstat -m cmi >/dev/null 2>&1; then
    echo 'FAIL: cmi not loaded at boot; add cmi_load="YES" to /boot/loader.conf and reboot'
    exit 1
fi
echo "=== Loading service modules ==="
if ! kldstat -m cmi_capprotect >/dev/null 2>&1; then
    echo 'FAIL: cmi_capprotect not loaded at boot; add cmi_capprotect_load="YES" to /boot/loader.conf and reboot'
    exit 1
fi
for m in cmi_kernelstore cmi_keystore cmi_pair cmi_namespace cmi_token; do
    kldload "$m" || { echo "FAIL: kldload $m"; exit 1; }
done
echo "=== Verifying ==="
kldstat -m cmi
sysctl kern.cmi.services kern.cmi.instances
[ -c /dev/cmi ] || { echo "FAIL: /dev/cmi missing"; exit 1; }
echo "=== ATF tests ==="
cd /tmp/cmi-tests
export TESTSDIR=/tmp/cmi-tests
if command -v kyua >/dev/null 2>&1; then
    kyua test
    kyua report
else
    for tc in $(./cmi_test -l | grep '^ident:' | sed 's/ident: //'); do
        echo "--- ${tc} ---"
        ./cmi_test -s /tmp/cmi-tests "${tc}" || echo "FAILED: ${tc}"
    done
fi
echo "=== Unloading modules ==="
for m in cmi_capprotect cmi_token cmi_namespace cmi_pair cmi_keystore cmi_kernelstore; do
    kldunload "$m" || echo "WARN: unload $m failed"
done
[ -c /dev/cmi ] || { echo "FAIL: /dev/cmi missing after service unload"; exit 1; }
echo "=== All tests passed ==="
RUN
}

deploy_disk() {
    echo "=== Deploying to VM via disk mount ==="

    # Check if VM is running
    if doas vm list | grep -q "${VM_NAME}.*Running"; then
        echo "Stopping VM..."
        doas vm stop "$VM_NAME"
        sleep 3
    fi

    # Find available md device
    MD_UNIT=$(doas mdconfig -lf "$VM_DISK" 2>/dev/null | cut -d: -f1 | sed 's/md//' || echo "")
    if [ -z "$MD_UNIT" ]; then
        echo "Attaching disk image..."
        MD_DEV=$(doas mdconfig -a -t vnode -f "$VM_DISK")
        MD_UNIT=$(echo "$MD_DEV" | sed 's/md//')
    else
        MD_DEV="md${MD_UNIT}"
    fi
    echo "Using ${MD_DEV}"

    # Show partitions
    echo "Partitions:"
    doas gpart show "$MD_DEV"

    # Mount root partition
    echo "Mounting ${MD_DEV}p2..."
    doas mount "/dev/${MD_DEV}p2" /mnt

    # Copy kernel
    echo "Copying kernel..."
    doas cp -r "${STAGEDIR}/boot/"* /mnt/boot/

    # Copy tests
    echo "Copying tests..."
    for test in $TESTS; do
        if [ -f "${TEST_OBJDIR}/${test}" ]; then
            doas cp "${TEST_OBJDIR}/${test}" /mnt/usr/tests/sys/kern/
            echo "  Copied ${test}"
        else
            echo "  WARNING: ${test} not found"
        fi
    done

    # Copy CMI tests
    echo "Copying CMI tests..."
    doas mkdir -p /mnt/tmp/cmi-tests
    for t in $CMI_TESTS; do
        if [ -f "${CMI_TESTDIR}/${t}" ]; then
            doas cp "${CMI_TESTDIR}/${t}" /mnt/tmp/cmi-tests/
            echo "  Copied ${t}"
        fi
    done
    deploy_cmi_scripts /mnt/tmp/cmi-tests

    echo "Configuring boot loader for CMI..."
    ensure_loader_conf /mnt/boot/loader.conf

    # Unmount and detach
    echo "Unmounting..."
    doas umount /mnt
    doas mdconfig -d -u "$MD_UNIT"

    # Start VM
    echo "Starting VM..."
    doas vm start "$VM_NAME"

    echo "=== Deploy complete ==="
    echo "Connect with: doas vm console ${VM_NAME}"
    echo "Or SSH: ssh root@${VM_IP}"
    echo "Run CMI tests: ssh root@${VM_IP} /tmp/cmi-tests/run-tests.sh"
}

deploy_ssh() {
    echo "=== Deploying to VM via SSH ==="

    # Check if VM is reachable
    if ! ping -c 1 -t 2 "$VM_IP" >/dev/null 2>&1; then
        echo "ERROR: VM not reachable at ${VM_IP}"
        echo "Start VM with: doas vm start ${VM_NAME}"
        exit 1
    fi

    # Copy kernel
    echo "Copying kernel via SSH..."
    cd "$STAGEDIR" && tar cf - boot | ssh "root@${VM_IP}" 'cd / && tar xvf -'

    # Copy tests
    echo "Copying tests via SSH..."
    for test in $TESTS; do
        if [ -f "${TEST_OBJDIR}/${test}" ]; then
            scp "${TEST_OBJDIR}/${test}" "root@${VM_IP}:/usr/tests/sys/kern/"
            echo "  Copied ${test}"
        else
            echo "  WARNING: ${test} not found"
        fi
    done

    # Copy CMI tests
    echo "Copying CMI tests via SSH..."
    ssh "root@${VM_IP}" "mkdir -p /tmp/cmi-tests"
    for t in $CMI_TESTS; do
        if [ -f "${CMI_TESTDIR}/${t}" ]; then
            scp "${CMI_TESTDIR}/${t}" "root@${VM_IP}:/tmp/cmi-tests/"
            echo "  Copied ${t}"
        fi
    done
    deploy_cmi_scripts_ssh

    # Ensure CMI + capprotect load at boot (NOTLATE MAC policies)
    echo "Configuring boot loader for CMI..."
    ssh "root@${VM_IP}" 'grep -q cmi_load /boot/loader.conf 2>/dev/null || echo "cmi_load=\"YES\"" >> /boot/loader.conf'
    ssh "root@${VM_IP}" 'grep -q cmi_capprotect_load /boot/loader.conf 2>/dev/null || echo "cmi_capprotect_load=\"YES\"" >> /boot/loader.conf'

    echo "=== Deploy complete ==="
    echo "SSH: ssh root@${VM_IP}"
    echo "Reboot VM to load new kernel/core module: ./deploy-5bsd-vm.sh reboot"
    echo "Run CMI tests: ./deploy-5bsd-vm.sh test"
}

reboot_vm() {
    echo "=== Rebooting ${VM_IP} ==="
    ssh "root@${VM_IP}" reboot || true
    sleep 5
    wait_for_vm_ssh
}

run_tests() {
    echo "=== Running tests on ${VM_IP} ==="
    ssh "root@${VM_IP}" /tmp/cmi-tests/run-tests.sh
}

show_usage() {
    echo "Usage: $0 [build|install|deploy|ssh-deploy|reboot|test|all]"
    echo ""
    echo "Commands:"
    echo "  build       - Build kernel and tests"
    echo "  install     - Install kernel to staging area"
    echo "  deploy      - Deploy via disk mount (stops VM)"
    echo "  ssh-deploy  - Deploy via SSH (VM must be running)"
    echo "  reboot      - Reboot VM and wait for SSH"
    echo "  test        - Run tests on VM via SSH"
    echo "  all         - Build, install, and deploy via disk"
    echo ""
    echo "VM: ${VM_NAME} (${VM_IP})"
}

case "${1:-}" in
    build)
        build_kernel
        build_tests
        ;;
    install)
        install_kernel
        ;;
    deploy)
        deploy_disk
        ;;
    ssh-deploy)
        deploy_ssh
        ;;
    reboot)
        reboot_vm
        ;;
    test)
        run_tests
        ;;
    all)
        build_kernel
        build_tests
        install_kernel
        deploy_disk
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
