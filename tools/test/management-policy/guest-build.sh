#!/bin/sh
# Build only in the disposable guest, using the standard object tree.
set -eu
[ "$(hostname)" = auth-policy-vm ] || exit 1
jobs=$(sysctl -n hw.ncpu)
echo "BUILD_CPUS=$jobs"
export MAKEOBJDIRPREFIX=/usr/obj
src=/usr/src/usr.sbin/switchboard
# A seeded, matching GENERIC object tree permits an incremental guest kernel
# rebuild for the veriexec regression.  No host installation is performed.
if [ -f /root/policy-kernel-seed.sha256 ]; then
    kobj=/usr/obj/usr/src/amd64.amd64/sys/GENERIC
    test "$(uname -i)" = GENERIC
    test "$(sysctl -n hw.machine_arch)" = amd64
    test "$(sha256 -q /boot/kernel/kernel)" = "$(cat /root/policy-kernel-seed.sha256)"
    make -C "$kobj" -j"$jobs" MK_META_MODE=no kernel
    config -x /boot/kernel/kernel > /root/original-kernel.conf
    config -x "$kobj/kernel" > /root/rebuilt-kernel.conf
    cmp /root/original-kernel.conf /root/rebuilt-kernel.conf
    install -m 0555 "$kobj/kernel" /boot/kernel/kernel
    touch /root/policy-kernel-rebuilt
    echo POLICY_KERNEL_BUILD_PASS
fi
out=/usr/obj/usr/src/amd64.amd64
mkdir -p "$out/usr.sbin/switchboard/tests"
# Build changed libraries and consumers in the standard guest object tree.
make -C /usr/src/lib/libcapbundle MK_DTRACE=no MK_TESTS=no obj
make -C /usr/src/lib/libcapbundle -j"$jobs" MK_DTRACE=no MK_TESTS=no all \
    LIBCAPSULERT=/usr/lib/libcapsulert.a LIBUCL=/usr/lib/libprivateucl.a LIBMD=/usr/lib/libmd.a
make -C /usr/src/lib/libcapbundle MK_DTRACE=no MK_TESTS=no MK_MAN=no install
make -C /usr/src/usr.sbin/BSDAuth MK_DTRACE=no MK_TESTS=no obj
make -C /usr/src/usr.sbin/BSDAuth -j"$jobs" MK_DTRACE=no MK_TESTS=no all \
    LIBSERVICE=/usr/lib/libservice.a LIBCHANNEL=/usr/lib/libchannel.a \
    LIBCAPABILITY=/usr/lib/libcapability.a LIBCAPBUNDLE=/usr/lib/libcapbundle.a \
    LIBCRYPT=/usr/lib/libcrypt.a LIBAUDITCMP=/usr/lib/libauditcmp.a
obj=$(make -C /usr/src/usr.sbin/BSDAuth MK_DTRACE=no MK_TESTS=no -V .OBJDIR)
install -m 0555 "$obj/BSDAuth" /Capabilities/System/Auth.cap/Units/bsdauth.unit/bin/BSDAuth
make -C /usr/src/usr.sbin/policyctl MK_DTRACE=no MK_TESTS=no obj
make -C /usr/src/usr.sbin/policyctl -j"$jobs" MK_DTRACE=no MK_TESTS=no all \
    LIBCAPBUNDLE=/usr/lib/libcapbundle.a LIBUCL=/usr/lib/libprivateucl.a
obj=$(make -C /usr/src/usr.sbin/policyctl MK_DTRACE=no MK_TESTS=no -V .OBJDIR)
install -m 0555 "$obj/policyctl" /usr/sbin/policyctl
make -C "$src" MK_DTRACE=no MK_TESTS=no obj
make -C "$src" -j"$jobs" MK_DTRACE=no MK_TESTS=no all \
    LIBCAPABILITY=/usr/lib/libcapability.a LIBCAPBUNDLE=/usr/lib/libcapbundle.a \
    LIBCHANNEL=/usr/lib/libchannel.a LIBCAPSULERT=/usr/lib/libcapsulert.a \
    LIBSERVICE=/usr/lib/libservice.a LIBUCL=/usr/lib/libprivateucl.a \
    LIBUTIL=/usr/lib/libutil.a LIBBSM=/usr/lib/libbsm.a
obj=$(make -C "$src" MK_DTRACE=no MK_TESTS=no -V .OBJDIR)
install -m 0555 "$obj/switchboard" /usr/libexec/switchboard
cd "$out/usr.sbin/switchboard/tests"
cc -O2 -Wall -Wextra -Wno-unused-parameter \
    -I/usr/src/lib/libcapbundle -I/usr/src/lib/libcapsulert \
    /usr/src/lib/libcapbundle/tests/principal_policy_test.c \
    -lcapbundle -lprivateatf-c -o principal_policy_test &
p1=$!
cc -O2 -Wall -Wextra -I/usr/src/lib/libservice \
    /usr/src/tools/test/management-policy/fixture.c -lservice -o fixture &
p2=$!
cc -O2 -Wall -Wextra -I/usr/src/lib/libservice -I/usr/src/lib/libcapsulert \
    /usr/src/tools/test/management-policy/probe.c -lservice -o probe &
p3=$!
cc -O2 -Wall -Wextra -Wno-unused-parameter \
    -I"$src" -I/usr/src/sys -I/usr/src/lib/libcapbundle \
    -I/usr/src/lib/libcapsulert -I/usr/src/lib/libservice \
    "$src/tests/management_enforce_test.c" "$src/management.c" \
    -lprivateatf-c -o management_enforce_test &
p4=$!
wait "$p1"; wait "$p2"; wait "$p3"; wait "$p4"
install -m 0555 probe /root/policy-probe
for name in network storage; do
    install -m 0555 fixture "/Capabilities/System/Policy-$name.cap/Units/worker.unit/bin/worker"
done
printf 'syntax(2)\ntest_suite("policy")\natf_test_program{name="principal_policy_test"}\n' > Kyuafile
printf 'atf_test_program{name="management_enforce_test"}\n' >> Kyuafile
# Build through the regular test Makefile as well as exercising the pure
# authentication, identity, elevation, and mint-decision tests below.
auth_tests=/usr/src/usr.sbin/BSDAuth/tests
make -C "$auth_tests" MK_DTRACE=no obj
make -C "$auth_tests" -j"$jobs" MK_DTRACE=no all \
    LIBSERVICE=/usr/lib/libservice.a LIBCHANNEL=/usr/lib/libchannel.a \
    LIBCAPABILITY=/usr/lib/libcapability.a LIBCAPBUNDLE=/usr/lib/libcapbundle.a \
    LIBCRYPT=/usr/lib/libcrypt.a LIBAUDITCMP=/usr/lib/libauditcmp.a \
    LIBUTIL=/usr/lib/libutil.a
obj=$(make -C "$auth_tests" MK_DTRACE=no -V .OBJDIR)
for test in gate_test elevate_test identity_test mint_decision_test; do
    cp "$obj/$test" "$test"
    printf 'atf_test_program{name="%s"}\n' "$test" >> Kyuafile
done
# Exercise the actual filesystem grant boundary, then its kernel verification
# in the final disposable-VM phase after the BE rollback evidence is exported.
fs=/usr/src/usr.sbin/BSDFilesystem
for sub in "$fs" "$fs/tests"; do
    case "$sub" in */tests) testmode=yes ;; *) testmode=no ;; esac
    make -C "$sub" MK_DTRACE=no MK_TESTS="$testmode" obj
    make -C "$sub" -j"$jobs" MK_DTRACE=no MK_TESTS="$testmode" all \
        LIBTRUSTEDZFS=/usr/lib/libtrustedzfs.a LIBUCL=/usr/lib/libprivateucl.a \
        LIBNVPAIR=/usr/lib/libnvpair.a LIBSERVICE=/usr/lib/libservice.a \
        LIBCHANNEL=/usr/lib/libchannel.a LIBMD=/usr/lib/libmd.a \
        LIBCAPRECLAIM=/usr/lib/libcapreclaim.a LIBLOGCMP=/usr/lib/liblogcmp.a \
        LIBSPL=/usr/lib/libspl.a LIBM=/usr/lib/libm.a \
        LIBCAPABILITY=/usr/lib/libcapability.a LIBCAPSULERT=/usr/lib/libcapsulert.a \
        LIBSHMRING=/usr/lib/libshmring.a LIBTHR=/usr/lib/libthr.a \
        LIBC=/usr/lib/libc.a LIBSYS=/usr/lib/libsys.a \
        LIBCOMPILER_RT=/usr/lib/libcompiler_rt.a
done
obj=$(make -C "$fs" MK_DTRACE=no -V .OBJDIR)
install -m 0555 "$obj/BSDFilesystem" /Capabilities/System/Filesystem.cap/Units/bsdfilesystem.unit/bin/BSDFilesystem
install -m 0644 "$fs/bsdfilesystem.ucl" /Capabilities/Config/bsdfilesystem.ucl
obj=$(make -C "$fs/tests" MK_DTRACE=no -V .OBJDIR)
cp "$obj/namespace_test" ./namespace_test
printf 'atf_test_program{name="namespace_test"}\n' >> Kyuafile
cc -O2 -Wall -Wextra -static -DBSDFILESYSTEM_TESTING \
    -I"$fs" -I/usr/src/sys -I/usr/src/lib/libcapsulert \
    -I/usr/src/lib/libtrustedzfs -I/usr/src/lib/libservice \
    /usr/src/tools/test/management-policy/verified-open-vm.c \
    "$obj/request.o" "$obj/layout.o" "$obj/nvwalk.o" "$obj/config.o" \
    -Wl,--start-group -ltrustedzfs -lprivateucl -lnvpair -lspl -lservice \
    -lcapability -lchannel -lcapsulert -lcapreclaim -llogcmp -lshmring \
    -lmd -lm -lpthread -Wl,--end-group \
    -o /root/verified-open-vm
kyua test -k ./Kyuafile
policyctl init > /root/empty-policy.ucl
policyctl validate /root/empty-policy.ucl
policyctl format /Capabilities/Config/principal-policy.ucl > /root/formatted-policy.ucl
policyctl validate /root/formatted-policy.ucl
policyctl explain /root/formatted-policy.ucl policyuser | grep 'system.trace.client'
printf 'principals { default { typo=true; } }\n' > /root/bad-policy.ucl
if policyctl validate /root/bad-policy.ucl; then exit 1; fi
sh /usr/src/tools/test/management-policy/installer-test.sh
echo POLICY_TOOL_PASS
# Password fixtures are set before reboot: BSDAuth retains the passwd fd.
printf '%s\n' 'policy-vm-only' | pw usermod policyuser -h 0
printf '%s\n' 'other-vm-only' | pw usermod otheruser -h 0
printf '%s\n' 'admin-vm-only' | pw usermod adminuser -h 0
printf '%s\n' 'all-vm-only' | pw usermod alluser -h 0
cc -O2 -Wall -Wextra /usr/src/usr.sbin/BSDAuth/tests/pty_askpass.c \
    -lutil -o pty_askpass
install -m 0555 pty_askpass /usr/bin/policy-askpass
touch /root/policy-build-passed
echo POLICY_BUILD_PASS
shutdown -r now
