#!/bin/sh
# Build only in the disposable guest, using the standard object tree.
set -eu
[ "$(hostname)" = auth-policy-vm ] || exit 1
jobs=$(sysctl -n hw.ncpu)
echo "BUILD_CPUS=$jobs"
export MAKEOBJDIRPREFIX=/usr/obj
src=/usr/src/usr.sbin/switchboard
out=/usr/obj/usr/src/amd64.amd64
mkdir -p "$out/usr.sbin/switchboard/tests"
# Installed libraries come from the same pkgbase generation as the source.
make -C "$src" MK_DTRACE=no MK_TESTS=no obj
make -C "$src" -j"$jobs" MK_DTRACE=no MK_TESTS=no all \
    LIBCAPABILITY=/usr/lib/libcapability.a LIBCAPBUNDLE=/usr/lib/libcapbundle.a \
    LIBCHANNEL=/usr/lib/libchannel.a LIBCAPSULERT=/usr/lib/libcapsulert.a \
    LIBSERVICE=/usr/lib/libservice.a LIBUCL=/usr/lib/libprivateucl.a \
    LIBUTIL=/usr/lib/libutil.a LIBBSM=/usr/lib/libbsm.a
obj=$(make -C "$src" MK_DTRACE=no MK_TESTS=no -V .OBJDIR)
install -m 0555 "$obj/switchboard" /usr/libexec/switchboard
cd "$out/usr.sbin/switchboard/tests"
cc -O2 -Wall -Wextra -Wno-unused-parameter -DMANAGEMENT_POLICY_TESTING \
    -I"$src" -I/usr/src/contrib/libucl/include \
    "$src/tests/management_policy_test.c" "$src/management_policy.c" \
    -lprivateucl -lprivateatf-c -o management_policy_test &
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
printf 'syntax(2)\ntest_suite("policy")\natf_test_program{name="management_policy_test"}\n' > Kyuafile
printf 'atf_test_program{name="management_enforce_test"}\n' >> Kyuafile
kyua test -k ./Kyuafile
# Password fixtures are set before reboot: BSDAuth retains the passwd fd.
printf '%s\n' 'policy-vm-only' | pw usermod policyuser -h 0
printf '%s\n' 'other-vm-only' | pw usermod otheruser -h 0
cc -O2 -Wall -Wextra /usr/src/usr.sbin/BSDAuth/tests/pty_askpass.c \
    -lutil -o pty_askpass
install -m 0555 pty_askpass /usr/bin/policy-askpass
printf '\nswitchboard_management_policy="YES"\n' >> /boot/loader.conf
touch /root/policy-build-passed
echo POLICY_BUILD_PASS
shutdown -r now
