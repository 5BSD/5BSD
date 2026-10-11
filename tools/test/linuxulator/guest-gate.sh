#!/bin/sh
PATH=/sbin:/bin:/usr/sbin:/usr/bin
export PATH
mount -uw / || exit 1
mount -t devfs devfs /dev 2>/dev/null || true
ifconfig lo0 inet 127.0.0.1 up
mkdir -p /tmp/linuxulator-gate
chmod 1777 /tmp
cd /tmp/linuxulator-gate || exit 1
echo LINUXULATOR_GATE_BEGIN
# The supported base system boots from ZFS; a UFS-root run cannot qualify it.
require_zfs()
{
    df -T "$1" | {
        read -r header
        read -r device type rest
        [ "$type" = zfs ]
    }
}
require_zfs / || exit 1
require_zfs /tmp/linuxulator-gate || exit 1
echo GATE_ROOT_FS zfs
mount -p
zpool status || exit 1
zfs list || exit 1
uname -a
sha256 /boot/kernel/kernel /boot/kernel/zfs.ko /boot/kernel/linux64.ko /boot/kernel/linux_common.ko /root/linux_abi_gate /root/linux_fileattr /root/linux_fchroot /root/ofd_native /root/ofd_linux /root/ofd_native_extra /root/seal_native /root/seal_linux /root/linux_resolve
sha256 /root/linux_rwf
if [ "$(uname -m)" = amd64 ]; then sha256 /root/linux_fallocate; fi
kldstat -q -n linux64.ko || kldload /boot/kernel/linux64.ko || exit 1
if [ "$(uname -m)" = amd64 ]; then
    sha256 /root/linux_unshare /root/unshare_capmode /root/unshare_capmode_probe
    for round in 1 2 3; do
        timeout 30 /root/unshare_capmode /root/unshare_capmode_probe
        rc=$?
        echo GATE_UNSHARE_CAPMODE "$round" "$rc"
        [ "$rc" -eq 0 ] || exit 1
    done
    mkdir -p /tmp/linuxulator-gate/unshare-zfs /tmp/linuxulator-gate/unshare-tmpfs
    mount -t tmpfs tmpfs /tmp/linuxulator-gate/unshare-tmpfs || exit 1
    for fs in zfs tmpfs; do
        for round in 1 2 3; do
            for case in zero_preserves_sharing fs_detaches_only_paths_and_umask files_detaches_only_descriptors fs_files_detach_both files_preserves_open_description invalid_flags rejection_preserves_sharing fs_unprivileged fs_repeated fs_fork_exec_lifetime files_exec_detaches fs_exec_preserves_sharing fs_root_lifetime fs_concurrent_shared_mutation bsd_rejected_flags bsd_thread_rejection bsd_epoll_rejection; do
                (cd "/tmp/linuxulator-gate/unshare-$fs" && timeout 30 /root/linux_unshare "$case")
                rc=$?
                echo GATE_UNSHARE "$fs" "$round" "$case" "$rc"
                [ "$rc" -eq 0 ] || exit 1
            done
        done
    done
    umount /tmp/linuxulator-gate/unshare-tmpfs || exit 1
fi
if [ "$(uname -m)" = amd64 ]; then
    /bin/sh /root/guest-quota.sh || exit 1
    /bin/sh /root/guest-ptrace.sh || exit 1
    /bin/sh /root/guest-cookie.sh || exit 1
    /bin/sh /root/guest-xstate-mcast.sh || exit 1
    /bin/sh /root/guest-peer-events.sh || exit 1
    sha256 /root/linux_sysfs64
    for round in 1 2 3; do
        timeout 30 /root/linux_sysfs64
        result=$?
        echo "GATE_SYSFS zfs 64 $round $result"
        [ "$result" -eq 0 ] || exit 1
    done
    mkdir -p /tmp/linuxulator-gate/sysfs-tmp
    mount -t tmpfs tmpfs /tmp/linuxulator-gate/sysfs-tmp || exit 1
    for round in 1 2 3; do
        (cd /tmp/linuxulator-gate/sysfs-tmp && timeout 30 /root/linux_sysfs64)
        result=$?
        echo "GATE_SYSFS tmpfs 64 $round $result"
        [ "$result" -eq 0 ] || exit 1
    done
    umount /tmp/linuxulator-gate/sysfs-tmp || exit 1
fi
run_rseq_hold()
(
    cd "$1" || exit 1
    rm -f rseq-active rseq-unload.out
    /root/linux_rseq_hold &
    rseq_hold_pid=$!
    rseq_hold_wait=0
    while [ ! -f rseq-active ] && [ "$rseq_hold_wait" -lt 5 ]; do
        kill -0 "$rseq_hold_pid" 2>/dev/null || break
        sleep 1
        rseq_hold_wait=$((rseq_hold_wait + 1))
    done
    if [ "$(cat rseq-active 2>/dev/null)" != ready ]; then
        kill "$rseq_hold_pid" 2>/dev/null
        wait "$rseq_hold_pid" 2>/dev/null
        exit 1
    fi
    if kldunload linux64.ko >rseq-unload.out 2>&1; then
        echo "rseq-active Linux module unexpectedly unloaded"
        kill "$rseq_hold_pid" 2>/dev/null
        wait "$rseq_hold_pid" 2>/dev/null
        exit 1
    fi
    rseq_unload_output=$(cat rseq-unload.out)
    case "$rseq_unload_output" in
        *busy*|*Busy*) ;;
        *) echo "$rseq_unload_output"; kill "$rseq_hold_pid" 2>/dev/null
           wait "$rseq_hold_pid" 2>/dev/null; exit 1 ;;
    esac
    if ! kldstat -q -n linux64.ko; then
        kill "$rseq_hold_pid" 2>/dev/null
        wait "$rseq_hold_pid" 2>/dev/null
        exit 1
    fi
    kill "$rseq_hold_pid" || exit 1
    wait "$rseq_hold_pid" 2>/dev/null
    rm rseq-active rseq-unload.out
    exit 0
)
if [ "$(uname -m)" = amd64 ]; then
    ulimit -c 0
    sha256 /root/linux_rseq /root/linux_rseq_signal /root/linux_rseq_threads /root/linux_rseq_lifecycle /root/linux_rseq_auxv /root/linux_rseq_preempt /root/linux_rseq_hold
    for fs in zfs tmpfs; do
        if [ "$fs" = tmpfs ]; then
            mkdir -p /tmp/linuxulator-gate/rseq-tmp
            mount -t tmpfs tmpfs /tmp/linuxulator-gate/rseq-tmp || exit 1
        fi
        for round in 1 2 3; do
            for case in register signal threads lifecycle auxv preempt hold; do
                binary=/root/linux_rseq
                [ "$case" = signal ] && binary=/root/linux_rseq_signal
                [ "$case" = threads ] && binary=/root/linux_rseq_threads
                [ "$case" = lifecycle ] && binary=/root/linux_rseq_lifecycle
                [ "$case" = auxv ] && binary=/root/linux_rseq_auxv
                [ "$case" = preempt ] && binary=/root/linux_rseq_preempt
                if [ "$case" = hold ]; then
                    if [ "$fs" = zfs ]; then
                        run_rseq_hold /tmp/linuxulator-gate
                    else
                        run_rseq_hold /tmp/linuxulator-gate/rseq-tmp
                    fi
                elif [ "$fs" = zfs ]; then
                    timeout 30 "$binary"
                else
                    (cd /tmp/linuxulator-gate/rseq-tmp && timeout 30 "$binary")
                fi
                result=$?
                echo "GATE_RSEQ $fs $case $round $result"
                [ "$result" -eq 0 ] || exit 1
            done
        done
        if [ "$fs" = tmpfs ]; then
            umount /tmp/linuxulator-gate/rseq-tmp || exit 1
        fi
    done
fi
if [ "$(uname -m)" = amd64 ]; then
    sha256 /root/linux_perf_event
    /root/linux_perf_event -l >perf-cases.txt || exit 1
    [ "$(wc -l <perf-cases.txt | tr -d ' ')" -eq 13 ] || exit 1
    for fs in zfs tmpfs; do
        if [ "$fs" = tmpfs ]; then
            mkdir -p /tmp/linuxulator-gate/perf-tmp
            mount -t tmpfs tmpfs /tmp/linuxulator-gate/perf-tmp || exit 1
            perf_base=/tmp/linuxulator-gate/perf-tmp
        else
            perf_base=/tmp/linuxulator-gate
        fi
        for round in 1 2 3; do
            while read -r name; do
                (cd "$perf_base" && timeout 30 /root/linux_perf_event "$name")
                result=$?
                echo "GATE_PERF $fs $round $name $result"
                [ "$result" -eq 0 ] || exit 1
            done <perf-cases.txt
        done
        if [ "$fs" = tmpfs ]; then
            umount /tmp/linuxulator-gate/perf-tmp || exit 1
        fi
    done
    sha256 /root/perf_native_hold
    rm -f perf-native-ready perf-native-release perf-native-unload.out
    /root/linux_perf_event native_exec_hold /root/perf_native_hold \
        /tmp/linuxulator-gate/perf-native-ready \
        /tmp/linuxulator-gate/perf-native-release &
    perf_hold_pid=$!
    for attempt in 1 2 3 4 5; do
        [ -f perf-native-ready ] && break
        kill -0 "$perf_hold_pid" 2>/dev/null || break
        sleep 1
    done
    [ -f perf-native-ready ] || { kill "$perf_hold_pid" 2>/dev/null; exit 1; }
    if kldunload linux64.ko >perf-native-unload.out 2>&1; then
        echo "linux64 unexpectedly unloaded with native-held perf fd"
        : >perf-native-release
        wait "$perf_hold_pid" 2>/dev/null
        exit 1
    fi
    case "$(cat perf-native-unload.out)" in
        *busy*|*Busy*) ;;
        *) cat perf-native-unload.out; : >perf-native-release
           wait "$perf_hold_pid" 2>/dev/null; exit 1 ;;
    esac
    kldstat -q -n linux64.ko || exit 1
    : >perf-native-release
    wait "$perf_hold_pid" || exit 1
    rm -f perf-native-ready perf-native-release perf-native-unload.out
    echo GATE_PERF_NATIVE_EXEC 0
fi
if [ "$(uname -m)" = amd64 ]; then
    sha256 /root/linux_remap_file_pages
    for round in 1 2 3; do
        timeout 30 /root/linux_remap_file_pages
        result=$?
        echo "GATE_REMAP zfs $round $result"
        [ "$result" -eq 0 ] || exit 1
    done
    mkdir -p /tmp/linuxulator-gate/remap-tmp
    mount -t tmpfs tmpfs /tmp/linuxulator-gate/remap-tmp || exit 1
    for round in 1 2 3; do
        (cd /tmp/linuxulator-gate/remap-tmp && timeout 30 /root/linux_remap_file_pages)
        result=$?
        echo "GATE_REMAP tmpfs $round $result"
        [ "$result" -eq 0 ] || exit 1
    done
    umount /tmp/linuxulator-gate/remap-tmp || exit 1
fi
if [ "$(uname -m)" = amd64 ]; then
    sha256 /root/linux_ioperm /root/ioperm_native
    for round in 1 2 3; do
        timeout 30 /root/linux_ioperm
        result=$?
        echo "GATE_IOPERM zfs $round $result"
        [ "$result" -eq 0 ] || exit 1
        timeout 30 /root/ioperm_native
        result=$?
        echo "GATE_IOPERM_NATIVE zfs $round $result"
        [ "$result" -eq 0 ] || exit 1
    done
    mkdir -p /tmp/linuxulator-gate/ioperm-tmp
    mount -t tmpfs tmpfs /tmp/linuxulator-gate/ioperm-tmp || exit 1
    for round in 1 2 3; do
        (cd /tmp/linuxulator-gate/ioperm-tmp && timeout 30 /root/linux_ioperm)
        result=$?
        echo "GATE_IOPERM tmpfs $round $result"
        [ "$result" -eq 0 ] || exit 1
        (cd /tmp/linuxulator-gate/ioperm-tmp && timeout 30 /root/ioperm_native)
        result=$?
        echo "GATE_IOPERM_NATIVE tmpfs $round $result"
        [ "$result" -eq 0 ] || exit 1
    done
    umount /tmp/linuxulator-gate/ioperm-tmp || exit 1
fi
if [ "$(uname -m)" = amd64 ]; then
    sha256 /root/linux_iopl_options
    for round in 1 2 3; do
        timeout 30 /root/linux_iopl_options
        result=$?
        echo "GATE_IOPL zfs $round $result"
        [ "$result" -eq 0 ] || exit 1
    done
    mkdir -p /tmp/linuxulator-gate/iopl-tmp
    mount -t tmpfs tmpfs /tmp/linuxulator-gate/iopl-tmp || exit 1
    for round in 1 2 3; do
        (cd /tmp/linuxulator-gate/iopl-tmp && timeout 30 /root/linux_iopl_options)
        result=$?
        echo "GATE_IOPL tmpfs $round $result"
        [ "$result" -eq 0 ] || exit 1
    done
    umount /tmp/linuxulator-gate/iopl-tmp || exit 1
fi
if [ "$(uname -m)" = amd64 ]; then
    sha256 /root/linux_modify_ldt
    for round in 1 2 3; do
        timeout 30 /root/linux_modify_ldt
        result=$?
        echo "GATE_LDT zfs $round $result"
        [ "$result" -eq 0 ] || exit 1
    done
    mkdir -p /tmp/linuxulator-gate/ldt-tmp
    mount -t tmpfs tmpfs /tmp/linuxulator-gate/ldt-tmp || exit 1
    for round in 1 2 3; do
        (cd /tmp/linuxulator-gate/ldt-tmp && timeout 30 /root/linux_modify_ldt)
        result=$?
        echo "GATE_LDT tmpfs $round $result"
        [ "$result" -eq 0 ] || exit 1
    done
    umount /tmp/linuxulator-gate/ldt-tmp || exit 1
fi
if [ "$(uname -m)" = amd64 ]; then
    sha256 /root/linux_swapoff
    for round in 1 2 3; do
        timeout 30 /root/linux_swapoff
        result=$?
        echo "GATE_SWAPOFF zfs $round $result"
        [ "$result" -eq 0 ] || exit 1
    done
    mkdir -p /tmp/linuxulator-gate/swapoff-tmp
    mount -t tmpfs tmpfs /tmp/linuxulator-gate/swapoff-tmp || exit 1
    for round in 1 2 3; do
        (cd /tmp/linuxulator-gate/swapoff-tmp && timeout 30 /root/linux_swapoff)
        result=$?
        echo "GATE_SWAPOFF tmpfs $round $result"
        [ "$result" -eq 0 ] || exit 1
    done
    umount /tmp/linuxulator-gate/swapoff-tmp || exit 1
fi
if [ "$(uname -m)" = amd64 ]; then
    sha256 /root/linux_swapon_flags
    for round in 1 2 3; do
        timeout 30 /root/linux_swapon_flags
        result=$?
        echo "GATE_SWAPON_FLAGS zfs $round $result"
        [ "$result" -eq 0 ] || exit 1
    done
    mkdir -p /tmp/linuxulator-gate/swapon-tmp
    mount -t tmpfs tmpfs /tmp/linuxulator-gate/swapon-tmp || exit 1
    for round in 1 2 3; do
        (cd /tmp/linuxulator-gate/swapon-tmp && timeout 30 /root/linux_swapon_flags)
        result=$?
        echo "GATE_SWAPON_FLAGS tmpfs $round $result"
        [ "$result" -eq 0 ] || exit 1
    done
    umount /tmp/linuxulator-gate/swapon-tmp || exit 1
fi
if [ "$(uname -m)" = amd64 ]; then
    sha256 /root/aio_compat_native /root/linux_aio_context /root/linux_aio_rw \
        /root/linux_aio_full /root/linux_aio_capacity /root/linux_aio_flags \
        /root/linux_aio_cancel /root/linux_aio_poll /root/linux_aio_signal \
        /root/linux_aio_timeout /root/linux_aio_counts /root/linux_aio_nosignal
for round in 1 2 3; do
    timeout 30 /root/aio_compat_native
    result=$?
    echo "GATE_NATIVE_AIO zfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
mkdir -p /tmp/linuxulator-gate/native-aio-tmp
mount -t tmpfs tmpfs /tmp/linuxulator-gate/native-aio-tmp || exit 1
for round in 1 2 3; do
    (cd /tmp/linuxulator-gate/native-aio-tmp && timeout 30 /root/aio_compat_native)
    result=$?
    echo "GATE_NATIVE_AIO tmpfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
umount /tmp/linuxulator-gate/native-aio-tmp || exit 1
for round in 1 2 3; do
    timeout 30 /root/linux_aio_cancel
    result=$?
    echo "GATE_AIO_CANCEL zfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
mkdir -p /tmp/linuxulator-gate/aio-cancel-tmp
mount -t tmpfs tmpfs /tmp/linuxulator-gate/aio-cancel-tmp || exit 1
for round in 1 2 3; do
    (cd /tmp/linuxulator-gate/aio-cancel-tmp && timeout 30 /root/linux_aio_cancel)
    result=$?
    echo "GATE_AIO_CANCEL tmpfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
umount /tmp/linuxulator-gate/aio-cancel-tmp || exit 1
for round in 1 2 3; do
    timeout 60 /root/linux_aio_poll
    result=$?
    echo "GATE_AIO_POLL zfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
mkdir -p /tmp/linuxulator-gate/aio-poll-tmp
mount -t tmpfs tmpfs /tmp/linuxulator-gate/aio-poll-tmp || exit 1
for round in 1 2 3; do
    (cd /tmp/linuxulator-gate/aio-poll-tmp && timeout 60 /root/linux_aio_poll)
    result=$?
    echo "GATE_AIO_POLL tmpfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
umount /tmp/linuxulator-gate/aio-poll-tmp || exit 1
for round in 1 2 3; do
    timeout 15 /root/linux_aio_signal
    result=$?
    echo "GATE_AIO_SIGNAL zfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
mkdir -p /tmp/linuxulator-gate/aio-signal-tmp
mount -t tmpfs tmpfs /tmp/linuxulator-gate/aio-signal-tmp || exit 1
for round in 1 2 3; do
    (cd /tmp/linuxulator-gate/aio-signal-tmp && timeout 15 /root/linux_aio_signal)
    result=$?
    echo "GATE_AIO_SIGNAL tmpfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
umount /tmp/linuxulator-gate/aio-signal-tmp || exit 1
for round in 1 2 3; do
    timeout 60 /root/linux_aio_timeout
    result=$?
    echo "GATE_AIO_TIMEOUT zfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
mkdir -p /tmp/linuxulator-gate/aio-timeout-tmp
mount -t tmpfs tmpfs /tmp/linuxulator-gate/aio-timeout-tmp || exit 1
for round in 1 2 3; do
    (cd /tmp/linuxulator-gate/aio-timeout-tmp && timeout 60 /root/linux_aio_timeout)
    result=$?
    echo "GATE_AIO_TIMEOUT tmpfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
umount /tmp/linuxulator-gate/aio-timeout-tmp || exit 1
for round in 1 2 3; do
    timeout 30 /root/linux_aio_counts
    result=$?
    echo "GATE_AIO_COUNTS zfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
mkdir -p /tmp/linuxulator-gate/aio-counts-tmp
mount -t tmpfs tmpfs /tmp/linuxulator-gate/aio-counts-tmp || exit 1
for round in 1 2 3; do
    (cd /tmp/linuxulator-gate/aio-counts-tmp && timeout 30 /root/linux_aio_counts)
    result=$?
    echo "GATE_AIO_COUNTS tmpfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
umount /tmp/linuxulator-gate/aio-counts-tmp || exit 1
for round in 1 2 3; do
    timeout 30 /root/linux_aio_nosignal
    result=$?
    echo "GATE_AIO_NOSIGNAL zfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
mkdir -p /tmp/linuxulator-gate/aio-nosignal-tmp
mount -t tmpfs tmpfs /tmp/linuxulator-gate/aio-nosignal-tmp || exit 1
for round in 1 2 3; do
    (cd /tmp/linuxulator-gate/aio-nosignal-tmp && timeout 30 /root/linux_aio_nosignal)
    result=$?
    echo "GATE_AIO_NOSIGNAL tmpfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
umount /tmp/linuxulator-gate/aio-nosignal-tmp || exit 1
for round in 1 2 3; do
    timeout 30 /root/linux_aio_flags
    result=$?
    echo "GATE_AIO_FLAGS zfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
mkdir -p /tmp/linuxulator-gate/aio-flags-tmp
mount -t tmpfs tmpfs /tmp/linuxulator-gate/aio-flags-tmp || exit 1
for round in 1 2 3; do
    (cd /tmp/linuxulator-gate/aio-flags-tmp && timeout 30 /root/linux_aio_flags)
    result=$?
    echo "GATE_AIO_FLAGS tmpfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
umount /tmp/linuxulator-gate/aio-flags-tmp || exit 1
for round in 1 2 3; do
    timeout 120 /root/linux_aio_capacity
    result=$?
    echo "GATE_AIO_CAPACITY zfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
mkdir -p /tmp/linuxulator-gate/aio-capacity-tmp
mount -t tmpfs tmpfs /tmp/linuxulator-gate/aio-capacity-tmp || exit 1
for round in 1 2 3; do
    (cd /tmp/linuxulator-gate/aio-capacity-tmp && timeout 120 /root/linux_aio_capacity)
    result=$?
    echo "GATE_AIO_CAPACITY tmpfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
umount /tmp/linuxulator-gate/aio-capacity-tmp || exit 1
for round in 1 2 3; do
    timeout 30 /root/linux_aio_context
    result=$?
    echo "GATE_AIO_CONTEXT $round $result"
    [ "$result" -eq 0 ] || exit 1
done
for round in 1 2 3; do
    timeout 30 /root/linux_aio_rw
    result=$?
    echo "GATE_AIO_RW zfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
mkdir -p /tmp/linuxulator-gate/aio-rw-tmp
mount -t tmpfs tmpfs /tmp/linuxulator-gate/aio-rw-tmp || exit 1
for round in 1 2 3; do
    (cd /tmp/linuxulator-gate/aio-rw-tmp && timeout 30 /root/linux_aio_rw)
    result=$?
    echo "GATE_AIO_RW tmpfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
umount /tmp/linuxulator-gate/aio-rw-tmp || exit 1
for round in 1 2 3; do
    timeout 30 /root/linux_aio_full
    result=$?
    echo "GATE_AIO_FULL zfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
mkdir -p /tmp/linuxulator-gate/aio-full-tmp
mount -t tmpfs tmpfs /tmp/linuxulator-gate/aio-full-tmp || exit 1
for round in 1 2 3; do
    (cd /tmp/linuxulator-gate/aio-full-tmp && timeout 30 /root/linux_aio_full)
    result=$?
    echo "GATE_AIO_FULL tmpfs $round $result"
    [ "$result" -eq 0 ] || exit 1
done
umount /tmp/linuxulator-gate/aio-full-tmp || exit 1
fi
/root/linux_abi_gate -l >cases.txt || exit 1
[ "$(wc -l <cases.txt | tr -d ' ')" -eq 16 ] || exit 1
passed=0
failed=0
for round in 1 2 3; do
    while read -r name; do
        dir="round$round-$name"
        mkdir "$dir" || exit 1
        (cd "$dir" && timeout 20 /root/linux_abi_gate "$name")
        result=$?
        echo "GATE_CASE $round $name $result"
        if [ "$result" -eq 0 ]; then passed=$((passed+1)); else failed=$((failed+1)); fi
    done <cases.txt
done
echo "GATE_TOTAL passed=$passed failed=$failed"
if [ "$(uname -m)" = amd64 ]; then
    for name in linux_fileflags linux_fileattr linux_fchroot linux_machdep2 linux_openat2; do
        mkdir "$name" || exit 1
        (cd "$name" && timeout 30 /root/$name)
        echo "GATE_REGRESSION $name $?"
    done
fi
# Exercise both ABI entry paths on each filesystem that advertises OFD locks.
mkdir -p /tmp/ofd-tmpfs
mount -t tmpfs tmpfs /tmp/ofd-tmpfs || exit 1
for fs in zfs tmpfs; do
    if [ "$fs" = zfs ]; then base=/tmp/linuxulator-gate; else base=/tmp/ofd-tmpfs; fi
    for abi in native linux; do
        /root/ofd_$abi -l >ofd-cases.txt || exit 1
        [ "$(wc -l <ofd-cases.txt | tr -d ' ')" -eq 15 ] || exit 1
        for round in 1 2 3; do
            while read -r name; do
                dir="$base/ofd-$abi-$round-$name"
                mkdir "$dir" || exit 1
                (cd "$dir" && timeout 20 /root/ofd_$abi "$name")
                echo "GATE_OFD $fs $abi $round $name $?"
            done <ofd-cases.txt
        done
    done
    for round in 1 2 3; do
        dir="$base/rwf-direct-$round"
        mkdir "$dir" || exit 1
        (cd "$dir" && timeout 30 /root/linux_rwf)
        echo "GATE_RWF_DIRECT $fs $round $?"
    done
    for round in 1 2 3; do
        dir="$base/ofd-native-extra-$round"
        mkdir "$dir" || exit 1
        (cd "$dir" && timeout 20 /root/ofd_native_extra)
        echo "GATE_OFD_EXTRA $fs $round $?"
    done
done
umount /tmp/ofd-tmpfs || exit 1
for abi in native linux; do
    /root/seal_$abi -l >seal-cases.txt || exit 1
    if [ "$abi" = native ]; then count=7; else count=6; fi
    [ "$(wc -l <seal-cases.txt | tr -d ' ')" -eq "$count" ] || exit 1
    for round in 1 2 3; do
        while read -r name; do
            dir="seal-$abi-$round-$name"
            mkdir "$dir" || exit 1
            (cd "$dir" && timeout 20 /root/seal_$abi "$name")
            echo "GATE_SEAL $abi $round $name $?"
        done <seal-cases.txt
    done
done
# proc object links and descriptor handoffs are part of the lookup contract.
mkdir -p /proc /dev/fd || exit 1
kldstat -q -n linprocfs.ko || kldload /boot/kernel/linprocfs.ko || exit 1
kldstat -q -n fdescfs.ko || kldload /boot/kernel/fdescfs.ko || exit 1
mount -t linprocfs linprocfs /proc || exit 1
# Verify Linux swap priorities and native allocation order using two
# disposable disks.  The md device reserves swap blocks without memory pressure.
run_swap_priority()
(
    cd "$1" || exit 1
    timeout 30 /root/linux_swapon_priority || exit 1
    low_before=$(swapinfo -k | awk '$1 == "/dev/vtbd1" { print $3 }')
    high_before=$(swapinfo -k | awk '$1 == "/dev/vtbd2" { print $3 }')
    [ "$low_before" = 0 ] && [ "$high_before" = 0 ] || exit 1
    unit=$(mdconfig -a -t swap -s 4m -o reserve) || exit 1
    low_used=$(swapinfo -k | awk '$1 == "/dev/vtbd1" { print $3 }')
    high_used=$(swapinfo -k | awk '$1 == "/dev/vtbd2" { print $3 }')
    [ "$low_used" = 0 ] && [ "${high_used:-0}" -ge 4096 ] || exit 1
    mdconfig -d -u "$unit" || exit 1
    timeout 30 /root/linux_swapon_priority_cleanup || exit 1
    # Native default devices keep their original equal-priority round robin.
    swapctl -a /dev/vtbd1 /dev/vtbd2 || exit 1
    unit1=$(mdconfig -a -t swap -s 4m -o reserve) || exit 1
    unit2=$(mdconfig -a -t swap -s 4m -o reserve) || exit 1
    native_low=$(swapinfo -k | awk '$1 == "/dev/vtbd1" { print $3 }')
    native_high=$(swapinfo -k | awk '$1 == "/dev/vtbd2" { print $3 }')
    [ "${native_low:-0}" -ge 4096 ] && [ "${native_high:-0}" -ge 4096 ] || exit 1
    mdconfig -d -u "$unit1" || exit 1
    mdconfig -d -u "$unit2" || exit 1
    swapctl -d /dev/vtbd1 /dev/vtbd2 || exit 1
    if swapinfo -k | awk '$1 == "/dev/vtbd1" || $1 == "/dev/vtbd2" { found=1 } END { exit !found }'; then
        exit 1
    fi
)
if [ "$(uname -m)" = amd64 ]; then
    sha256 /root/linux_swapon_priority /root/linux_swapon_priority_cleanup
    for round in 1 2 3; do
        run_swap_priority /tmp/linuxulator-gate
        result=$?
        echo "GATE_SWAP_PRIORITY zfs $round $result"
        [ "$result" -eq 0 ] || exit 1
    done
    mkdir -p /tmp/linuxulator-gate/swap-priority-tmp
    mount -t tmpfs tmpfs /tmp/linuxulator-gate/swap-priority-tmp || exit 1
    for round in 1 2 3; do
        run_swap_priority /tmp/linuxulator-gate/swap-priority-tmp
        result=$?
        echo "GATE_SWAP_PRIORITY tmpfs $round $result"
        [ "$result" -eq 0 ] || exit 1
    done
    umount /tmp/linuxulator-gate/swap-priority-tmp || exit 1
fi
# Verify Linux discard policies on the disposable trim-capable third disk.
run_swap_discard()
(
    cd "$1" || exit 1
    once_before=$(sysctl -n vm.stats.swap.discard_once) || exit 1
    pages_before=$(sysctl -n vm.stats.swap.discard_pages) || exit 1
    errors_before=$(sysctl -n vm.stats.swap.discard_errors) || exit 1
    timeout 60 /root/linux_swapon_discard || exit 1
    once_after=$(sysctl -n vm.stats.swap.discard_once) || exit 1
    pages_after=$(sysctl -n vm.stats.swap.discard_pages) || exit 1
    errors_after=$(sysctl -n vm.stats.swap.discard_errors) || exit 1
    [ "$((once_after - once_before))" -ge 3 ] || exit 1
    [ "$pages_after" -eq "$pages_before" ] || exit 1
    [ "$errors_after" -eq "$errors_before" ] || exit 1
    timeout 30 /root/linux_swapon_discard_pages || exit 1
    unit=$(mdconfig -a -t swap -s 4m -o reserve) || exit 1
    mdconfig -d -u "$unit" || exit 1
    swapctl -d /dev/vtbd2 || exit 1
    pages_final=$(sysctl -n vm.stats.swap.discard_pages) || exit 1
    errors_final=$(sysctl -n vm.stats.swap.discard_errors) || exit 1
    [ "$pages_final" -gt "$pages_after" ] || exit 1
    [ "$errors_final" -eq "$errors_before" ] || exit 1
)
if [ "$(uname -m)" = amd64 ]; then
    sha256 /root/linux_swapon_discard /root/linux_swapon_discard_pages
    for round in 1 2 3; do
        run_swap_discard /tmp/linuxulator-gate
        result=$?
        echo "GATE_SWAP_DISCARD zfs $round $result"
        [ "$result" -eq 0 ] || exit 1
    done
    mkdir -p /tmp/linuxulator-gate/swap-discard-tmp
    mount -t tmpfs tmpfs /tmp/linuxulator-gate/swap-discard-tmp || exit 1
    for round in 1 2 3; do
        run_swap_discard /tmp/linuxulator-gate/swap-discard-tmp
        result=$?
        echo "GATE_SWAP_DISCARD tmpfs $round $result"
        [ "$result" -eq 0 ] || exit 1
    done
    umount /tmp/linuxulator-gate/swap-discard-tmp || exit 1
fi
mount -t fdescfs -o linrdlnk fdescfs /dev/fd || exit 1
mkdir -p /tmp/resolve-linprocfs /tmp/resolve-fd-plain /tmp/resolve-fd-rdlnk /tmp/resolve-fd-nodup || exit 1
mount -t linprocfs linprocfs /tmp/resolve-linprocfs || exit 1
mount -t fdescfs fdescfs /tmp/resolve-fd-plain || exit 1
mount -t fdescfs -o rdlnk fdescfs /tmp/resolve-fd-rdlnk || exit 1
mount -t fdescfs -o nodup fdescfs /tmp/resolve-fd-nodup || exit 1
kldstat -q -n nullfs.ko || kldload /boot/kernel/nullfs.ko || exit 1
mkdir -p /tmp/xdev-base/mnt /tmp/xdev-base/source /tmp/xdev-base/bind || exit 1
mount -t tmpfs tmpfs /tmp/xdev-base/mnt || exit 1
mkdir -p /tmp/xdev-base/mnt/sub /tmp/xdev-base/mnt/nested || exit 1
mount -t tmpfs tmpfs /tmp/xdev-base/mnt/nested || exit 1
printf safe >/tmp/xdev-base/file
printf safe >/tmp/xdev-base/source/file
printf safe >/tmp/xdev-base/mnt/file
printf safe >/tmp/xdev-base/mnt/nested/file
ln -s / /tmp/xdev-base/mnt/abs || exit 1
ln -s .. /tmp/xdev-base/mnt/up || exit 1
mount -t nullfs /tmp/xdev-base/source /tmp/xdev-base/bind || exit 1
kldstat -q -n autofs.ko || kldload /boot/kernel/autofs.ko || exit 1
mkdir -p /tmp/xdev-autofs /tmp/xdev-union || exit 1
mount -t autofs -o master_options=,master_prefix=/tmp/xdev-autofs autofs /tmp/xdev-autofs || exit 1
printf lower >/tmp/xdev-union/lower
mount -t tmpfs -o union tmpfs /tmp/xdev-union || exit 1
printf upper >/tmp/xdev-union/upper
# ZFS dataset boundaries and snapshot clones are required base-system cases.
mkdir /tmp/resolve-zfs || exit 1
zfs create -o mountpoint=/tmp/resolve-zfs/child linuxgate/resolve-child || exit 1
printf safe >/tmp/resolve-zfs/child/file
zfs snapshot linuxgate/resolve-child@gate || exit 1
zfs clone -o mountpoint=/tmp/resolve-zfs/clone linuxgate/resolve-child@gate linuxgate/resolve-clone || exit 1
zfs clone -o readonly=on -o mountpoint=/tmp/resolve-zfs/readonly linuxgate/resolve-child@gate linuxgate/resolve-readonly || exit 1
/root/linux_resolve -l >resolve-cases.txt || exit 1
[ "$(wc -l <resolve-cases.txt | tr -d ' ')" -eq 24 ] || exit 1
mkdir -p /tmp/resolve-tmpfs || exit 1
mount -t tmpfs tmpfs /tmp/resolve-tmpfs || exit 1
for fs in zfs tmpfs; do
    if [ "$fs" = zfs ]; then base=/tmp/linuxulator-gate; else base=/tmp/resolve-tmpfs; fi
    for round in 1 2 3; do
        while read -r name; do
            dir="$base/resolve-$round-$name"
            mkdir "$dir" || exit 1
            resolve_timeout=60
            # This case does 1000 ZFS namespace mutations and 4000 guarded
            # lookups; allow a bounded margin for heavily loaded TCG hosts.
            if [ "$fs" = zfs ] && [ "$name" = race ]; then
                resolve_timeout=180
            fi
            (cd "$dir" && timeout "$resolve_timeout" /root/linux_resolve "$name")
            echo "GATE_RESOLVE $fs $round $name $?"
        done <resolve-cases.txt
    done
done
# ZFS intentionally rejects reservation allocation. Exercise successful
# allocation and hole punching on tmpfs while the supported base stays on ZFS.
if [ "$(uname -m)" = amd64 ]; then
    mkdir /tmp/resolve-tmpfs/linux-fallocate-direct || exit 1
    (cd /tmp/resolve-tmpfs/linux-fallocate-direct &&
        timeout 60 /root/linux_fallocate)
    echo "GATE_REGRESSION linux_fallocate $?"
fi
zfs destroy linuxgate/resolve-readonly || exit 1
zfs destroy linuxgate/resolve-clone || exit 1
zfs destroy linuxgate/resolve-child@gate || exit 1
zfs destroy linuxgate/resolve-child || exit 1
umount /tmp/xdev-autofs || exit 1
umount /tmp/xdev-union || exit 1
umount /tmp/xdev-base/bind || exit 1
umount /tmp/xdev-base/mnt/nested || exit 1
umount /tmp/xdev-base/mnt || exit 1
umount /tmp/resolve-tmpfs || exit 1
umount /tmp/resolve-fd-nodup || exit 1
umount /tmp/resolve-fd-rdlnk || exit 1
umount /tmp/resolve-fd-plain || exit 1
umount /tmp/resolve-linprocfs || exit 1
umount /dev/fd || exit 1
umount /proc || exit 1
dmesg | tail -30
zpool sync linuxgate || exit 1
zpool status -x >pool-health.txt || exit 1
read -r health <pool-health.txt
[ "$health" = "all pools are healthy" ] || { cat pool-health.txt; exit 1; }
echo GATE_POOL_HEALTHY
echo LINUXULATOR_GATE_DONE
/sbin/halt -p
