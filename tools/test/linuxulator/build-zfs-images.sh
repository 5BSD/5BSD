#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Create private ZFS-root images without importing a pool into the host kernel.
set -eu
if [ "$#" -ne 3 ]; then
    echo "usage: $0 amd64-staged-root arm64-staged-root new-output-directory" >&2
    exit 64
fi
amdroot=$(realpath "$1")
armroot=$(realpath "$2")
mkdir "$3"
out=$(realpath "$3")
truncate -s 64m "$out/amd64-swap.img"
truncate -s 64m "$out/amd64-swap2.img"
for arch in amd64 arm64; do
    if [ "$arch" = amd64 ]; then root=$amdroot; else root=$armroot; fi
    test -f "$root/boot/kernel/zfs.ko"
    if [ -f "$root/boot/loader.conf.local" ]; then
        awk '/^init_rc=/ {if (seen && $0 != value) exit 1; seen=1; value=$0}' \
            "$root/boot/loader.conf" "$root/boot/loader.conf.local" || {
            echo "$arch: conflicting gate init_rc settings" >&2
            exit 1
        }
    fi
    # makefs consumes the manifest, not every staged file.  Fail early if a
    # mandatory gate payload (or the staged crash script) would be omitted.
    for payload in linuxulator-gate.sh squeue_options_native squeue_options_linux linux_rwf guest-rwf-durability.sh; do
        if [ "$payload" = guest-rwf-durability.sh ] && [ ! -f "$root/root/$payload" ]; then continue; fi
        test -f "$root/root/$payload"
        awk -v path="./root/$payload" '$1 == path {found=1} END {exit !found}' "$root/METALOG.minimal" || {
            echo "$arch: missing manifest entry for /root/$payload" >&2
            exit 1
        }
    done
    if [ "$arch" = amd64 ]; then
        for payload in ./bin/dd ./usr/bin/awk ./usr/sbin/swapinfo; do
            test -f "$root/${payload#./}" || exit 1
            awk -v path="$payload" '$1 == path {found=1} END {exit !found}' "$root/METALOG.minimal" || exit 1
        done
        for payload in guest-peer-events.sh linux_socket_peername linux_ptrace_events peer_caps peer_caps_probe ptrace_exit_native guest-xstate-mcast.sh linux_ptrace_xstate linux_mcast_filter mcast_native guest-cookie.sh linux_socket_cookie cookie_caps cookie_caps_probe linux_ptrace_seize linux_ptrace_interrupt linux_ptrace_listen linux_ptrace_lifecycle linux_ptrace_user linux_ptrace_metadata linux_ptrace_sigmask linux_proc_task linux_ptrace_kill_native guest-ptrace.sh linux_ptrace_registers ptrace_native ptrace_capmode ptrace_capmode_probe guest-quota.sh linux_quota quota_native quota_capmode quota_capmode_probe quota_capmode_path_probe unshare_capmode unshare_capmode_probe linux_unshare linux_iouring_sqpoll linux_sysfs64 linux_rseq linux_rseq_signal linux_rseq_threads linux_rseq_lifecycle linux_rseq_auxv linux_rseq_preempt linux_rseq_hold linux_perf_event perf_native_hold linux_remap_file_pages linux_ioperm linux_iopl_options linux_modify_ldt linux_swapoff linux_swapon_flags linux_swapon_priority linux_swapon_priority_cleanup linux_swapon_discard linux_swapon_discard_pages ioperm_native; do
            test -f "$root/root/$payload" || exit 1
            awk -v path="./root/$payload" '$1 == path {found=1} END {exit !found}' "$root/METALOG.minimal" || exit 1
            case "$payload" in guest-peer-events.sh|peer_caps|ptrace_exit_native|guest-xstate-mcast.sh|mcast_native|ioperm_native|unshare_capmode|quota_native|quota_capmode|guest-quota.sh|guest-ptrace.sh|ptrace_native|ptrace_capmode|linux_ptrace_kill_native|guest-cookie.sh|cookie_caps) continue;; esac
            case "$(brandelf -l "$root/root/$payload" 2>/dev/null)" in
                *"of brand 'Linux'"*) ;;
                *) echo "$arch: /root/$payload is not a Linux ELF" >&2; exit 1 ;;
            esac
        done
        for payload in aio_compat_native linux_aio_context linux_aio_rw linux_aio_full linux_aio_capacity linux_aio_flags linux_aio_cancel linux_aio_poll linux_aio_signal linux_aio_timeout linux_aio_counts linux_aio_nosignal; do
            test -f "$root/root/$payload"
            awk -v path="./root/$payload" '$1 == path {found=1} END {exit !found}' \
                "$root/METALOG.minimal" || {
                echo "$arch: missing manifest entry for /root/$payload" >&2
                exit 1
            }
            if [ "$payload" != aio_compat_native ]; then
                case "$(brandelf -l "$root/root/$payload" 2>/dev/null)" in
                    *"of brand 'Linux'"*) ;;
                    *) echo "$arch: /root/$payload is not a Linux ELF" >&2
                       exit 1 ;;
                esac
            fi
        done
    fi
    (cd "$root" && makefs -t zfs -s 4g \
        -o poolname=linuxgate -o bootfs=linuxgate -o rootpath=/ \
        "$out/rootfs-$arch.zfs" METALOG.minimal) >"$out/makefs-$arch.log" 2>&1
    if [ "$arch" = amd64 ]; then
        mkimg -s gpt -f raw -b "$root/boot/pmbr" \
            -p freebsd-boot:="$root/boot/gptzfsboot" \
            -p freebsd-zfs:="$out/rootfs-$arch.zfs" -o "$out/amd64.img"
    else
        mkdir -p "$out/esp/EFI/BOOT"
        cp "$root/boot/loader.efi" "$out/esp/EFI/BOOT/BOOTAA64.EFI"
        makefs -t msdos -s 64m -o fat_type=32,sectors_per_cluster=1 \
            "$out/esp.img" "$out/esp" >"$out/makefs-esp.log" 2>&1
        mkimg -s gpt -f raw -p efi:="$out/esp.img" \
            -p freebsd-zfs:="$out/rootfs-$arch.zfs" -o "$out/arm64.img"
    fi
done
