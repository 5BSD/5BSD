# Compare identical four-vCPU guests with nested SVM hidden/exposed.
phase_begin boot-smp
need_root
need_generation
need_vmm
need_image
[ "$(host_vendor)" = amd ] || refuse "boot-smp currently requires AMD"
nested_gate amd >/dev/null || refuse "nested SVM host gate unavailable"
need_mem_mb 6144
need_disk_mb 12288
dry && dry_end
phase_workdir
HT_BOOT_TIMEOUT=60
for mode in off on; do
    vm=ht-smp-$mode
    opts=""
    [ "$mode" = off ] || opts="-o x86.nested_svm=true"
    disk=$(vm_disk "$vm")
    l2disk=$(vm_disk "$vm-l2")
    log "four-vCPU boot, nesting $mode; $(sysctl -n vm.loadavg) host load"
    if vm_boot "$vm" "$disk" 4G 4 "hosttest.role=l1 hosttest.hostname=ht-smp" "$opts -s 4,virtio-blk,$l2disk"; then
        if vm_wait "$vm" HOSTTEST-GUEST-READY 60; then
            check "boot-$mode" PASS "four-vCPU guest ready"
        else
            check "boot-$mode" FAIL "$(vm_diag "$vm")"
        fi
    else
        check "boot-$mode" FAIL "bhyve launch failed: $(vm_diag "$vm")"
    fi
        # Capture every CPU before destruction, even after failed readiness.
        for cpu in 0 1 2 3; do
            timeout -k 1 3 bhyvectl --vm="$vm" --cpu="$cpu" \
                --get-rip --get-rflags --get-intinfo --get-stats \
                > "$HT_OUT/$vm.vcpu$cpu.txt" 2>&1
            capture_rc=$?
            echo "capture_rc=$capture_rc" >> "$HT_OUT/$vm.vcpu$cpu.txt"
        done
    vm_destroy "$vm"
done
phase_end
