# 5BSD real-hardware host test kit

This kit tests a real host after an upgrade: the AMD host (Ryzen 7 255,
Family 0x19 Model 0x75, SVM with DecodeAssists) today, and an Intel host
later (vendor detection, VMX-aware nested gate, vendor-neutral save/restore).
Run it as root. It has six independent phases that run in any order. Each
phase runs a preflight first and writes its own results directory with logs
and a PASS/FAIL summary.

The kit is safe to rerun. It never edits `rc.conf`, `loader.conf`,
`otel.conf` or pf rules. It never loads or unloads kernel modules and never
installs packages. VM disks and checkpoints are private copies under
`/usr/obj`. The phases remove everything they create (the bridge, the taps,
VMs, checkpoints, the dtraced they started, OTel services, a podman
container) when they end, including on ^C. Logs and consoles stay in the
results directory.

Target generation: the newest published generation (gen4 at the time of
writing, with the forwarder bare-ELF fix, the vmm host-CPU-local CPUID
leaves, the named CPU-contract/migration-topology refusals, the image "/"
mode and nested SVM VMMCALL). The preflight refuses only
16.snap20261031171249 (`HT_BROKEN_GENERATIONS` in lib/common.sh). The guest
image must be rebuilt for each generation and whenever the kit's guest files
change (step 0): `need_image` refuses an image whose generation differs from
the host's, or whose `kit_overlay_sha256` differs from the kit's guest files.

## Run order (after the upgrade)

```sh
K=/usr/obj/5BSD-otel-validation/hosttest-kit

# 0. As your ordinary user (no root). About 3 minutes. refresh-tools first:
#    the image embeds guest-bin/ (vsock-pipe, srtool).
$K/images/refresh-tools.sh      # OTLP collector/validators + helpers from the new objtree
$K/images/build-guest.sh        # guest image from .../repo/FreeBSD:16:amd64/latest
$K/coverage/build-hwstat-cov.sh # coverage-instrumented hwstat from /usr/src + objtree
$K/hosttest.sh selftest         # unprivileged self-test of the kit logic (~4 min)
$K/hosttest.sh status           # dry run: lists what would still block each phase

# 1. As root. These need no vmm. About 6 minutes.
$K/hosttest.sh hwstat devices

# 2. As root. These need vmm (the new generation loads it by default).
#    About 80-120 minutes.
$K/hosttest.sh hypertrace snapshot saverestore devices-sr

# 3. As root. Nested virtualization. About 25-60 minutes. No reboot on AMD:
#    hw.vmm.svm.nested=1 is the default; each L1 guest opts in with
#    x86.nested_svm. On Intel the phase is SKIP while hw.vmm.vmx.nested=0.
$K/hosttest.sh nested
```

Guest images boot the default 5BSD policy (capability plane ON; before
htcap the overlay set `capability_plane="NO"`, which hid plane problems).
`GUEST_CAPABILITY_PLANE=NO images/build-guest.sh` builds a plane-free image
for comparison; `guest.manifest` records `capability_plane=`. Guest boots wait
up to `HT_BOOT_TIMEOUT` seconds (default 600).

The nested phase refuses on AMD when `hw.vmm.svm.nested` is 0. That happens on a
generation built before the default changed, or when loader.conf sets
`hw.vmm.svm.nested=0`. On such a generation, enable it for one boot with
`nextboot -e hw.vmm.svm.nested=1 && shutdown -r now` (or `set
hw.vmm.svm.nested=1` and `boot` at the loader prompt), then rerun the phase.
On Intel, nested VMX is behind the boot-time tunable `hw.vmm.vmx.nested`
(0 by default while live Intel qualification is in progress); with it off
every nested check is SKIP with that reason, with it on the same checks run
against VMX (`-o x86.nested_vmx=true`).

`hosttest.sh all` runs hwstat, hypertrace, snapshot, saverestore, devices-sr, devices and
nested in that order. nested is last. If the
first commands are run before the upgrade, the hwstat and devices phases
still work: they skip the generation check when it is the only blocker.

### Expected runtime (idle host; the build load makes everything slower)

Each phase prints its estimate in phase.log; RUNINFO lists them for the run.

| phase | time | notes |
|---|---|---|
| hwstat | 2-4 min | includes a 5 s all-core busy loop and the coverage run |
| devices | 1-2 min | 30 s of OTel service collection; 1 s audible tone |
| hypertrace | 8-12 min | 2 guests (1 GiB each), 7 dtrace -E sessions of 45-50 s |
| snapshot | 16-32 min | 6 guest boots, 2 suspend/restore, a 150 s session across a suspend, 4 migrations |
| saverestore | 18-35 min | 2 guests, 7 restores, 3 cycles, 7 refused restores, disk copies |
| devices-sr | 28-48 min | 7 device-group guests + 1 UEFI guest (1 GiB each), one running checkpoint + suspend/restore each, ~3 min of watchdog/RTC waits, 1 UEFI migration |
| nested | 25-60 min | L1 4 GiB/4 vCPU; 6 L2 runs under nested paging (slow boots), L1 suspend/restore with L2 running |

Resources: about 6 GiB of free memory for nested, 4 GiB for snapshot and
3 GiB for saverestore, checked in the preflight and again before every VM
start or restore (`vm_mem_guard`: the guest's memory plus
`HT_MEM_MARGIN_MB`, default 1024). Each VM gets a copy of the 4 GiB image
under `/usr/obj/5BSD-otel-validation/hosttest-work`; saverestore keeps two
more (the disk at the suspend, and one for the refused restores). The copies
and checkpoints are deleted at the end of the phase; set `HT_KEEP_WORK=yes`
to keep them.

Tunables: `HT_SR_MB` (256, memory/file pattern size), `HT_SR_CYCLES` (3),
`HT_DIRTY_MB` (256, migration dirtying load), `HT_L2_TIMEOUT` (600 s per L2
run inside L1; the host console limit is 360 s longer), `HT_L2_REPEAT` (3),
`HT_L2_WORK_MB` (256 per L2 vCPU), `HT_L2_HOLD` (300 s, L2 ticking while L1
is checkpointed), `HT_L1TRACE_SECS` (120).

## How to read the results

```
/usr/obj/5BSD-otel-validation/hosttest-results/run-<UTC>/
  RUNINFO              kernel, generation, kit checksum, host capability report
                       (vendor, model, SVM/VMX features, hw.vmm.* nested policy,
                       kernel ident/sha), expected minutes per phase
  SUMMARY              one line per phase: PASS|FAIL|SKIP|REFUSED|ERROR pass= fail= skip= seconds=
  <phase>/RESULT       same line for the phase
  <phase>/checks.tsv   name<TAB>PASS|FAIL|SKIP|INFO|REFUSED<TAB>detail  (one line per check)
  <phase>/phase.log    timestamped narrative
  <phase>/identity.txt generation, kernel sha256 vs publication.json
  <phase>/*.console    guest serial consoles; *.bhyve.log bhyve stderr
  <phase>/...          raw evidence per check (JSON, OTLP payloads, dtrace output)
```

- `REFUSED` means a preflight stopped the phase before it changed anything.
  The detail says what to do next.
- `SKIP` means the item cannot be tested on this setup, and the detail says
  why (for example: no dock, or the FreeBSD CNI build).
- `INFO` records evidence that has no pass criterion.
- At the end, `hosttest.sh` prints every FAIL or REFUSED check. The exit
  status is 0 only if no phase failed.

## What each phase checks

### hwstat (phase 1)

Preflight: root, `cpuctl` loaded with `/dev/cpuctl0`, `cpucontrol`, and the
kit's OTLP tools present.

- CPUID family through cpuctl is 0x17, 0x19 or 0x1a (the families hwstat
  supports for AMD RAPL).
- `hwstat list --format json`: `rapl_available:true` and a package domain.
- Independent cross-check: the raw MSRs 0xC0010299 (energy unit) and
  0xC001029B (package energy) are read with `cpucontrol`, 2 s apart. The
  energy must advance, and `hwstat watch` package watts must agree with the
  raw value within a factor of 3.
- `watch --format json`: package watts in the range 0.5-200 W; amdtemp
  temperature in the range 15-110 C; ACPI tz0 if present; CPU frequency; GPU
  metric sources (recorded as INFO).
- `--per-core`: all 16 logical CPUs are reported with usage. hwstat reads
  only package energy, not the AMD per-core energy MSR 0xC001029A.
- `hwstat exec`: energy of a known workload (every thread busy for 5 s)
  compared with 5 s of `sleep`. The workload must use more joules. Also
  checked: exit-code propagation and the text summary.
- OTLP: `watch --format otel --per-core` goes to the loopback `otlp_collector`
  over http/json. The payloads must pass `otlp_validate`. `otlp_json_validate`
  must find `hwstat.power.package_milliwatts` (above 500 mW),
  `hwstat.thermal.temperature_millicelsius`, `hwstat.cpu.freq_mhz` and
  `hwstat.system.cpu_busy_basis_points`. The file target
  (`export { target = "file"; }`, through `OTELCONF_FILE`) must produce a
  valid `hwstat.jsonl`.
- Coverage: the instrumented hwstat runs the 5 atf-c unit programs, the
  atf-sh CLI suite and the real-hardware invocations as root. The results are
  merged with llvm-profdata, then llvm-cov produces `coverage/report-hwstat.txt`
  (combined) and `coverage/report-hwstat-hw-only.txt` (hardware runs only).
  The check passes when rapl.c line coverage from the hardware runs alone is
  above 50%. The recorded baseline was 78.85% lines / 65.60% branches. An
  unprivileged dry run of the same script already gave 83.67% / 68.27%, but
  rapl.c's hardware path was 0%.

### hypertrace (phase 2)

Preflight: root, generation, vmm with `/dev/vmmctl` (VMs appear under `/dev/vmm/` once created), dtrace and hypertrace
modules with `/dev/dtrace/hypertrace`, `dtracedctl`, a guest image whose
generation equals the host generation (matched builds), memory and disk.

The phase starts a host `dtraced -O` unless one is already running; it
refuses if the running one is a minion. It creates `/var/ddtrace{,/inbound}`
only if they are missing, and removes them afterwards. It boots `ht-trace1`
and `ht-trace2` with `-o enable_hypertrace=true -s 7,virtio-dtrace`, and the
guest dtraced runs as a minion.

- Guest `/dev/dttransport` and the guest minion are present.
- Each VM registers both forwarder channels (rx and wx):
  `dtracedctl --show-stats=<vm>` reports `forwarder channels: 2` or more.
  (The output never names the VM; the --show-stats=<vm> argument selects it.)
- `dtrace -E` with guest syscall probes aggregates by `vmname, execname`.
- Two `-n` programs in one `-E` session both report (the "-E sends all"
  fix).
- A program aimed at `ht-trace1` sees only ht-trace1. The glob `ht-trace*`
  sees both guests.
- Exact drain: a bounded workload's exec count in the guest equals the host
  count, and no drops are reported.
- A new session with a predicate that also matches the previous session's
  tag shows no old aggregates.
- `-x otel=otlp` (http/json to the loopback collector): the payloads pass
  `otlp_validate`. There is one resource per guest
  (`hypertrace.vm.name`/`id`/`epoch`) plus `hypertrace.host.name`, and a
  `hypertrace.vm.registered` log event.

No existing HyperTrace suite needs a real vmm (all of
contrib/hypertrace/tests are rootless component fixtures). This phase covers
the live part of README.5BSD's acceptance step 1. Steps 2-4 are in the
snapshot phase.

### nested (phase 3)

Preflight: as for hypertrace, plus the vendor's nested gate (`nested_gate`):
AMD needs `hw.vmm.svm.nested=1` (the default) and host DecodeAssists; Intel
needs `hw.vmm.vmx.nested=1` (off by default, so on Intel today every check
below is SKIP with that reason and the phase does not fail). The guest image
must come from the host's generation: the L1 loads its own vmm.ko. L1 gets
`-o x86.nested_svm=true` (Intel: `x86.nested_vmx=true`), 4 vCPU, 4 GiB.
Every L2 run is bounded inside L1 by l2-boot.sh itself, not timeout(1)
(bhyve maps SIGTERM to the ACPI power button and a process blocked in the
kernel ignores signals; gen4 never returned): destroy 20 s, bhyveload 120 s,
bhyve `HT_L2_TIMEOUT`, then diagnostics and the report. The host console
limit is `HT_L2_TIMEOUT` + 360 s and l2-boot.sh gets `L2_BUDGET` = console
limit - 30 s, lowering its bhyve limit if the stages would not fit
(`l2-boot.sh --limits`). A stage that overruns prints L1 diagnostics
(`== L2-DIAG`: procstat -kk of bhyve/bhyveload/dtraced, top -H, ps -auxww,
dmesg tail, vmm/dtrace state) before it is killed; the L2 console and bhyve
stderr are copied live to L1's /dev/console as `[L2]` / `[L2-bhyve]` lines,
so `ht-l1.console` has them even if a run never returns, and a console
command that times out keeps the output it printed.

- `atf-nested`: if `/usr/tests/sys/vmm/run-svm-nested-atf.sh` is installed,
  the root-only nested ATF cases (including `svm_l2_checkpoint`) run first,
  while no VMs are running, in a root-owned 0700 `/var/run/ht-atf.*` WORKDIR
  (the runner refuses ancestors it does not trust; the old work dir under
  `/usr/obj` never qualified). Otherwise SKIP, with the install command:
  `pkg install -r 5BSD-base 5BSD-waspnest-tests`.
- `svm-hidden-without-gate` (Intel: `vmx-hidden-without-gate`): a guest
  without the option must not see SVM/VMX in CPUID.
- `l1-boot`, `l1-sees-svm`/`l1-sees-vmx`, `l1-vmm-loaded`.
- `l2-boots-to-marker`, `l2-cpu-reported`: L2 boots from the second disk
  through bhyveload/bhyve with a nmdm console and prints
  `HOSTTEST-L2-MARKER <id> model=... ncpu=1`.
- `hypertrace-probes-from-l1` (host hypertrace loaded): during that L2 run, a
  120 s `dtrace -E` session counts L1's `bhyve` ioctl syscalls and the
  bhyve/bhyveload execs; the detail carries the delivery counters.
- `l2-2vcpu-boots`, `l2-2vcpu-checksum`: L2 with 2 vCPUs runs one CPU-bound
  worker pinned to each vCPU (`srtool work 256 1000+cpu` under `cpuset -l`);
  L1 recomputes each SHA-256 natively and requires the digest and the CPU
  each worker finished on.
- `l2-network-from-l1`: L1 creates a tap (10.231.78.1/24), L2 comes up at .2
  and holds for 30 s; L1 must ping it without loss.
- `l2-repeat-1..3`, `l1-clean-after-l2-runs`: L2 started and stopped three
  more times; afterwards L1's new kernel messages contain no
  vmm/svm/vmx/error/panic/fault/lock-order lines and `/dev/vmm` is empty.
- Active L2 across L1 save/restore (`svm_snapshot_nested_save` records the
  nested state, including an active L2's VMCB12; EBUSY while a nested
  instruction is pending is retried twice):
  `l1-checkpoint-active-l2` (nonterminal checkpoint published; a clean
  refusal is FAIL with bhyvectl's message, a dead L1 says so),
  `l2-runs-after-l1-checkpoint` (L2's tick advances), `l1-suspend-active-l2`,
  `l1-restore-active-l2` (FAIL detail = bhyve's refusal line),
  `l2-continues-after-l1-restore` (ticks continue from where they were),
  `l2-completes-after-l1-restore` (L2 finishes its hold and powers off).

### snapshot (phase 4)

Preflight: root, generation, vmm, `options BHYVE_SNAPSHOT`, snapshot-capable
bhyve, migration-capable bhyvectl, openssl, timeout, memory and disk.

The phase creates a private `bridge`+`tap` with the host at 10.231.77.1/24
and the guest at .2. Cleanup attempts to remove both at the end. Before
creation, the phase refuses an existing interface address in that /24 and
saves interfaces/routes. This is not an atomic reservation for concurrent runs.
PF is not changed; a ping failure alone does not identify its cause.

Before and after the initial and restored pings, `net-before-{pre,post}.*`
and `net-restored-{pre,post}.*` capture all interfaces, IPv4 routes, the route
to the guest, ARP entries, interface byte/packet counters, bridge forwarding
entries, tap state and bridge filtering sysctls. Each host query records its
command, UTC start/end and exit status, preserving errors and partial output;
queries use a 5-second timeout with a 1-second kill grace. Four captures can
add about 192 seconds when every query times out. Kernel-uninterruptible
operations cannot be guaranteed to stop by a userspace timeout.
`a-start.txt` and `a-after-restore.txt` retain guest interfaces/routes/ARP/
counters and full ping output. Guest queries share the existing 30/40-second
serial wait budget; a serial timeout does not cancel a stuck guest command.
Only a complete positive-packet, zero-loss ping summary passes networking.
Diagnostic query success alone never passes it. No packet capture is added.

`phase.log` now timestamps console-detach entry/exit and bhyvectl-destroy
entry/exit (including return status and stderr) during VM destruction. A
missing completion marker identifies the last entered stage; it does not
prove the kernel cause. Lifecycle and force-kill policy are unchanged.

The focused unprivileged regression can also be run separately:
`sh "$K/lib/network-selftest.sh" /usr/obj/5BSD-otel-validation/hosttest-results/network-diag-local`.
It is included in `hosttest.sh selftest`.

- **Checkpoint**: `bhyvectl --checkpoint` publishes a
  `BHYVE-CHECKPOINT-MANIFEST-3`, and the guest counter keeps running.
- **Suspend/restore**: `bhyvectl --suspend` must exit 0, bhyve must exit
  with status 5 (BHYVE_EXIT_SUSPEND) and the checkpoint manifest must be
  published. If only bhyvectl failed ("nvlist_xfer() failed: Socket is not
  connected"), the detail says the suspend itself worked. The guests boot
  through bhyveload, so `vm_restore` creates the empty VM with
  `bhyvectl --create --vm=NAME` before `bhyve -r` with the identical devices.
  The counter process is alive, its value is at least the pre-suspend value
  and still increasing, and the guest can still ping the host bridge. A
  refused restore puts bhyve's own line in the FAIL detail, e.g.
  `Checkpoint CPU contract differs at CPUID 0x80000026.0 edx: source ...,
  destination ...` (gen3 said only "restored bhyve did not start").
- **HyperTrace fresh-session contract**: a guest with virtio-dtrace runs
  session `htpre` (`ht-pre-delivery`: outbound and installed deliveries above
  0), then a second session `htlive` is still running when the coordinated
  `--suspend` is sent (`ht-session-active-at-suspend`; how that consumer
  ended is `ht-live-session-outcome` INFO), then a restore. The restored
  guest re-registers with dtraced (`ht-restore-reconnect`). A newly submitted
  program sees only `htpost` events, with deliveries above 0
  (`ht-post-delivery`). The OTel resource epoch must differ from the one
  before the checkpoint, and a `hypertrace.vm.restarted` event must be
  exported. If the guest never registers, the rest is SKIP instead of a
  10-minute suspend timeout.
- **Migration, plaintext_unix**: `bhyve -R 3 -o migrate.plaintext_unix=true`
  and `bhyvectl --migrate-fd=3 --migrate-plaintext-unix` run over one
  AF_UNIX socketpair (`bin/ht-sockpair`). The destination VM is created
  first with `bhyvectl --create`. bhyvectl must report completion, the
  source must retire, and the counter must continue on the destination. A
  failed handoff carries the destination's
  `Inbound migration topology refused (reason N): device ...` line.
- **Migration under memory dirtying** (`mig-dirty-*`,
  `mig-dirty-memory-intact`): the guest rewrites `HT_DIRTY_MB` (256) MiB
  continuously (`srtool dirty`: each word must still hold the previous
  pass's value before it is rewritten, so a dirty page the migration lost is
  counted). After the handoff the pass counter keeps rising on the
  destination with 0 word errors.
- **Migration, mutual TLS**: a throwaway CA and source/destination EC
  certificates are made under the work dir (removed at the end).
  Certificate, key and trust are passed as fds 4, 5 and 6 on both sides, and
  the peer leaf SHA-256 pins are checked. The same checks apply.
- **vsock relay**: a guest connection to host port 5000 (`nc -lU`) carries a
  timestamp stream. A plaintext migration runs with
  `checkpoint.migrate_active_vsock=true` and the same `migration_endpoint_id`.
  More lines must arrive after the handoff, and only a completed handoff with
  a retired source counts (a source that keeps running also keeps writing).
- The new migration journals are decoded with `bhyvectl --migrate-journal`
  into `journals.txt`. They are left in `/var/db/bhyve/migration`.

### saverestore (phase 4b)

Preflight: as for snapshot (no migration tools needed) plus `guest-bin/srtool`.
Bridge with two taps, host 10.231.79.1/24. Every guest probe line is judged
by a library function covered by the self-test (`sr_hold_verdict`,
`sr_spin_verdict`, `sr_clock_verdict`, `sr_leaf_verdict`). The reference
digest is computed on the host by the same static `srtool` (fresh seed per
run, so no stale data can match).

- `host-cpu-local-leaves` INFO: how many distinct values CPUID 0x80000026 and
  0x1A have across the host CPUs (more than one is why a same-host restore
  failed in gen3).
- `guest-cpu-local-leaf-0x80000026` / `-0x1a`: read with cpuctl on every vCPU
  of the guest; must be not enumerated or zero on all vCPUs (the gen4 vmm
  fix). The detail marks which leaf belongs to the host's vendor.
- `sr-prep`: 2-vCPU guest `ht-sr1` writes a `HT_SR_MB` MiB pattern file
  (synced) and starts a process holding the same pattern in memory; both
  must equal the host digest. Two workers pinned to vCPU 0 and 1 start.
  Status files live on a tmpfs, so the workload never writes the disk.
- `sr-baseline-ping`, `sr-baseline-tcp` (guest->host and host->guest).
- `sr-suspend-A`: suspend checkpoint A; the disk is copied at that moment.
- Restore #1 and restore #2 of the same checkpoint A, each from a fresh copy
  of the suspend-time disk (`sr-r1-*`, `sr-r2-*`): `-restore` (FAIL detail =
  bhyve's refusal, e.g. the named CPU contract field), `-guest-responds`
  (FAIL = hang), `-memory` (the same process, same pid, still holds the
  expected digest), `-file`, `-vcpus` (every pinned worker advanced, on its
  own CPU), `-clock` (guest realtime/monotonic jump vs host elapsed is
  reported; FAIL only if a clock went backwards), `-ping`, `-tcp`,
  `-write-after-restore` (16 MiB written, synced, read back).
  `sr-r2-independent`: restore #1's file is absent and the holder's
  verification count is the same in both restores.
- `sr-cycle1..3-*`: suspend -> restore three times in a row from the running
  guest, with the same memory/vCPU/clock checks (network and write on the
  last cycle).
- `sr-running-checkpoint`, `sr-running-*`: a checkpoint of the running guest
  (after `sync`; the source is stopped right after it), restored.
- `sr4-*`: 4-vCPU guest: `sr4-checkpoint-busy` (checkpoint while 4 pinned
  workers are busy; all keep running), suspend/restore, memory, all 4 vCPUs,
  clock, ping.
- Refused restores, each on a copy of checkpoint A: `sr-neg-tamper-data`,
  `-kern`, `-meta` (one byte flipped; must be refused with "integrity
  verification failed"), `sr-neg-truncated-manifest`,
  `sr-neg-device-missing` (no virtio-rnd), `sr-neg-device-moved` (virtio-rnd
  at slot 7), `sr-neg-cpu-contract` (the destination exposes nested
  SVM/VMX that the checkpoint did not have; must be refused with
  "Checkpoint CPU contract differs at <field>"; SKIP without the nested
  gate). `sr-neg-device-named` INFO records whether the device refusal names
  the device (the restore path does not; see sr2-record.md).
  `sr-neg-original-untouched`: checkpoint A's digest is unchanged.

### devices-sr (phase 4c): device save/restore matrix

`hosttest.sh devices-sr` (root, vmm; 28-48 min; separate from the hardware
`devices` phase, runs alone or in any order). One bhyveload guest per device
group. Each group: boot, exercise every device so it holds live state,
checkpoint the running guest (`dsr-G-checkpoint-running`: published and the
guest goes on), suspend (`dsr-G-suspend`), restore with the identical config
(`dsr-G-restore`), `dsr-G-present-after-restore` (pciconf -l, devinfo and
usbconfig identical before/after), exercise again, partly with the processes
started before the suspend. Every FAIL detail carries the guest's error lines
(`dsr-guest.sh errs`) and bhyve's last refusal lines. `HT_DSR_GROUPS` picks
groups; `devices-sr/plan.txt` says which optional backends are available.

| group | devices | after-restore checks |
|---|---|---|
| stor | nvme, ahci-hd, ahci-cd (ISO), virtio-blk modern 4 queues, 2nd virtio-blk; virtio-scsi with `HT_DSR_SCSI=yes` | old pattern intact + new write (`-after`), read loop alive across the suspend (`-io-across-restore`), NVMe identify (`dsr-nvme-admin-after`), host backing file holds the new write (`-backing`), whole ISO sha256 |
| net | e1000, virtio-net modern 2 queue pairs, virtio-console 2 ports, COM2 over TCP | ping started before the suspend still answered (`-traffic-across-restore`), ping + TCP both ways, `act_vq_pairs` unchanged, port reader opened before the suspend gets host data, guest->host on both ports |
| gfx | xhci + tablet, fbuf, hda, virtio-snd (null backend), virtio-input (host uinput keyboard from `dsrtool uinput`) | descriptor read through xhci, RFB banner from the VNC port, pcm play+capture, the evdev reader opened before the suspend receives new keys |
| fs | virtio-9p, virtio-fs (host virtiofsd), virtio-balloon target=128M, virtio-pmem, virtio-mem 128M plugged | file opened before the suspend read to the end after it (9p fid, virtio-fs handle), guest write on the host, balloon desired/current unchanged, pmem pattern + host file, plugged size |
| misc | i6300esb (action=notify), virtio-rtc alarm, virtio-crypto (geli), pvpanic; tpm with `HT_DSR_TPM=yes` + swtpm | no spurious watchdog expiry after a restore that took longer than both stages, and the restored watchdog fires once patting stops; RTC alarm due during the suspend fires after it; the pre-suspend geli session still encrypts on vtcrypto |
| gpu | virtio-gpu alone (its guest driver panicked at boot attach under QEMU; dm-record.md) | vtgpu attached without errors before and after |
| iommu | virtio-iommu + modern virtio-blk endpoint | endpoint I/O after the restore |
| neg | passthru (`HT_DSR_PPT=pptN`): the only emulation without pe_snapshot | checkpoint refused, guest survives; otherwise SKIP with the reason |
| uefi | firmware `/usr/local/share/uefi-firmware/BHYVE_UEFI.fd` + per-VM varfile copy | UEFI boot (`machdep.bootmethod`), memory pattern and clock across the restore, localhost migration with the destination's topology line (`dsr-uefi-migration-topology`) |

SKIP reasons are explicit: virtio-scsi (host CTL LUN is host
configuration), tpm (no swtpm; TPM checkpoint also needs migration=true,
state_id, migration_key_id), fw_cfg (no FreeBSD guest driver), passthru (no
reserved device), uefi ("UEFI firmware not installed: <path>; install
5BSD-ports sysutils/edk2 (bhyve flavor)"). The image preloads the guest
drivers (5BSD refuses a late kldload) and has an EFI system partition, so the
same image boots through bhyveload and UEFI. `images/qemu-dsr-smoke.sh`
(unprivileged) proves the guest-side exercises under QEMU/TCG with the
capability plane on.

### devices (phase 5)

Preflight: root. No vmm is needed.

- Audio: `/dev/sndstat` lists pcm devices. A 1 s 440 Hz tone plays on
  `/dev/dsp` (the default unit; `HT_AUDIO_PLAY=no` to skip) — listen for it.
  2 s is recorded from the default unit, and the peak must be above -90 dBFS
  (a muted mic fails).
- Camera: on `/dev/video0`, `bin/ht-camera` reads a frame through video(4)
  `read(2)` and requires a non-constant frame. With no `/dev/video0`, the
  check is SKIP (uvideo is not loaded and late kldload is gated).
- Bluetooth: the `ubt0` netgraph node, plus `hccontrol` BD_ADDR and version.
  `HT_BT_INQUIRY=yes` adds a 10 s inquiry.
- Dock Ethernet: `ure0` with `status: active`. With no ure0, the check is SKIP.
- OTel services: `otel_hwstat`, `otelpfd`, `otel_dtrace`, and `otelauditd`
  if auditd runs. Each starts with `service -E OTELCONF_FILE=<kit
  file-target conf> X onestart`; services that are already running are left
  alone. After 30 s each `<name>.jsonl` must pass `otlp_validate`. Each
  service is stopped with `onestop` and must be gone. The sha256 of
  `rc.conf`, `otel.conf` and `pf.conf` must be the same before and after.
- Podman port publishing through OpenBSD PF: this runs only if
  `containernetworking-plugins` comes from repository `5BSD-ports` and its
  portmap emits `rdr-to`. Right now the installed one is FreeBSD's (repository
  `FreeBSD-ports`, emits `rdr pass`), so the check is SKIP with that message.
  With the 5BSD build, a local image (`HT_PODMAN_IMAGE` or the first local
  one; nothing is pulled) publishes 127.0.0.1:18080. The answer is checked and
  the `cni-rdr` anchor rules are recorded.

## What this kit cannot test, and why

- **Two-host migration and migration recovery/reconstruction.** Only
  localhost migration is covered. The 25-case fresh-session live matrix
  (`contrib/hypertrace/tests/fresh-session-live-matrix.json`) needs two
  matched hosts and a fault-injection mechanism. This kit covers the
  baseline-isolation, checkpoint-stop, restore-fresh and repeated-session
  rows in their non-fault form only.
- **HyperTrace across live migration.** bhyve refuses plaintext migration
  when HyperTrace is enabled, so this path would need TLS. The fresh-session
  migration protocol is not exercised. HyperTrace is covered across
  suspend/restore only.
- **More than one nesting level, and Linux L1/L2.** L2 CPUID hides SVM, so
  there is one nested level only. The Linux/KVM L1 qualification in
  `tests/sys/vmm/SVM_NESTED_LIVE.md` needs images the repo does not ship.
  L1 save/restore with an active L2 is tested on one host only (no L1
  migration with an active L2).
- **Intel nested VMX** while `hw.vmm.vmx.nested=0` (SKIP), and the Intel
  VMX ATF runner `run-vmx-nested-live.sh` (not wired in).
- **Restore across hosts** (the CPU contract check is exercised on one host
  by changing the nested exposure).

- **Per-core energy.** hwstat reads AMD package energy only (0xC001029B). It
  does not read the per-core energy MSR (0xC001029A).
- **The camera** needs `uvideo` loaded at boot. The kit does not load
  modules, and late kldload is refused by mac_capability. Whether a tone is
  audible needs a human listener.
- **The waspnest/vmm ATF suites when not installed.** Install with
  `pkg install -r 5BSD-base 5BSD-waspnest-tests`. `run-vmm-root.sh` also kldloads, which the mac_capability gate
  refuses after boot.
- **Podman through OpenBSD PF** with the FreeBSD CNI build (see above).

## Files

```
hosttest.sh            driver (phases, results, summary)
lib/common.sh          results, preflights, cleanup, bhyve and HyperTrace helpers
lib/acmd-console.sh    serial-console command driver (from tests/sys/kern/vsock_e2e)
lib/selftest.sh        unprivileged self-test of the library logic
phases/*.sh            hwstat, hypertrace, nested, snapshot, saverestore, devices-sr, devices
guest/*.sh             counter.sh, workload.sh, l2-boot.sh (L1), l2-role.sh (L2),
                       sr-guest.sh (save/restore probes), dsr-guest.sh (device exercises)  -> /root/hosttest in the image
guest-bin/vsock-pipe   guest vsock client (tests/sys/kern/vsock_e2e/vsock-pipe.c)
guest-bin/srtool       static: pattern/expect/work/hold/verify/dirty/spin/clock (src/srtool.c);
                       also run on the host for reference digests
guest-bin/dsrtool      static: vfsmount (virtio-fs), evread, tpmrand in the guest; uinput on the host (src/dsrtool.c)
images/pkgroot.sh      unprivileged pkgbase install into a METALOG root
images/mkimage.sh      makefs + mkimg (GPT: gptboot, UFS root p2, EFI system partition p3) from the METALOG
images/build-guest.sh  root + overlay (autologin root sh on ttyu0, loader.conf, rc.local roles)
images/qemu-smoke.sh   unprivileged QEMU/TCG smoke test of the image
images/qemu-dsr-smoke.sh QEMU/TCG smoke of the devices-sr guest side + UEFI boot of the image
images/refresh-tools.sh refresh the bin/ helpers after the upgrade
coverage/build-hwstat-cov.sh, run-hwstat-cov.sh, hwstat/ (instrumented build)
bin/                   otlp_collector, otlp_validate, otlp_json_validate, ht-sockpair,
                       ht-camera, ht-audio, vsh-connect (PROVENANCE lists sources)
src/                   sources of the C helpers
```

Guest roles are chosen at boot with `bhyveload -e hosttest.role=l1|l2
-e hosttest.hostname=... -e hosttest.inet=... -e hosttest.dtraced=yes` and
read in the guest with kenv(1). There is one image for every role. L2 also
reads `hosttest.marker`, `hosttest.l2work` (MiB per vCPU) and `hosttest.l2hold`
(seconds); `guest/l2-role.sh` runs them from rc.local. The guest preloads
`cpuctl` (loader.conf) for the CPUID leaf checks.

### Gen7 diagnostic corrections

Delivery counts are current ledger entries, cleared by session teardown.
`NAME.stats.VM` preserves the first live sample with positive outbound and
installed counts, with its sampling time in `.time`; `NAME.stats-after.VM`
records teardown separately. No positive sample is not proof of no delivery.
Guest minions run under `daemon -o /var/log/hosttest-dtraced.log` in foreground
mode so child linker/probe errors are retained. Rebuild images with the normal
`mkimage.sh` procedure after changing this overlay; existing images are stale.
Standalone HyperTrace sessions save `NAME.diagnostics.VM` after completion.

`HT_NESTED_HYPERTRACE=no` omits the L1 HyperTrace device, minion and session
for nested-virtualization isolation. It does not disable the existing L0
capture probes. Default remains `yes`. Do not interpret an isolation run as
qualification of HyperTrace. The gen7 freeze capture requirements still apply.

Repeated session names clear previous delivery snapshots before tracing starts.
Statistics commands receive SIGTERM after five seconds and SIGKILL two seconds
later if needed, so cooperative sampler shutdown does not wait indefinitely.

### Isolating the gen7 nested/HyperTrace freeze

For the first captured nested qualification, set both
`HT_NESTED_HYPERTRACE=no HT_L0DIAG_DTRACE=no`. The first disables the L1
HyperTrace session; the second disables L0 diagnostic FBT/SDT probes.
Thread stacks and bounded vCPU/statistics queries remain enabled. Disabled
tracing is explicitly marked, never treated as zero NPFs. Keep the serial/NMI
capture plan in `../gen7-freezes-record.md`; disabling probes does not establish
that nested execution is safe or fixed. Re-enable each tracing path separately
after the uninstrumented baseline is qualified.

Snapshot OTel checks consume validated OTLP metric points, not stdout.
A new consumer after restore emits `hypertrace.vm.registered`; `restarted`
is emitted only when one consumer observes a change in an already-known VMID's
epoch. The separate before/after epoch comparison remains required.

Expanded DTrace and nested storage qualification (Gen8 follow-up)
--------------------------------------------------------------
The staged hypertrace phase now runs guest/dtrace-cases.sh locally on the
host and in both minions. It checks BEGIN/END, syscall entry/return/_exit,
proc exec-success, and explicit syntax-error rejection. Each positive test
requires both command success and a positive aggregation. This is provider
coverage for the paths used here, not a claim that every DTrace provider or
probe is tested. Each remote exec/_exit clause is tested separately before
the combined session; both combined counts must equal the workload run count.
The existing syscall, isolation, glob, drain, fresh-session and per-VM OTLP
checks remain required. Full hardware results are pending.

The nested checkpoint workload now attaches three 16MiB file-backed scratch
disks inside L1: virtio-blk at slot5, NVMe at6, AHCI at7. The L2 boot disk is
still virtio-blk at slot3. Before HOLD, L2 writes/reads separate4MiB seeded
patterns. After the hold spanning L1 suspend/restore, it verifies those old
patterns, writes new ones and reads them back. L1 then checks each backing
file for the new pattern. Every device/stage has an individual result.
Capacity and mounted-device checks refuse unexpected targets; these are
emulated disposable devices, not physical passthrough. Existing L2 serial,
virtio-net and CPU checks remain. Other emulations (e.g. virtio-fs, TPM, GPU,
USB, IOMMU translation) have no new nested qualification from this change.
A new guest image is required for these scripts; keep HT_IMAGES pointed at
the matching staged images directory. The host library aggregation correction
also requires a reviewed system update before expecting the OTLP bug to pass.

hosttest.sh selftest includes lib/coverage-test.py (Python3 required), which
uses scratch-file stubs to reject missing output, trace failures, compiler
crashes/timeouts/missing tools, corrupted disks, mounted devices, wrong capacity
and failed mount enumeration. These are harness regressions, not hardware tests.

### Guest VirtIO activity through HyperTrace

The HyperTrace phase requires the guest kernel's request-level SDT probes
`virtqueue::enqueue:result` and `virtqueue::dequeue:complete`. It performs a
bounded, read-only raw disk workload and filters root block queue events on the
host. The guest tracing driver suppresses SDT on its transport queues before
forwarding; host-side predicates cannot provide that exclusion. It requires
positive submissions and completions, clean tracer exit and delivery evidence.
Any tracing-transport event in these aggregates fails the check.
Counts establish activity, not one-to-one I/O accounting across session edges.

Run the phase with `HT_ROOT_PACKED=no` (default split queue), then
`HT_ROOT_PACKED=yes` to offer a modern packed root disk. The observed probe ring
mode must match the requested mode; merely offering packed is not a pass.
The root disk options are also preserved by the ordinary save/restore helpers,
so `HT_ROOT_PACKED=yes` can qualify `saverestore` with the same device topology.
This requires rebuilding the guest kernel and all matching VirtIO modules,
then the guest image; the queue allocation interface changed. It does
not enable unsupported virtio-fs notification or packed guest negotiation.

Packed `saverestore` runs require local guest DTrace evidence of positive root
queue submissions and completions in packed mode before the first checkpoint
and after every restore. Split runs can request the same check with
`HT_SR_VIRTQUEUE=yes`. Each check allows 20 seconds for the read-only workload
and tracer, with a 30-second host command deadline; missing probes, wrong mode,
failed workloads and tracer timeouts fail the check.

Qualification requires `capability_plane=YES` in the guest manifest. Host
preflight and guest boot check that the loader has not disabled the plane,
`mac_capability` is loaded, isolation enforcement is 1 and switchboard is running.
Each runtime check is bounded to five seconds. A guest failure prevents both
READY and L2 success markers. These checks establish runtime prerequisites;
they do not prove every grant or policy operation is correct. Plane-OFF images
remain available for manual comparisons but are refused by normal qualification.

To qualify an uninstalled bhyve candidate, set `HT_BHYVE_DIR` to an absolute
directory containing its executable named `bhyve`. The kit preserves that
selection when resetting PATH and when using timeout wrappers, and records the
selected path in RUNINFO. Invalid overrides fail rather than using the installed
binary. This does not select guest kernels/modules or imply compatible builds.
