# FireWire and Hyper-V module qualification

## Implemented scope

Twelve selected amd64 GENERIC leaves use native C/assembly/KOBJ and existing
module link/CTF/debug/install stages: six FireWire and six Hyper-V modules.
Thirty-eight compiler contexts cover thirty-six physical C files, one assembly
source and generated vmbus_if.c from original vmbus_if.m. Sixty-eight physical
header contexts include thirty-three exact reused providers; generated option,
audio/video/VMBus interfaces and assym.inc are declared native dependencies.
Original EXPORT_SYMS=YES for firewire/hv_vmbus and other NO policies are retained.
Source/option/order declarations are explicit. No original runtime C/assembly,
Makefile or protocol/driver behavior is changed.

The new sys/dev/firewire package owns shared fwcrom.c and the four public header
inputs. The old root header target is a native alias to the owned provider;
fwcontrol uses the new source label. fwcontrol and dconschat are requalified with
the correct userland toolchain, separately from kernel profiles. Their installation
manifests/manual bytes and executable payloads are preserved; debug bytes differ
and the exact archive differences are retained, as described below.

## Correct per-object CTF policy

The original custom vmbus_vector.S recipe invokes only the compiler; ordinary C
recipes also run ctfconvert. Applying conversion to that assembly object added a
CTF section and changed final VMBus CTF bytes. Per-object diagnosis retains raw
section/hash differences before correction. The existing module object helper
now takes convert_ctf=True by default, meaning participate in the selected kernel
CTF mode. False explicitly skips conversion for this original custom recipe.
The option cannot enable conversion when global kernel_ctf is disabled.
All previous callers retain their original default behavior. Twenty-two previous
ISP/Myricom module artifacts remain byte-identical across both profiles.

## Evidence

All paths below are under /usr/obj/usr/src:

- bazel-firewire-hyperv-module-make-references-r1-20261102: all 24 untouched Make
  build/install controls, one workload at a time with all sixteen CPUs. Original
  Makefile/input hashes are checked against the source inventory before building.
- bazel-firewire-hyperv-modules-ctf-debug-native-r5-20261102 and the corresponding
  plain-native-r1-20261102: normal build-bsd format-5 qualification of 53 targets,
  including twelve module/debug/install triples, eleven prior module artifacts
  and six existing provider tests. Tests pass in both profiles; they do not
  demonstrate FireWire/Hyper-V hardware behavior.
- bazel-firewire-tools-ownership-native-r1-20261102: two utility installation
  archives built with the userland SDK. No new utility behavioral tests are added.
- bazel-firewire-hyperv-modules-review-r1-20261102: actual compiler/link actions,
  input digests, exact parameter files, artifact/debug/install proofs, helper and
  utility regression results, rejected-run diagnosis, source snapshot and drivers.

All twelve plain modules are byte-identical to untouched original Make outputs.
CTF/debug section inventories, metadata and payloads agree except GNU build-ID
and debug-link values; CTF bytes agree exactly and both debug CRC sets validate.
All 36 module file installation records match. Whole DWARF byte identity is not claimed.
The utility ELF regression requires exact section inventories/metadata/payloads
except build-ID/debug-link values, identical manifest/manual bytes and validated
old/new debug CRCs. Their tar archives differ in executable debug links and debug
contents/sizes (plus derived header checksums); archive or DWARF byte identity is
not claimed. The rejected whole-archive equality result and member diagnosis
remain alongside the accepted bounded ELF/metadata proof.
Thirty-eight executed compiler contexts from r3 verify SDK compiler, defines,
warning order, code-generation flags and 4,853 consumed prerequisite entries.
Final r4/r5 CTF-only corrections reuse those compiled objects; no fresh compiler
spawn is invented for cached results. Both earlier and final execution logs are
hash-bound. Twelve original ordered initial links pass with actual input digests;
parameter bytes were captured before later profiles. Only exact KOBJ provenance
comments may differ in generated inputs; raw hashes/controls are retained.

The first analysis run rejected a duplicate computed-name PCM interface view;
the correction reuses existing interface views and preserves prior visibility.
A second run rejected mixed userland targets under the kernel toolchain; separate
profiles now select the intended toolchains. The r3 CTF mismatch and per-object
diagnosis are retained. No rejected result is promoted to accepted evidence.
No finished artifact is normalized and no fallback executes Make inside Bazel.

## Observability and open gates

The bounded scan of 36 C files, the assembly file and interface schema records
four explicit DTrace marker lines: one network-send-pressure event in if_hn.c and
three storage connect/request-pressure events in hv_storvsc_drv_freebsd.c.
Compiled probe sections and payloads match original Make. Other scanned sources
lack explicit markers under this scan; inherited subsystem/header instrumentation
and live firing still need review. Track FireWire bus/reset/isochronous/DMA/error
paths and VMBus channel/ring/interrupt/network/storage lifecycle with useful shared
events; avoid per-packet logs or payload disclosure. No new probes are added here.

The existing build-bsd C interface/format-5 backend and maintained helpers express
these inputs. The frontend manual documents original CTF recipe exceptions; no
CLI, signing/security, staging or publication contract changes are required.
The default-loader/strict-export distinction remains documented separately.

ARM64/RISC-V and alternate KERNCONF/options, real module loading, FireWire/Hyper-V
hardware, live probes/audit, full world/rescue/pkgbase/hardware/bootstrap,
publication, VM/runtime, cache/sandbox and CPU/memory/disk I/O/disk-use gates remain
open. The existing Hyper-V Make ARM branch uses SRC rather than SRCS for its two
architecture sources; that selection needs review/fix during ARM qualification.
Current evidence is amd64 only. Resource records are bounded observations, not a
comparative performance result. Make remains production/default; BIP is excluded.
No host module loading, installation, upgrade or reboot was performed.
