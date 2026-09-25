# Inside bhyve

## A code-guided tour of modern virtualization on FreeBSD

Status: source review of the FreeBSD tree at `/usr/src`, 2026-07-15, at commit
`d14e7d716b14f9579b6224ed65752502b03c77d0`.

This document explains bhyve as it is implemented in this source tree. It is
not just a command-line guide. It follows execution from the kernel
virtualization code through `libvmmapi`, the bhyve process, the event loop, and
the device backends; inventories the available machine and device models; and
compares the result with Linux KVM plus QEMU.

The comparison needs one important qualification:

* **KVM is primarily a kernel virtualization API**, comparable to FreeBSD's
  `vmm(4)` kernel subsystem plus parts of `libvmmapi`.
* **QEMU system emulation is primarily a userspace machine, device, I/O, and
  lifecycle runtime**, comparable to the `bhyve(8)` process, its device models,
  its backends, and some tools around it.
* A normal Linux hardware-accelerated VM uses **KVM + QEMU**. A normal FreeBSD
  VM uses **vmm + bhyve**. Comparing bhyve alone with either KVM or QEMU alone
  produces misleading conclusions.

### Who this book is for

This is written for a systems programmer, product architect, or operator who
wants to understand bhyve deeply enough to make engineering decisions. It does
not assume prior hypervisor implementation experience, but it does assume basic
familiarity with operating systems, processes, virtual memory, PCI devices, and
C.

It has three goals:

1. Build an accurate mental model of hardware-assisted virtualization.
2. Connect that model to the actual FreeBSD and bhyve source code.
3. Identify what must change for bhyve to anchor a FreeBSD-system,
   Linux/Android-application appliance.

The code samples are either shortened excerpts from this tree or explicitly
labeled illustrative examples. Ellipses mean irrelevant setup or error paths
were omitted. The examples favor architectural clarity; use the cited source as
the authority before copying code into the implementation.

### How to read it

For a first reading:

* Read the preamble and executive summary.
* Follow the startup, vCPU, MMIO, and asynchronous-I/O chapters in order.
* Skim the device inventory, then read the devices relevant to your product.
* Read security, lifecycle, and limits together; they constrain each other.
* Finish with the KVM/QEMU comparison and appliance roadmap.

For source work, start with the source map near the end and use the “code walk”
sections as entry points. For operations, start with the launch and inspection
examples in the appliance section.

### Book map

```text
Part I    Foundations
          How virtualization works; the kernel/userspace split

Part II   Execution
          Startup; vCPUs; exits; MMIO; threads; the kqueue reactor

Part III  The virtual machine
          PCI; firmware; storage; networking; VirtIO; graphics; audio; TPM

Part IV   Trust and time
          Capsicum; snapshots; migration; observability; nested virtualization

Part V    Perspective
          KVM/QEMU comparison; hard limits; appliance design; testing

Appendix  Source map and primary external references
```

The numbered sections remain usable as standalone reference chapters. The
short code walks are intentionally repeated at the point where the underlying
idea matters; the book should not require constant jumping to an appendix.

# Part I — Foundations

This part builds the generic virtualization model and then identifies bhyve's
kernel, library, process, platform, and backend layers.

## 0. Preamble: how modern virtualization works

Before looking at bhyve, it helps to have a precise mental model of a modern
virtual machine. The short version is:

> A modern VM is mostly a real CPU executing guest instructions directly, plus
> hardware and software that intercept the relatively small set of operations
> the guest must not control directly.

It is not normally an interpreter reading and simulating every guest
instruction. It is also not merely a process with a different filesystem view.
The CPU, memory-management unit, interrupt machinery, host kernel, and a
userspace machine model cooperate to create the illusion that the guest owns a
computer.

### 0.1 Three related technologies that are not the same

The terms virtualization, emulation, and containers are often mixed together.

**Hardware-assisted virtualization** runs an unmodified guest kernel for the
same instruction-set architecture as the host. Most ordinary guest instructions
execute directly on the host CPU. Intel VT-x/VMX, AMD-V/SVM, Arm virtualization
extensions, and the RISC-V Hypervisor extension provide the additional CPU
state and privilege boundaries required to do this safely. bhyve and KVM are in
this category.

**Full system emulation** models a CPU and machine in software. It can run a
guest compiled for a different architecture—for example, an Arm guest on an x86
host—but it must translate or interpret guest instructions. QEMU's TCG is a
dynamic binary translator that can do this. Hardware-assisted virtualization
is normally much faster because it avoids translating ordinary instructions.
bhyve does not contain a TCG equivalent.

**OS-level containers** share the host kernel. Namespaces, jails, cgroups,
capabilities, resource controls, and filesystem views isolate processes, but a
container does not boot an independent kernel. FreeBSD jails and Linux
containers are in this category. Containers are lighter than VMs, but they do
not let a FreeBSD host directly run a Linux kernel ABI or isolate a separately
patched guest kernel in the same way as a VM.

These technologies can be combined. A Linux VM can run Linux containers. That
is a natural design when FreeBSD owns the physical system but Linux provides the
application ABI and container ecosystem.

### 0.2 The actors in a virtual machine

A useful vocabulary is:

* The **host** is the physical machine and operating system controlling the
  hardware.
* The **guest** is the operating system running inside the VM.
* The **hypervisor** or **virtual machine monitor (VMM)** controls guest CPU
  execution and isolation. In real systems this may be split between a kernel
  component and a userspace runtime.
* A **vCPU** is the guest's view of one CPU. It is state—registers, control
  registers, interrupt state, and virtualization control data—plus a host
  thread that gets scheduled on physical CPUs.
* **Guest physical memory** is what the guest kernel believes is RAM at physical
  addresses 0 through N. It is not necessarily contiguous physical host RAM.
* A **device model** implements the registers, queues, interrupts, and behavior
  of hardware visible to the guest.
* A **backend** connects that virtual device to a host resource such as a file,
  disk, tap interface, socket, audio device, or rendering service.

The word “hypervisor” is sometimes used for all of this and sometimes only for
the privileged CPU layer. In this document, the exact component is named when
the distinction matters.

### 0.3 CPU privilege and hardware virtualization

An operating-system kernel expects to control privileged CPU state: page
tables, interrupts, timers, processor modes, and hardware registers. Simply
running a guest kernel as an ordinary userspace program would not work. It
would either fault constantly or, if given real privilege, take over the host.

Virtualization extensions add a mode in which the guest can run with the
privilege level it expects while remaining subordinate to the host VMM.

On x86, Intel describes the split as **VMX root** and **VMX non-root** operation;
AMD has corresponding host and guest SVM operation. This is separate from the
guest's own ring 0/ring 3 distinction. A guest kernel can run at its ring 0
inside non-root operation, while the host hypervisor retains ultimate control.

On Arm, a host hypervisor normally operates at exception level EL2 and runs a
guest kernel at EL1. RISC-V's Hypervisor extension provides comparable
supervisor/hypervisor execution and two-stage translation facilities.

Before entering a guest vCPU, the VMM loads a hardware control structure. On
Intel this is the VMCS; on AMD it is the VMCB. It describes:

* guest register and control state;
* host state to restore on an exit;
* which instructions and events should cause exits;
* second-stage memory translation roots;
* interrupt behavior;
* entry and exit controls; and
* optional acceleration features supported by that CPU generation.

The VMM then executes a hardware entry instruction. The CPU begins executing
the guest directly until an event requires the VMM.

### 0.4 VM exits: where direct execution stops

A **VM exit** transfers control from the guest back to the host VMM. Typical
reasons include:

* access to an emulated I/O port or MMIO register;
* selected privileged instructions or model-specific registers;
* a stage-2 memory fault;
* interrupt-controller operations that need software help;
* halt, pause, debug, breakpoint, or single-step conditions;
* invalid guest state;
* shutdown or reset; and
* an external request to stop, inspect, or suspend the vCPU.

Not every privileged action must exit. Modern CPUs can virtualize many
operations directly, and the VMM chooses controls that balance correctness,
security, and performance.

After an exit, one of three broad things happens:

1. The kernel VMM handles it and immediately re-enters the guest.
2. The kernel returns an exit record to the userspace VM runtime, which emulates
   a device or policy operation and calls the run ioctl again.
3. The event terminates, suspends, resets, or exposes a fatal error in the VM.

VM exits are much more expensive than an ordinary guest instruction. Good
virtualization design therefore avoids unnecessary exits, batches device work,
uses paravirtual queues, and lets hardware handle common interrupt and memory
operations.

### 0.5 vCPUs are scheduled host work

A guest with four vCPUs does not permanently own four physical cores unless the
host explicitly dedicates them. Each vCPU becomes schedulable host work,
usually represented by a host thread. The host scheduler decides when and where
it runs.

This has several consequences:

* A VM can have more vCPUs than are simultaneously running.
* Host CPU contention appears to the guest as stolen or delayed execution time.
* Pinning vCPU threads to physical CPUs can improve predictability but can waste
  capacity if designed poorly.
* Guest spinlocks behave badly when one vCPU spins while the vCPU holding the
  lock is descheduled.
* NUMA placement matters: a vCPU running on one socket may frequently access
  guest RAM allocated on another.
* Device workers, event threads, interrupt delivery, and backend services also
  consume host CPU time; pinning only vCPUs does not fully define VM latency.

For performance isolation, the product must manage host scheduling, vCPU
topology, cpusets, NUMA memory, backend workers, interrupt placement, and noisy
neighbors as one policy.

### 0.6 Two-stage memory translation

An ordinary operating system uses page tables to translate a process's virtual
address into a physical address. A VM adds another layer:

```text
guest virtual address
        |
        | guest page tables controlled by guest kernel
        v
guest physical address
        |
        | EPT / NPT / Arm stage-2 / RISC-V G-stage translation
        v
host physical memory
```

The first translation gives the guest exactly the memory-management model it
expects. The second is controlled by the host VMM and prevents the guest from
addressing arbitrary host RAM.

Modern CPUs walk both levels in hardware and cache combined translations in
the TLB. This is the critical acceleration that makes unmodified guest virtual
memory practical. The host can change second-stage mappings to add RAM, map
device memory, revoke access, implement copy-on-write or dirty tracking, and
protect pages.

The userspace device model also needs to access guest buffers. The kernel VMM
therefore provides controlled ways to map guest RAM into the VM process and
translate a guest physical address into a host userspace pointer. This makes
device emulation fast, but it means the device process is trusted with the
guest's memory.

For migration, the runtime must identify pages dirtied while the guest is still
running. KVM exposes mature dirty-log mechanisms. A basic local suspend can
instead stop all vCPUs and copy RAM, accepting a long pause.

### 0.7 Virtual devices: trap-and-emulate

One way to make a guest run is to model hardware it already knows. If the guest
uses an emulated e1000 NIC, AHCI controller, NVMe controller, UART, or HDA audio
device, it loads its ordinary hardware driver.

For a register access, the path may look like:

```text
guest driver writes device MMIO register
        |
CPU finds no ordinary RAM mapping and exits
        |
kernel VMM reports the MMIO exit to userspace
        |
device model validates and applies the register write
        |
device model starts or defers backend work
        |
userspace re-enters the vCPU
```

This provides compatibility, but accurately emulating historical hardware can
be complex and exit-heavy. Old physical devices were designed for real buses,
not efficient virtualization.

### 0.8 Paravirtual devices and VirtIO

A **paravirtual** device is explicitly designed for virtual machines. The guest
uses a virtualization-aware driver instead of pretending it is talking to a
particular physical NIC or disk controller.

VirtIO is the dominant open standard. A VirtIO device normally exposes:

* feature bits negotiated by driver and device;
* device-specific configuration;
* one or more **virtqueues** in guest RAM;
* a notification mechanism from guest to device; and
* interrupts or equivalent notifications from device to guest.

The guest puts descriptor chains into a shared queue. Descriptors identify
guest buffers and whether the device may read or write them. The guest then
notifies the device, often once for a batch. The device processes the buffers,
publishes used entries, and interrupts the guest only when required.

This is efficient because the bulk data stays in shared guest memory. The
hypervisor does not need a VM exit for every byte or packet. Features such as
indirect descriptors, event-index suppression, packed rings, multi-queue, and
notification optimizations reduce exits and contention further.

VirtIO separates several concepts:

* The **transport** describes how the device is discovered and how generic
  queue/configuration registers are exposed, such as legacy PCI, modern PCI, or
  MMIO.
* The **ring format** describes the shared queue, principally split or packed
  virtqueues.
* The **device type** describes network, block, input, sound, filesystem, vsock,
  GPU, and other semantics.
* **Device-specific features** describe optional capabilities within that
  device type.

Supporting modern VirtIO PCI does not automatically support packed rings, every
device type, or every optional feature. Conformance is a matrix rather than a
single version number.

### 0.9 Device backends and data placement

The guest-visible device is only the front half. A backend must perform the
actual work:

```text
guest virtio-net driver -> virtqueue -> virtual NIC -> tap/netmap/switch
guest virtio-blk driver -> virtqueue -> virtual block device -> file/ZVOL/disk
guest virtio-snd driver -> virtqueue -> virtual sound device -> audio service
```

The backend can live:

* in the main userspace VM process;
* in the host kernel, as with Linux vhost acceleration;
* in a separate process using a protocol such as vhost-user; or
* in physical hardware through passthrough.

In-process backends are simple and have direct access to guest memory, but a bug
can compromise the whole VM process. Kernel backends can be very fast but add
host-kernel attack surface. Separate backend processes improve modularity and
fault containment, at the cost of a memory-sharing, notification, lifecycle,
and state-transfer protocol.

The backend's location does not decide which operating system owns the product
service. A Linux service VM may own a hardware or media stack and export a
higher-level service to FreeBSD. Conversely, FreeBSD may own storage and expose
blocks or files to Linux. VirtIO defines particular driver/device boundaries;
it does not impose the overall system's policy direction.

### 0.10 Interrupt virtualization

Devices need to tell guest CPUs that work completed. The guest also expects
local and system interrupt controllers, priorities, masking, inter-processor
interrupts, and timers.

The VMM can emulate legacy interrupt lines, deliver MSI/MSI-X messages, and
virtualize APIC/GIC/APLIC state. Modern CPUs can accelerate parts of interrupt
delivery, but the VMM still owns the mapping between a virtual device event and
the target vCPU's pending interrupt state.

Interrupt behavior strongly affects performance. Too many interrupts cause
exits and scheduling overhead; too much coalescing increases latency. Multi-
queue devices normally pair queues and interrupt vectors with vCPUs to reduce
shared locks and cache-line movement.

### 0.11 DMA and the IOMMU

An emulated device does not perform uncontrolled physical DMA. Its device model
reads and writes buffers after validating guest descriptors and translating
guest addresses.

PCI passthrough is different. A real device can issue DMA transactions without
asking the userspace VMM. The host IOMMU—Intel VT-d or AMD-Vi on x86—must map
only the assigned guest pages for that device and must remap interrupts safely.
Without an IOMMU, a passed-through device or malicious guest driver could DMA
into the host kernel or another VM.

An IOMMU cannot repair poor hardware isolation. Multiple functions may share
reset or isolation boundaries, firmware may be buggy, and some devices cannot
be reset into a safe reusable state. Passthrough support is therefore a
hardware qualification problem as well as a hypervisor feature.

### 0.12 Time is virtualized too

A guest needs wall-clock time, monotonic time, timer interrupts, and a stable
view of CPU time even though its vCPUs can stop running. The VMM virtualizes
hardware timers and clock sources and accounts for pause/resume.

Time becomes especially difficult during suspend and migration:

* Should wall time jump forward while the VM was suspended?
* Should a monotonic guest clock include the stopped interval?
* Which expired timers should fire on restore, and in what order?
* Is the destination CPU's counter frequency and behavior compatible?
* How are application-visible deadlines affected?

A correct snapshot is therefore more than CPU registers plus a RAM file. It
must preserve the guest's temporal and interrupt state coherently.

### 0.13 What VM isolation does and does not provide

Hardware virtualization provides a strong boundary around CPU privilege and
guest memory, but the total attack surface includes:

* CPU virtualization and instruction emulation in the host kernel;
* second-stage page-table and interrupt-controller code;
* every device register and descriptor parser;
* backend file descriptors and protocols;
* firmware and boot interfaces;
* passthrough and IOMMU code; and
* management, debug, console, and migration interfaces.

The guest controls most inputs to its virtual devices. A malformed descriptor
is not an accidental edge case; it is untrusted input from across a security
boundary. Device code must validate addresses, sizes, directions, chain length,
feature state, queue state, and arithmetic before touching guest memory.

Process sandboxing protects the host if a userspace device is compromised.
Separate backend processes can further prevent one complex device from
compromising unrelated VM services. Neither replaces defensive kernel and
device implementation.

### 0.14 VM lifecycle is distributed state

Starting a VM is comparatively easy: allocate RAM, create vCPUs, instantiate
devices, load firmware, and run. Saving or moving one is hard because live state
is distributed across:

* vCPU registers and virtualization control state;
* guest RAM and pages changing during capture;
* interrupt controllers and pending interrupts;
* virtual clocks and timers;
* device registers and queues;
* requests executing in backend workers;
* storage contents and write caches;
* network and socket connections;
* external backend processes; and
* passed-through physical devices.

Suspend/save/restore requires a quiescence protocol and a versioned state
schema for every component. Live migration adds dirty-page iteration,
destination compatibility negotiation, transfer transports, failure rollback,
and bounded downtime. This is why migration maturity is a measure of the whole
VM runtime architecture, not merely a memory-copy feature.

### 0.15 Type 1 versus type 2 is less useful than the layer diagram

Traditional terminology calls a bare-metal hypervisor “type 1” and a
hypervisor hosted by a general-purpose OS “type 2.” bhyve is commonly described
as a type-2 hypervisor because FreeBSD remains the host operating system. KVM is
also part of a general-purpose host kernel, yet is often discussed as turning
Linux into a type-1 hypervisor.

For engineering decisions, the label matters less than these questions:

* Which code executes in the host kernel?
* Which code executes in the per-VM process or external services?
* Which operations cause VM exits?
* Who maps guest memory and injects interrupts?
* Where do device queues and backend work run?
* What authority does each component retain after startup?
* How are state, failure, and compatibility managed?

The rest of this document answers those questions for bhyve.

### 0.16 Mapping the generic model onto bhyve and KVM/QEMU

```text
Concept                    FreeBSD stack              Linux stack
-------------------------  -------------------------  -------------------------
hardware CPU virtualization vmm.ko / kernel vmm       KVM kernel modules
userspace ioctl wrapper     libvmmapi                  KVM API used by QEMU/etc.
per-VM runtime              bhyve                      QEMU, crosvm, cloud-hypervisor
machine/device models       compiled into bhyve        QEMU qdev/QOM devices
event/backend layer         mevent + device workers    QEMU main loops/iothreads
kernel device acceleration  limited/passthrough paths  vhost, ioeventfd, irqfd
external device protocol    no general equivalent      vhost-user, vfio-user
management protocol         CLI/config + bhyvectl      QMP plus management stacks
```

Both stacks use the same fundamental modern-virtualization techniques. Their
largest differences are not that one executes guest arithmetic differently;
they are the size and stability of the kernel API, userspace runtime
abstractions, device/backend ecosystem, lifecycle machinery, and management
surface.

## 1. Executive summary

bhyve is a compact, hardware-assisted type-2 virtual machine monitor. Its
architecture is a deliberate split:

```text
              management scripts / service supervisor
                              |
                    command line + nvlist config
                              |
       +----------------------v-----------------------+
       | one bhyve userspace process per VM           |
       |                                               |
       | machine model, firmware tables, PCI, devices  |
       | block/net/audio/socket backends, GDB, VNC     |
       |                                               |
       | vCPU pthreads             kqueue mevent loop  |
       +-------------+-----------------------+---------+
                     | libvmmapi             |
                     | ioctls + mmap          |
       +-------------v-----------------------v---------+
       | FreeBSD vmm kernel subsystem                  |
       | VM/vCPU state, VMX/SVM/EL2/RISC-V H, memory   |
       | stage-2 translation, interrupts, timers, ppt  |
       +----------------------+------------------------+
                              |
                  CPU virtualization + IOMMU
```

The kernel executes guest CPUs and owns the security-critical CPU, address
translation, interrupt, timer, and passthrough machinery. The userspace bhyve
process builds the virtual machine and emulates most devices. Each vCPU runs in
its own pthread and repeatedly issues `VM_RUN`. The main thread is a kqueue
reactor. Block, network transmit, audio, SCSI, TPM, VNC, and some other
subsystems add dedicated workers.

The design is **hybrid asynchronous**, not uniformly asynchronous. Host file
descriptor readiness is event driven and expensive block work is sent to
workers. However, MMIO, port-I/O, and PCI callbacks normally execute on the
vCPU thread that caused the exit. A slow or blocking callback stalls that vCPU.
Each device family has evolved its own locking, worker, reset, pause, and
completion model.

### Where bhyve is strongest

* A small and understandable CPU-to-device path.
* Low overhead when guests use hardware virtualization and efficient VirtIO or
  passthrough devices.
* Excellent integration with FreeBSD facilities: Capsicum, cpusets, NUMA
  domains, tap/vmnet, netgraph, netmap/VALE, GEOM/raw devices, PCI passthrough,
  DTrace, and the host scheduler.
* Mature amd64 fundamentals on Intel VMX/EPT and AMD SVM/NPT.
* One host thread per vCPU, which makes affinity and scheduling behavior easy
  to reason about.
* A simple linker-set device registration mechanism that makes in-tree device
  additions direct.
* A much smaller default attack surface than a feature-complete QEMU build,
  plus systematic capability-rights reduction and entry into Capsicum mode.
* Useful conventional device coverage for server VMs: AHCI, NVMe, e1000,
  VirtIO block/network/SCSI/console/random, and PCI passthrough.

### Where bhyve is weakest

* Save/restore is experimental, disabled by default, amd64-only, format-unstable,
  and incomplete. There is no production live migration framework.
* The userspace runtime is monolithic and has no general production-quality
  vhost-user/vfio-user-equivalent external-device framework.
* VirtIO coverage and feature depth are incomplete. In this tree only random,
  input, and vsock have the new non-transitional modern PCI transport; core
  devices such as block, network, console, SCSI, and 9P remain legacy-only.
* No general hotplug model or stable machine-management protocol comparable to
  QEMU's QMP.
* Narrower device, platform, graphics, USB, audio, and storage-backend coverage
  than QEMU.
* No software CPU emulator comparable to QEMU TCG. bhyve cannot emulate a
  different ISA and depends on host virtualization extensions.
* No nested virtualization. VMX and SVM are deliberately hidden from guests.
* Concurrency and I/O scaling are device-specific: for example, a fixed eight
  threads per block backend and only one VirtIO-net queue pair.
* Architecture parity is uneven. amd64 has the fullest machine model; arm64 and
  RISC-V have much smaller platform-specific layers.
* Operational observability exists in pieces, but there is no uniform metrics,
  tracing, event, and control schema across all devices.

For an appliance that uses FreeBSD as the system/control plane and Linux or
Android as application domains, bhyve is a credible CPU and isolation
foundation. The highest-value missing foundations are not random new device
types. They are a versioned VM/device-state model, robust suspend/save/restore,
an external backend protocol, complete modern VirtIO for the core data plane,
multi-queue and resource control, and a machine-readable management and
observability interface.

## 2. The layers

### 2.1 Hardware and kernel virtualization layer

The lowest software layer is the FreeBSD `vmm` kernel subsystem.

On amd64, the common implementation is under `sys/amd64/vmm/`:

* `vmm.c` owns VM/vCPU lifecycle and the generic run path.
* `intel/vmx.c`, `vmcs.c`, and assembly support implement Intel VMX.
* `intel/ept.c` implements Extended Page Tables.
* `amd/svm.c`, `vmcb.c`, and assembly support implement AMD SVM.
* `amd/npt.c` implements Nested Page Tables.
* `vmm_instruction_emul.c` and `vmm_ioport.c` handle instruction and port-I/O
  emulation shared with userspace exit handling.
* `io/vlapic.c`, `vioapic.c`, `vatpic.c`, `vatpit.c`, `vhpet.c`, `vrtc.c`, and
  `vpmtmr.c` implement interrupt controllers and legacy timers.
* `intel/vtd.c`, `amd/amdv*.c`, `io/iommu.c`, and `io/ppt.c` implement IOMMU
  integration and PCI passthrough.

On arm64, `sys/arm64/vmm/` contains EL2 VHE and nVHE execution, stage-2 MMU
handling, VGICv3, virtual timers, exception handling, and instruction
emulation. On RISC-V, `sys/riscv/vmm/` contains the hypervisor run path, APLIC,
SBI, fencing, virtual timer, and instruction emulation.

This is real hardware virtualization, not full CPU interpretation. Ordinary
guest instructions execute on the physical CPU. The VMM configures the
hardware control structure (VMCS on Intel, VMCB on AMD, equivalent EL2/H-mode
state elsewhere), enters the guest, handles exits that belong in the kernel,
and returns other exits to userspace.

The kernel/user boundary is intentional. Operations that require privileged
CPU state, stage-2 page tables, interrupt injection, or IOMMU control remain in
the kernel. Policy-rich device behavior stays in a less-privileged userspace
process.

### 2.2 Device node and ioctl ABI

VMs are represented under `/dev/vmm`. Userspace creates or opens a VM, opens
vCPUs, maps guest memory, sets register and interrupt state, and executes a vCPU
through ioctls. The public wrapper is `lib/libvmmapi`.

`libvmmapi` exposes APIs for:

* VM create/open/reinitialize/destroy.
* vCPU open, activate, suspend, resume, register access, capabilities, and run.
* guest memory segment creation, mapping, unmapping, and GPA translation.
* topology and memory-domain setup.
* interrupt, exception, MSI, IOAPIC/PIC/LAPIC, VGIC, and APLIC operations.
* PCI passthrough assignment, MMIO mapping, MSI, and MSI-X.
* vCPU statistics.
* suspend and optional snapshot support.

The `vm_run()` wrapper is deliberately thin: it issues the `VM_RUN` ioctl
(`lib/libvmmapi/vmmapi.c:811`). This resembles the broad KVM model, but the ABI
and ecosystem are much smaller. KVM has a documented stable API, capability
discovery, separate system/VM/vCPU/device file descriptors, dirty logging, and
a large userspace ecosystem. The KVM ABI has forbidden backward-incompatible
changes since Linux 2.6.22; FreeBSD's vmm API should not be assumed to offer the
same cross-release userspace compatibility contract.

### 2.3 Guest RAM mapping

bhyve allocates guest memory through the VMM and maps it into the userspace
process. `vm_setup_memory_domains()` lays NUMA domains sequentially in guest
physical address space, skips the low/high-memory hole, reserves guard regions,
and maps the memory with `MAP_SHARED | MAP_FIXED`
(`lib/libvmmapi/vmmapi.c:483`).

The current bhyve startup path requests `VM_MMAP_ALL`, and the implementation
asserts that this is the selected mapping style
(`lib/libvmmapi/vmmapi.c:492-503`). In practice, the bhyve process has a mapping
covering ordinary guest RAM. That is simple and fast for device emulation:
descriptor GPAs can be translated into process pointers. It also means a
compromised userspace device model can access all guest memory. Capsicum limits
host authority, not access between device models and guest RAM within the same
process.

Memory can be wired, excluded from host core dumps, assigned across host NUMA
domains, and paired with vCPU affinity. This is a useful appliance property:
the operator can make placement explicit instead of trusting a large runtime
to infer it.

### 2.4 The `bhyve` userspace process

`usr.sbin/bhyve/bhyverun.c` is the top-level runtime. It is responsible for:

* parsing legacy options and hierarchical nvlist configuration;
* opening or creating the kernel VM;
* defining CPU topology and host affinity;
* allocating/mapping RAM and boot ROM;
* creating vCPU objects and pthreads;
* initializing the architecture-specific platform;
* creating firmware interfaces and tables;
* instantiating PCI devices and TPM;
* restoring optional snapshot state;
* entering Capsicum capability mode;
* resuming the bootstrap processor; and
* running the main event dispatcher.

It is one process per VM. Devices are normally compiled into that process and
share its address space. A crash or memory-safety failure in any in-process
device can terminate or compromise the whole VM process, although it should be
contained from much of the host by Capsicum and limited descriptors.

### 2.5 Machine/platform layer

The common bhyve runtime is paired with architecture-specific machine setup.

amd64 adds the richest platform:

* ACPI, SMBIOS, E820, MP tables, LPC, RTC, PM timer, SCI, IOAPIC, legacy PIC,
  PIT, HPET, PS/2 keyboard/mouse, UARTs, VGA/framebuffer, and x86 MSR handling;
* UEFI/boot ROM boot and the older `bhyveload`-initialized path;
* PCI passthrough and Intel GVT-d support;
* RFB/VNC display and GDB support.

The source list is explicit in `usr.sbin/bhyve/amd64/Makefile.inc`.

arm64 uses a much smaller generic virtual platform described by FDT, with
PL011 UART, PL031 RTC, memory/MMIO handling, and GDB support
(`usr.sbin/bhyve/aarch64/Makefile.inc`). RISC-V uses FDT and architecture MMIO
support, but its userspace platform list is smaller still
(`usr.sbin/bhyve/riscv/Makefile.inc`). The kernel ports are substantial, but
the available virtual platform and peripheral parity should not be confused
with amd64 maturity.

### 2.6 Device model and backend layers

The guest-facing device model and host-facing backend are conceptually
separate, even when both live in one C file or one process.

Examples:

```text
guest virtio-blk driver
        |
virtqueue + PCI transport
        |
pci_virtio_block.c          guest-facing device semantics
        |
block_if.c                  host-facing asynchronous block API
        |
file, raw disk, or GEOM device
```

```text
guest virtio-net driver
        |
pci_virtio_net.c            guest-facing NIC
        |
net_backends.c interface    host-facing packet backend
        |
tap / vmnet / ngd / netgraph / netmap / VALE / slirp
```

This separation is good, but it is a C function-call interface inside the
bhyve process, not a general cross-process protocol. vsock and VirtIO-input in
this tree use external host endpoints for application/provider behavior, but
that does not amount to a general vhost-user facility that can host arbitrary
VirtIO backends outside bhyve.

# Part II — Execution

This part follows a VM from process startup into guest execution, through VM
exits and device callbacks, and out to asynchronous host I/O.

## 3. Process startup and device initialization

The startup sequence in `bhyverun.c:799-1072` is approximately:

1. Initialize configuration and parse options.
2. Calculate guest topology and vCPU maps.
3. Parse memory size.
4. Open, reinitialize, or create the named kernel VM.
5. Configure memory flags and NUMA domains; map all guest memory.
6. Apply host vCPU affinities.
7. Initialize memory emulation and the boot ROM.
8. Optionally fork into monitor mode. The parent waits for the child and, on a
   guest reset exit, reinitializes the VM and starts another child.
9. Open the bootstrap vCPU and all other vCPU handles.
10. Perform architecture-specific early platform initialization.
11. Initialize QEMU-compatible `fw_cfg` and add bhyve-specific values.
12. Instantiate all configured PCI devices.
13. Initialize the TPM interface.
14. Initialize VM Generation ID when firmware tables are enabled.
15. Initialize the GDB server if configured.
16. Create all vCPU pthreads in a suspended state.
17. Restore RAM, device, and kernel state if experimental restore was requested.
18. Build late platform tables.
19. Start the optional checkpoint-control thread.
20. Limit stdout/stderr rights and enter Capsicum capability mode.
21. Resume the bootstrap vCPU (or all restored vCPUs).
22. Turn the original main thread into the kqueue event dispatcher.

### Code walk: finding the architecture in `main()`

The real entry point is long, but its architecture becomes obvious when reduced
to the major calls. This is a shortened map of `bhyverun.c:799-1072`, not a
standalone program:

```c
int
main(int argc, char **argv)
{
        struct vmctx *ctx;
        struct vcpu *bsp;

        bhyve_init_config();
        bhyve_optparse(argc, argv);
        calc_topology();
        build_vcpumaps();

        ctx = do_open(vmname);                   /* kernel VM object */
        vm_set_memflags(ctx, memflags);
        vm_setup_memory_domains(ctx, VM_MMAP_ALL,
            guest_domains, guest_ndomains);      /* RAM + NUMA policy */

        init_mem(guest_ncpus);                   /* userspace MMIO */
        init_bootrom(ctx);
        bsp = vm_vcpu_open(ctx, BSP);

        bhyve_init_platform(ctx, bsp);           /* APIC/RTC/etc. */
        qemu_fwcfg_init(ctx);
        init_pci(ctx);                           /* all configured PCI */
        init_tpm(ctx);

        for (int id = 0; id < guest_ncpus; id++)
                bhyve_start_vcpu(vcpu_info[id].vcpu, id == BSP);

        bhyve_init_platform_late(ctx, bsp);       /* final tables */
        caph_enter();                            /* no ambient namespace */
        vm_resume_cpu(bsp);
        mevent_dispatch();                       /* main thread forever */
}
```

There are several useful observations in this small excerpt:

* Host resources must be opened before `caph_enter()`. This shapes hotplug and
  external-backend design.
* Devices are constructed before normal vCPU execution. Guest hardware is a
  startup-time object graph, even though the implementation does not call it
  that.
* vCPUs are separate threads, while the original thread becomes the event
  reactor.
* “Platform late” exists because firmware tables need resource assignments that
  are only known after PCI initialization.
* Failure is mostly fail-fast. A device initialization error prevents the VM
  from running instead of leaving a partially constructed guest.

When debugging an early boot failure, identify which of these boundaries was
last crossed. A failure before `init_pci()` is not a VirtIO queue bug; a failure
after driver binding probably is not boot-ROM allocation.

### 3.1 How a PCI device type registers

A device model provides a `struct pci_devemu`
(`usr.sbin/bhyve/pci_emul.h:54`). The important callbacks are:

* `pe_init` to create an instance;
* optional legacy-option conversion;
* optional ACPI DSDT generation;
* PCI configuration-space read/write;
* BAR read/write and address-change callbacks; and
* optional snapshot, pause, and resume callbacks.

The descriptor is placed in a linker set with `PCI_EMUL_SET`. At startup,
`pci_emul_finddev()` walks the set and matches the configured device name
(`usr.sbin/bhyve/pci_emul.c:1127`). Device source files therefore do not need a
central registry edit beyond being linked into the binary.

### Code walk: the smallest recognizable PCI device model

This illustrative skeleton shows the shape every in-process PCI device follows.
It is deliberately incomplete: production code must initialize PCI identity,
BARs, interrupts, locking, cleanup, reset, and malformed-access handling.

```c
struct demo_softc {
        uint32_t control;
        uint32_t status;
};

static int
demo_init(struct pci_devinst *pi, nvlist_t *nvl)
{
        struct demo_softc *sc;

        sc = calloc(1, sizeof(*sc));
        if (sc == NULL)
                return (ENOMEM);
        pi->pi_arg = sc;

        pci_set_cfgdata16(pi, PCIR_VENDOR, 0x1234);
        pci_set_cfgdata16(pi, PCIR_DEVICE, 0x0001);
        pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_SIMPLECOMM);

        if (pci_emul_alloc_bar(pi, 0, PCIBAR_MEM32, 4096) != 0) {
                free(sc);
                return (ENXIO);
        }
        return (0);
}

static uint64_t
demo_read(struct pci_devinst *pi, int bar, uint64_t off, int size)
{
        struct demo_softc *sc = pi->pi_arg;

        if (bar != 0 || size != 4)
                return (UINT64_MAX);
        switch (off) {
        case 0x00: return (sc->control);
        case 0x04: return (sc->status);
        default:   return (UINT32_MAX);
        }
}

static void
demo_write(struct pci_devinst *pi, int bar, uint64_t off, int size,
    uint64_t value)
{
        struct demo_softc *sc = pi->pi_arg;

        if (bar != 0 || size != 4)
                return;
        if (off == 0x00)
                sc->control = (uint32_t)value;
}

static const struct pci_devemu demo = {
        .pe_emu = "demo",
        .pe_init = demo_init,
        .pe_barread = demo_read,
        .pe_barwrite = demo_write,
};
PCI_EMUL_SET(demo);
```

The final macro puts a pointer in the `pci_devemu_set` linker set. A
configuration containing `device=demo` can then find it by name. The model is
closer to a static plugin registry than to a loadable plugin: registration is
modular, but the code is linked into the bhyve binary.

The example also shows a security rule: BAR offset, width, and access direction
are guest-controlled input. Validate them before indexing a structure, shifting
a value, calculating a range, or starting backend work.

### 3.2 How a configured instance is created

`init_pci()` walks hierarchical nodes named `pci.<bus>.<slot>.<function>`
(`usr.sbin/bhyve/pci_emul.c:1520`). For each node it:

1. obtains the `device` string;
2. finds the registered `pci_devemu`;
3. allocates a `pci_devinst`;
4. initializes its bus/slot/function, config space, interrupt state, and lock;
5. invokes `pe_init` with the device's nvlist;
6. performs a later pass to allocate I/O and 32/64-bit MMIO BAR resources;
7. initializes backends before final INTx routing;
8. routes interrupts and records boot order; and
9. registers PCI memory ranges with the MMIO dispatcher.

Initialization is static and front-loaded. There is no generic object graph,
transactional hotplug, or device lifecycle bus comparable to QEMU's QOM/qdev.
Some individual backends can detect changes such as resized media, but this is
not general device hotplug.

### 3.3 Configuration model

Modern bhyve configuration is a hierarchical nvlist whose leaf values are
strings (`usr.sbin/bhyve/config.c`, `bhyve_config(5)`). Legacy command-line
syntax is translated into the same tree.

This is simple and scriptable, but not a strong schema:

* unknown variables are intentionally ignored (`bhyve_config.5:38-44`);
* values are converted from strings at their consumers;
* initialization failures can occur late, after other resources have opened;
* the implementation contains acknowledged casts around nvlist immutability
  (`config.c:66-95`); and
* there is no built-in transactional configuration or versioned management API.

For an appliance, a supervising service should validate a strict product schema
before invoking bhyve and should treat bhyve's native config as an internal
execution format.

## 4. vCPU execution and VM exits

### 4.1 One pthread per vCPU

`fbsdrun_addcpu()` activates and suspends a kernel vCPU, then creates a pthread
(`bhyverun.c:570-589`). The thread names itself `vcpu N`, applies an optional
cpuset affinity, registers with checkpoint/GDB support, and calls `vm_loop()`.

The core loop is short (`bhyverun.c:625-665`):

```text
forever:
    ioctl(VM_RUN)
    inspect vm_exit.exitcode
    call userspace exit handler
    continue, abort, or terminate
```

This is a strong design for predictability. The FreeBSD scheduler sees real
host threads. Pinning, priority, accounting, and CPU isolation can use normal
host mechanisms. There is no hidden green-thread scheduler between a vCPU and
the host scheduler.

The cost is also clear: every active vCPU consumes a host thread, and a device
callback invoked from that thread can delay that vCPU. Scaling is primarily a
host scheduler and kernel VMM problem rather than an internal runtime scheduler
problem.

### Code walk: the vCPU thread is the hypervisor's heartbeat

The essential loop is almost exactly as small as the conceptual version. This
is condensed from `bhyverun.c:625-665`:

```c
static void
vm_loop(struct vmctx *ctx, struct vcpu *vcpu)
{
        struct vm_exit vme;
        struct vm_run vmrun;
        cpuset_t destination_cpus;

        vmrun.vm_exit = &vme;
        vmrun.cpuset = &destination_cpus;
        vmrun.cpusetsize = sizeof(destination_cpus);

        for (;;) {
                if (vm_run(vcpu, &vmrun) != 0)
                        break;

                if (vme.exitcode >= VM_EXITCODE_MAX ||
                    vmexit_handlers[vme.exitcode] == NULL)
                        errx(1, "unexpected VM exit");

                switch (vmexit_handlers[vme.exitcode](ctx, vcpu, &vmrun)) {
                case VMEXIT_CONTINUE:
                        break;
                case VMEXIT_ABORT:
                        abort();
                default:
                        exit(BHYVE_EXIT_ERROR);
                }
        }
}
```

And the library side of `vm_run()` is one ioctl
(`lib/libvmmapi/vmmapi.c:811-815`):

```c
int
vm_run(struct vcpu *vcpu, struct vm_run *vmrun)
{
        return (vcpu_ioctl(vcpu, VM_RUN, vmrun));
}
```

This is the kernel/userspace seam in its clearest form. While `VM_RUN` is
blocked, the host thread is executing guest code or waiting inside the kernel
VMM. When it returns successfully, `vme` explains what userspace must do.

It also explains an important performance diagnostic. High host CPU consumption
inside `vm_run` may be productive guest work. High time in a userspace exit
handler is emulation overhead. High sleep time behind a device lock may be a
backend design problem. These cases require different measurements even though
they all appear under one bhyve process.

### 4.2 What causes userspace exits

Hardware execution exits for privileged instructions, selected MSRs, port I/O,
unhandled MMIO, halt/pause policy, debug conditions, shutdown/reset, and other
architecture events. The kernel resolves exits that it can handle completely
and returns policy/device exits to bhyve.

Userspace dispatches exit codes through architecture-specific handler tables.
On amd64 that includes I/O-port emulation, MMIO instruction emulation, MSR
handling, AP spin-up, task switching for legacy cases, debug, suspension, and
VM termination. Device-facing MMIO ultimately reaches the memory-range handler
registered by PCI or platform code.

### 4.3 MMIO dispatch

`usr.sbin/bhyve/mem.c` stores memory ranges in red-black trees protected by an
rwlock and keeps a per-vCPU lookup hint (`mem.c:51-71`). An access performs a
cached or tree lookup and calls the registered handler (`mem.c:168-230`).

This is efficient and compact, but it is synchronous. The handler runs in the
context of the vCPU pthread processing the VM exit. Device implementations must
validate guest-controlled offsets and lengths, keep register operations short,
and defer potentially blocking work. A device that performs host I/O directly
from a BAR callback can stall guest execution on that vCPU and can create lock
ordering problems with other vCPU or event threads.

### Code walk: one MMIO write from guest to device

The generic dispatcher keeps the device callback independent of the tree used
to find it. The core call in `mem.c:156-164` is effectively:

```c
static int
mem_write(struct vcpu *vcpu, uint64_t gpa, uint64_t value,
    int size, void *arg)
{
        struct mem_range *mr = arg;

        return (mr->handler(vcpu, MEM_F_WRITE, gpa, size, &value,
            mr->arg1, mr->arg2));
}
```

For PCI MMIO, the registered handler determines which BAR contains the GPA,
converts it to a BAR-relative offset, and calls `pe_barwrite`. The complete path
is therefore:

```text
guest store instruction
  -> hardware nested-page exit
  -> kernel VM exit record
  -> userspace MMIO instruction emulation
  -> mem.c range lookup
  -> PCI BAR routing
  -> device pe_barwrite callback
  -> update state or enqueue work
  -> VM_RUN again
```

The callback must not retain the pointer to the stack `value`, must not trust
`size`, and must not assume accesses are naturally aligned unless the device
specification and dispatcher enforce it. Tests should deliberately issue byte,
word, dword, misaligned, boundary-crossing, and invalid-offset accesses.

## 5. Is bhyve asynchronous?

The precise answer is: **partly, by several mechanisms**.

### 5.1 The kqueue reactor

The original process thread becomes the `mevent` dispatcher after VM startup.
`mevent_dispatch()` creates a kqueue, installs an internal nonblocking pipe used
by other threads to wake it, and blocks in `kevent()`
(`usr.sbin/bhyve/mevent.c:496-564`).

The reactor supports readable, writable, timer, signal, and vnode events.
Callbacks are used by:

* tap/vmnet/netmap/netgraph/slirp receive paths;
* UART sockets and TTYs;
* VirtIO console sockets;
* VirtIO input host evdev input;
* vsock listeners, connections, writable backpressure, and reap timers;
* GDB sockets;
* block-device resize notification;
* virtual RTC timers; and
* power-button and other signals.

This avoids a polling thread for every descriptor and is a natural FreeBSD
design.

### Code walk: attaching a nonblocking backend to `mevent`

The interface is intentionally small (`mevent.h:32-60`):

```c
struct mevent *mevent_add(int fd, enum ev_type,
    void (*callback)(int, enum ev_type, void *), void *arg);
int mevent_enable(struct mevent *);
int mevent_disable(struct mevent *);
int mevent_delete_close(struct mevent *);
```

An illustrative readable backend looks like this:

```c
struct backend {
        int fd;
        struct mevent *event;
        struct device_softc *device;
};

static void
backend_readable(int fd, enum ev_type type, void *arg)
{
        struct backend *be = arg;
        uint8_t buf[4096];
        ssize_t n;

        assert(type == EVF_READ);
        for (;;) {
                n = read(fd, buf, sizeof(buf));
                if (n > 0) {
                        device_receive(be->device, buf, (size_t)n);
                        continue;
                }
                if (n < 0 && errno == EINTR)
                        continue;
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                        return;
                backend_disconnect(be);          /* EOF or fatal error */
                return;
        }
}

static int
backend_start(struct backend *be)
{
        if (fcntl(be->fd, F_SETFL, O_NONBLOCK) == -1)
                return (-1);
        be->event = mevent_add(be->fd, EVF_READ, backend_readable, be);
        return (be->event == NULL ? -1 : 0);
}
```

Real code must preserve existing file flags when enabling nonblocking mode,
limit descriptor rights before capability entry, and coordinate deletion with
other threads. The important pattern is that a callback drains work until
`EAGAIN` and then returns. Blocking for the next byte would freeze every other
callback sharing the main event thread.

For output backpressure, keep unsent bytes in a bounded buffer, enable an
`EVF_WRITE` event, write until complete or `EAGAIN`, then disable the event.
vsock is a useful in-tree example because it must not block a vCPU thread on a
slow host peer.

### 5.2 Dedicated workers

Several subsystems cannot or do not use only the reactor:

* Every vCPU has a pthread.
* Every opened `block_if` backend creates **eight worker threads** and queues up
  to 128 pending requests plus active workers (`block_if.c:67-119,
  661-670`). Its completion callback may run synchronously or on a worker
  (`block_if.h:29-33`).
* VirtIO-net creates one transmit thread and explicitly advertises only one
  queue pair (`pci_virtio_net.c:625-670`). Receive readiness comes from
  `mevent`.
* e1000 has a transmit thread and interrupt moderation timers.
* VirtIO-SCSI creates command workers.
* HDA codecs create audio threads; the OSS backend performs host `/dev/dsp`
  reads and writes.
* NVMe creates an asynchronous-event thread.
* TPM CRB creates a worker.
* RFB uses listener/output workers.
* Snapshot support adds checkpoint coordination threads.

### Code walk: asynchronous completion changes ownership

The block interface documents a subtle contract: a completion callback may run
before the submit function returns or later on a worker thread. A safe caller
must make request storage survive both possibilities.

```c
struct disk_request {
        struct blockif_req req;          /* submitted object, not stack-local */
        struct virtqueue_request guest;
        struct disk_softc *sc;
};

static void
disk_done(struct blockif_req *req, int error)
{
        struct disk_request *dr;

        dr = __containerof(req, struct disk_request, req);

        pthread_mutex_lock(&dr->sc->mtx);
        write_guest_status(dr, error);   /* validate writable status buffer */
        vq_relchain(dr->guest.vq, dr->guest.head,
            dr->guest.bytes_written);
        vq_endchains(dr->guest.vq, 0);
        recycle_request(dr);
        pthread_mutex_unlock(&dr->sc->mtx);
}

static int
submit_read(struct disk_request *dr)
{
        dr->req.br_callback = disk_done;
        dr->req.br_param = dr;
        return (blockif_read(dr->sc->bc, &dr->req));
}
```

This is illustrative, but the lifetime rule is real. A stack-allocated request
would become a use-after-return when a worker completes it. Reset and snapshot
add another question: who owns the request while the device is pausing, and how
does cancellation race with completion? A common future async framework should
make states such as free, queued, executing, completing, cancelled, and drained
explicit.

### 5.3 Consequences

The positive consequences are:

* guest CPUs do not normally wait for disk syscalls;
* socket and network receive paths are naturally readiness driven;
* host scheduling tools can see and place important workers; and
* the code for each device is relatively self-contained.

The negative consequences are:

* there is no common async request/executor abstraction for all devices;
* thread count grows quickly with disks and device choices;
* completion context differs by subsystem;
* backpressure, cancellation, pause, reset, and drain semantics are repeated;
* locks and callbacks cross vCPU, event, and device-worker contexts; and
* performance tuning is per device rather than a coherent runtime policy.

Calling bhyve “event-driven” is true for its descriptor reactor but incomplete
for the process as a whole. Calling it “thread-per-device” is also incomplete.
It is a pragmatic hybrid.

# Part III — The virtual machine

This part inventories the virtual hardware presented to a guest and the host
services behind it.

## 6. Interrupts, timers, and PCI

On amd64 the kernel provides virtual LAPIC, IOAPIC, legacy PIC, PIT, HPET, RTC,
and PM timer support. Userspace PCI code provides INTx routing, MSI, and MSI-X.
Device models assert or deassert lines or generate message-signaled interrupts
through `libvmmapi` calls into the kernel.

PCI emulation includes:

* conventional PCI config access and extended configuration space;
* multiple buses, slots, and functions;
* 32-bit and 64-bit MMIO BAR allocation and I/O BARs;
* MSI and MSI-X capability construction and delivery;
* PCI boot-order publication through `fw_cfg`;
* host and AMD host bridge identities;
* option ROM mapping; and
* passthrough-specific BAR and interrupt handling.

The model is intentionally a relatively simple virtual PC, not the enormous
set of chipsets and board versions QEMU maintains. That limits compatibility
testing choices but reduces code and machine-type complexity.

## 7. Firmware, boot, and machine description

bhyve supports UEFI/boot-ROM boot. On amd64 it can also use a VM context
prepared by `bhyveload`. It builds or supplies:

* ACPI tables;
* SMBIOS tables;
* E820 memory map;
* Intel MP table where required;
* QEMU-compatible `fw_cfg` entries and boot order;
* VM Generation ID; and
* optional device ACPI descriptions.

arm64 and RISC-V describe their virtual platform with flattened device trees.

QEMU has a much broader firmware and board ecosystem: many PC machine versions,
many non-PC boards, pflash and firmware integration, and extensive compatibility
machinery. bhyve's narrower machine is a strength for a controlled appliance
image, but a weakness for arbitrary legacy guests and long-lived cross-version
machine compatibility.

## 8. Device and backend inventory

The definitive common build list is in `usr.sbin/bhyve/Makefile:17-74`, with
architecture additions in each `Makefile.inc`.

### 8.1 Storage devices

Guest-facing storage models:

* AHCI controller, hard disk, and CD-ROM;
* NVMe controller/namespaces;
* VirtIO block;
* VirtIO SCSI, using FreeBSD CTL/CAM support; and
* 9P filesystem export over VirtIO.

The common `block_if` backend accepts regular files, character/raw devices, and
GEOM providers. It supports read-only mode, direct/nocache and synchronous I/O
options, logical/physical sector sizing, flush, delete/TRIM where the backend
allows it, cancellation, queue limits, and resize notification.

Important limits versus QEMU:

* no comparable graph-based block layer;
* no built-in qcow2 implementation, backing-chain graph, copy-on-write jobs,
  block commit/mirror/stream, or broad image/protocol format collection;
* no uniform I/O throttling and block-job control plane;
* fixed worker design rather than selectable io_uring/Linux AIO/thread/native
  backend strategies;
* no general storage daemon protocol; and
* no integrated migration of a complex storage graph.

FreeBSD and ZFS can supply snapshots, clones, checksums, compression,
replication, and volume management below bhyve, which is often the correct
appliance architecture. But filesystem/volume snapshots alone do not capture
CPU, RAM, in-flight I/O, and device state. Storage snapshotting and VM state
must be coordinated for a consistent suspend/resume product.

### 8.2 Network devices and backends

Guest-facing NICs:

* Intel e82545/e1000 emulation; and
* VirtIO network.

Host backends:

* tap;
* vmnet and ngd tap-like devices;
* netgraph;
* netmap and VALE;
* slirp user-mode networking.

This is a strong FreeBSD integration point. netmap/VALE can provide high packet
rates, netgraph provides composable kernel networking, and tap integrates with
ordinary bridges and firewalls.

The principal VirtIO-net limitation is explicit in the code: maximum queue
pairs is one, and only one transmit worker is created
(`pci_virtio_net.c:625-670`). There is no modern transport for VirtIO-net in
this tree, no mature vhost-net/vhost-user fast path, and much less offload,
RSS, control-queue, rate-control, and migration machinery than the
KVM+QEMU ecosystem.

For small numbers of appliance VMs, direct netmap/VALE integration can be very
effective. For many-core Linux/Android guests, multi-queue VirtIO-net and a
backend interface that allows queue processing outside the main bhyve process
are foundational scaling work.

### 8.3 VirtIO devices

This tree contains:

* `virtio-9p`
* `virtio-blk`
* `virtio-console`
* `virtio-input`
* `virtio-net`
* `virtio-rnd`
* `virtio-scsi`
* `virtio-vsock`

The generic implementation uses split virtqueues, validates direct and
indirect descriptor chains, maps guest buffers, publishes used entries, and
supports event-index interrupt suppression. It supports legacy PCI transport
and now contains a non-transitional modern PCI transport implementation.

In the reviewed tree, transport availability is:

| Device | Legacy PCI | Modern non-transitional PCI | Important note |
|---|---:|---:|---|
| random | yes | yes | host `/dev/random` backend |
| input | yes, historical identity | yes | upstream Linux binds the modern identity; host evdev source and status queue |
| vsock | yes | yes | host Unix-socket/control model |
| block | yes | no | core appliance gap |
| network | yes | no | single queue pair |
| console | yes | no | core management gap |
| SCSI | yes | no | CTL-backed |
| 9P | yes | no | host directory export |

The modern transport implements the required VirtIO 1.x PCI capabilities,
64-bit feature negotiation, queue address/enable/configuration state,
non-transitional identities, split-ring `INDIRECT_DESC`, `EVENT_IDX`, and
mandatory `VERSION_1` (`virtio_pci_modern.c:29-67`). It does **not** make bhyve
fully VirtIO 1.4-complete. Notable generic or ecosystem gaps include:

* packed virtqueues;
* notification data and other optional transport optimizations;
* queue reset/ring reset support where useful;
* administrative virtqueues and newer transport facilities;
* shared-memory regions and device-specific modern extensions;
* complete modern conversion of existing devices;
* broad multi-queue support;
* a generic external backend protocol; and
* stable snapshot state for modern devices.

The existing VirtIO snapshot serializer explicitly rejects modern transport
with `EOPNOTSUPP` because it serializes only legacy state
(`usr.sbin/bhyve/virtio.c:970-983`).

### Code walk: one VirtIO-random request

VirtIO-random is small enough to show the complete data-plane idea. On the
guest side, the driver conceptually does this:

```c
/* Guest-kernel pseudocode. Addresses written to the ring are guest physical. */
desc[head].addr = guest_physical_address(random_buffer);
desc[head].len = sizeof(random_buffer);
desc[head].flags = VRING_DESC_F_WRITE;   /* device may write this buffer */

avail->ring[avail->idx % queue_size] = head;
memory_barrier();                        /* descriptor before published index */
avail->idx++;
notify_device(queue_number);
```

The bhyve device callback in `pci_virtio_rnd.c:104-150` is approximately:

```c
static void
pci_vtrnd_notify(void *vsc, struct vqueue_info *vq)
{
        struct pci_vtrnd_softc *sc = vsc;
        struct iovec iov;
        struct vi_req req;
        ssize_t len;
        int n;

        while (vq_has_descs(vq)) {
                n = vq_getchain(vq, &iov, 1, &req);
                if (n <= 0)
                        break;

                /* Entropy device accepts exactly one writable buffer. */
                if (n != 1 || req.readable != 0 || req.writable != 1 ||
                    iov.iov_base == NULL || iov.iov_len == 0) {
                        vq_relchain(vq, req.idx, 0);
                        continue;
                }

                len = read(sc->vrsc_fd, iov.iov_base, iov.iov_len);
                if (len <= 0) {
                        vq_relchain(vq, req.idx, 0);
                        break;
                }
                vq_relchain(vq, req.idx, (uint32_t)len);
        }
        vq_endchains(vq, 1);
}
```

`vq_getchain()` is doing more security work than the small callback suggests.
It verifies the available count, bounds direct indices, checks that indirect
descriptors were negotiated, validates indirect table sizes and next indices,
bounds traversal to 512 descriptors, rejects nested indirect descriptors, and
maps every buffer wholly inside guest memory (`virtio.c:303-442`).

The device must still enforce its own contract. Generic parsing cannot know
that random requires writable rather than readable memory, that a block request
needs a header/data/status order, or that a status descriptor must have a
particular length.

Completion also has ordering requirements. `vq_relchain()` writes the used-ring
entry, executes a release fence, and publishes the used index. `vq_endchains()`
then applies a full barrier and decides whether `EVENT_IDX`, suppression flags,
or notify-on-empty require an interrupt (`virtio.c:459-562`). Without these
barriers, a weakly ordered host CPU could let the guest observe the new index
before the completed data.

### Code walk: selecting legacy or modern PCI transport

The random-device initialization demonstrates how compatibility is preserved:

```c
vi_softc_linkup(&sc->vrsc_vs, &vtrnd_vi_consts, sc, pi, &sc->vrsc_vq);
sc->vrsc_vq.vq_qsize = VTRND_RINGSZ;

if (vi_pci_select_transport(&sc->vrsc_vs, nvl,
    VIRTIO_PCI_LEGACY_DEFAULT) != 0)
        goto failed;

if (vi_pci_is_modern(&sc->vrsc_vs))
        vi_pci_modern_set_identity(&sc->vrsc_vs, VIRTIO_ID_ENTROPY);
else
        set_historical_pci_identity(pi);

vi_intr_init(&sc->vrsc_vs, 1, fbsdrun_virtio_msix());
if (vi_pci_is_modern(&sc->vrsc_vs))
        vi_pci_modern_init(&sc->vrsc_vs, 2);
else
        vi_set_io_bar(&sc->vrsc_vs, 0);
```

Legacy remains the default so an existing bhyve command line sees the same PCI
identity and register interface. `transport=modern` is opt-in. This is the
correct compatibility shape for converting block, network, console, and SCSI:
share device semantics and queues, select transport explicitly, and test both
paths rather than silently changing existing guests.

Missing VirtIO device types that matter to Linux/Android appliance workloads
include:

* **virtio-fs** for coherent host/guest file sharing;
* **virtio-gpu** for a modern display path and possible accelerated rendering;
* **virtio-snd** for a paravirtual audio path;
* **virtio-balloon** for cooperative memory reclaim and reporting;
* **virtio-mem** for finer-grained memory hotplug/reclaim;
* **virtio-iommu** for guest-visible DMA isolation/topologies;
* **virtio-pmem** for persistent-memory semantics; and
* specialized devices such as GPIO/I2C/SCMI only if the product has a concrete
  embedded use case.

9P exists, but virtio-fs is generally a better foundation for Linux application
domains because it is built around FUSE semantics and cache coherency rather
than the older Plan 9 protocol. Implementing virtio-fs also implies designing a
separate, sandboxed filesystem daemon and a shared-memory mapping model; merely
adding a PCI ID and queues would not create a safe filesystem service.

### 8.4 Console and serial

bhyve supports legacy UARTs backed by stdio, TTYs, files, or sockets, PCI UART,
and VirtIO console with socket endpoints. Console and serial paths are
important operationally because they remain available when networking or the
guest graphical stack fails.

For a product, these endpoints still need a supervisor that owns access
control, log rotation, reconnection, multiplexing, and audit policy. bhyve
provides the transport endpoints, not a complete console service.

### 8.5 Graphics, input, and USB

amd64 supports a framebuffer device with RFB/VNC output, VGA-related support,
PS/2 keyboard/mouse, xHCI, and USB mouse/tablet emulation. The USB device model
inventory is narrow: the registered USB emulation is essentially the mouse or
tablet path, not QEMU's broad USB controller/device ecosystem.

VirtIO-input now provides a modern Linux-compatible input device backed by a
host evdev device. Events flow host provider -> host evdev -> bhyve -> VirtIO
event queue -> Linux input subsystem. Guest status events, such as LEDs, flow
back through the VirtIO status queue -> bhyve -> host evdev state.

Graphics remains a major Android/product gap. The framebuffer/RFB path is fine
for installation, diagnostics, and low-rate desktop access. It is not a modern
GPU virtualization stack. A useful Android UI architecture would need a
decision among:

* virtio-gpu with a software renderer;
* virtio-gpu plus virgl/venus or another accelerated renderer in a sandboxed
  service;
* whole-GPU or mediated passthrough where hardware and isolation permit; or
* guest-rendered application surfaces exported through an explicit product
  compositor protocol.

The last option may fit an appliance better than trying to recreate a general
desktop hypervisor, but it is a product architecture decision, not something
VirtIO solves by itself.

### 8.6 Audio

bhyve emulates Intel HDA and connects playback/recording to FreeBSD OSS
`/dev/dsp`. Codec contexts use worker threads because host audio I/O can block.

This can provide conventional guest audio, but it is not an end-to-end
real-time audio service. Low-latency, glitch-resistant audio requires:

* bounded buffering and scheduling latency;
* sample-rate/format negotiation and conversion policy;
* clock-domain and drift handling;
* mixing, routing, focus, ducking, and per-application policy;
* device hotplug and route changes;
* security/consent for microphones;
* suspend/resume state; and
* observability of underruns, overruns, and latency.

Those are audio-service responsibilities. A virtio-snd device could be the
guest transport while a host daemon supplies policy and hardware access.
Alternatively, Linux could own much of the audio stack and export carefully
defined streams or controls to the FreeBSD system layer. In either direction,
the hypervisor should transport data and state; it should not become the audio
policy engine.

### 8.7 vsock

VirtIO-vsock supplies host/guest `SOCK_STREAM` and `SOCK_SEQPACKET` transport.
The implementation uses nonblocking Unix sockets, a control endpoint,
per-connection readiness events, buffering/backpressure, and resource limits.
It also contains DTrace USDT probes in this tree.

vsock should remain a transport rather than a mandatory product RPC protocol.
Applications can choose stream framing or preserve records with seqpacket.
Being on one host reduces network failure modes but does not remove application
requirements for authentication, authorization, timeouts, versioning, bounds,
and restart semantics. Those should be added when a concrete service exists,
not invented as a universal hypervisor protocol.

### 8.8 Random number device

VirtIO-random reads host entropy and fills guest-provided writable buffers. The
backend limits descriptor rights and contains validation/error handling for bad
chains, failed reads, EOF, and unavailable entropy. It is a small but essential
Linux/Android boot and cryptographic service.

For production, entropy provenance and blocking policy are host security
decisions. The virtual device should not pretend that statistical test output
proves cryptographic entropy quality.

### 8.9 TPM

bhyve provides a TPM 2.0 CRB interface with either:

* passthrough to a host TPM device; or
* an `swtpm` backend.

A worker separates potentially blocking TPM operations from vCPU MMIO. This is
useful for measured boot, sealed secrets, and guest identity, but a product also
needs persistent TPM-state lifecycle, backup policy, anti-rollback design,
firmware measurement consistency, and snapshot/restore semantics.

### 8.10 PCI passthrough

On amd64, physical PCI functions can be assigned to a guest through the `ppt`
kernel/IOMMU path. bhyve maps ordinary MMIO BAR portions into the guest,
emulates sensitive config and MSI-X table accesses, and configures interrupt
remapping. The backend limits `/dev/pci` ioctls under Capsicum
(`pci_passthru.c:134-164`).

Passthrough is one of bhyve's strongest appliance capabilities because it can
give Linux direct ownership of hardware whose stack FreeBSD should not need to
reimplement: GPUs, accelerators, specialty NICs, USB controllers, storage
controllers, radios behind a suitable PCI function, and vendor devices.

Its constraints are fundamental:

* isolation granularity is the host IOMMU group/function reality;
* reset behavior must be reliable;
* the device is generally unavailable to the host while assigned;
* suspend, snapshot, and live migration are usually unavailable without
  device-specific support;
* interrupt and DMA bugs cross a larger trust boundary; and
* consumer hardware often has poor reset or isolation behavior.

Passing through an entire USB controller is often more practical than adding
many emulated USB device types, but it reduces flexibility and migration.

### 8.11 What “host driver” and “guest driver” mean here

There are three different pieces that are easy to call a driver:

1. The **physical host driver** makes a real FreeBSD resource available: for
   example evdev/uinput, tap/netmap, OSS, GEOM, TPM, or `ppt`/IOMMU.
2. The **bhyve device model** implements the guest-visible PCI/VirtIO/AHCI/NVMe
   device and translates its operations to a backend.
3. The **guest driver** runs inside Linux, Android, FreeBSD, or another guest
   and speaks that virtual hardware protocol.

bhyve does not ship Linux or Android guest drivers. For standard devices it
relies on the drivers in the guest kernel. That is why PCI identity, transport
generation, negotiated features, and conformance matter: code can implement a
historical bhyve interface yet remain invisible to an upstream Linux driver, as
with the historical VirtIO-input identity. The modern non-transitional identity
binds to Linux's standard `virtio_input` driver.

FreeBSD contains its own guest VirtIO drivers under `sys/dev/virtio/`; those are
separate from bhyve's userspace host-side device implementations. Conventional
emulations such as e1000, AHCI, HDA, NVMe, UART, and xHCI similarly use the
guest's ordinary hardware drivers.

With PCI passthrough, most of the bhyve device model disappears from the data
path. The host `ppt`/IOMMU code assigns and isolates the function, and the Linux
guest loads the real vendor driver. That is the main mechanism by which a Linux
service VM can supply a hardware stack that FreeBSD does not have. Communication
back to the FreeBSD system domain is then a separate service interface, often
vsock or networking; the passed-through hardware protocol itself is not
bidirectional VirtIO.

# Part IV — Trust and time

This part treats security, durable state, observability, and nested
virtualization as properties of the whole runtime rather than isolated options.

## 9. Security architecture

bhyve's security posture has two distinct boundaries.

### 9.1 Kernel boundary

The guest can attack hardware virtualization configuration, instruction
emulation, virtual interrupt controllers/timers, guest-memory mapping, and
passthrough/IOMMU code in the kernel. This is the most privileged boundary and
must stay small, defensive, and heavily tested.

Keeping most device models out of the kernel is a major architectural strength.

### 9.2 Userspace capability boundary

Before guest execution proceeds normally, bhyve opens required resources,
reduces descriptor rights, and enters Capsicum capability mode
(`bhyverun.c:1047-1054`). Rights are explicitly limited for the VM descriptor,
block files, network descriptors, audio, UART, random, input, console/vsock
sockets, passthrough, GDB/RFB listeners, and 9P directory roots.

This materially limits what a compromised bhyve process can open or name in the
host filesystem after startup. It is stronger than merely dropping a uid while
retaining a broad filesystem namespace.

### Code walk: capability-first resource setup

VirtIO-random shows the normal pattern (`pci_virtio_rnd.c:164-188`):

```c
fd = open("/dev/random", O_RDONLY | O_NONBLOCK);
if (fd < 0)
        return (1);

cap_rights_t rights;
cap_rights_init(&rights, CAP_READ);
if (caph_rights_limit(fd, &rights) == -1)
        err(1, "limit /dev/random rights");

/* Verify the resource is usable before committing the VM startup. */
if (read(fd, &one_byte, 1) != 1) {
        close(fd);
        return (1);
}
```

The VMM descriptor is reduced to mapping and a finite ioctl allowlist in
`libvmmapi`:

```c
int
vm_limit_rights(struct vmctx *ctx)
{
        cap_rights_t rights;

        cap_rights_init(&rights, CAP_IOCTL, CAP_MMAP_RW);
        if (caph_rights_limit(ctx->fd, &rights) != 0)
                return (-1);
        if (caph_ioctls_limit(ctx->fd, vm_ioctl_cmds,
            vm_ioctl_ncmds) != 0)
                return (-1);
        return (0);
}
```

Finally, `main()` calls `caph_enter()`. Capability rights are monotonic: the
process may reduce them further but cannot regain ambient access to arbitrary
paths. That is why a product should not solve hotplug by weakening capability
mode. Better patterns are:

* pre-open a bounded set of resources;
* receive an already-authorized descriptor from a narrow broker designed for
  that operation; or
* run the changing backend in a separately supervised process and reconnect it
  through a fixed endpoint.

Passing a descriptor transfers authority. The receiver does not need path
lookup permission, so the broker can enforce product policy while bhyve remains
in capability mode.

### 9.3 Remaining security limits

* All in-process devices share one address space and all mapped guest RAM.
* C memory-safety bugs in a device can corrupt unrelated device/runtime state.
* Capability mode limits ambient host authority but does not separate devices
  from one another.
* A backend descriptor may itself convey powerful authority, especially a raw
  disk, directory, tap, physical PCI function, or TPM.
* The kernel VMM and passthrough paths remain host-kernel attack surfaces.
* RFB, GDB, console, and control sockets need product-level authentication and
  exposure policy.

An external backend framework would improve both modularity and containment:
filesystem, GPU, audio, networking, and other complex parsers could run in
separate Capsicum processes with only queue memory, an interrupt channel, and
their specific resource descriptors.

## 10. Save, restore, snapshots, and migration

This is the largest lifecycle gap.

The tree has real scaffolding:

* `bhyvectl` checkpoint/suspend controls;
* `bhyve -r` restore support when compiled in;
* kernel vCPU and virtual-platform snapshot code;
* guest RAM save/restore;
* optional PCI device `pe_snapshot`, `pe_pause`, and `pe_resume` callbacks;
* a checkpoint coordination thread; and
* serializers for selected devices.

But the feature is not a production contract:

* `BHYVE_SNAPSHOT` is default-off (`share/mk/src.opts.mk:199-202`).
* It is marked broken on non-amd64 (`share/mk/src.opts.mk:384-386`).
* The manual says the file format is unstable and provides no future backward
  compatibility guarantee (`bhyvectl.8:101-104`).
* Devices without `pe_snapshot` return unsupported.
* Snapshot hooks exist only for a subset: AHCI, e1000, framebuffer, host/LPC
  bridge, xHCI, VirtIO block/network/random, and test plumbing.
* Modern VirtIO state is explicitly unsupported.
* External resources and connections need independent coordination.
* There is no iterative dirty-page precopy/postcopy migration engine, migration
  transport, destination handshake, compatibility negotiation, or stable
  machine/device version model.

### 10.1 Why process restart is not restore

Monitor mode can fork a child and recreate it after a guest reset. This is
useful crash/reboot supervision. It does not preserve RAM, CPU registers,
devices, timers, network connections, or application execution. It is not
snapshot, suspend-to-disk, or migration.

### 10.2 What production save/restore requires

A sound implementation needs:

1. **A versioned state schema.** Serialize the guest-visible device model, not
   raw C layouts or implementation pointers. Define compatibility rules.
2. **A complete device contract.** Every supported device must quiesce, drain
   or record in-flight work, serialize, validate restore input, and resume.
3. **Kernel state coverage.** vCPU, interrupt controllers, timers, pending
   events, architecture state, and guest time must be captured coherently.
4. **RAM tracking.** Stop-and-copy is enough for local suspend; live migration
   needs dirty-page tracking and iterative transfer.
5. **Storage coordination.** Flush/freeze policy and ZFS snapshot/clone state
   must align with VM state.
6. **External backend lifecycle.** Backends need identities, reconnect,
   quiesce, state transfer, and failure semantics.
7. **Resource compatibility.** CPU model, devices, firmware, queue features,
   passthrough constraints, and destination capabilities need negotiation.
8. **Untrusted-input restore.** A state file is a complex parser input and must
   be bounded, authenticated as appropriate, and fuzzed.
9. **Atomic product orchestration.** Partial snapshots must never be presented
   as valid appliance checkpoints.

### Design example: serialize a device model, not a C structure

A tempting snapshot implementation is:

```c
/* Wrong as a durable format. */
write(fd, sc, sizeof(*sc));
```

That captures padding, host endianness, mutex internals, pointers, file
descriptors, queue mappings, and whatever layout this compiler produced. It
cannot survive an implementation change and is unsafe to restore.

A durable design starts with an explicit envelope and guest-visible fields:

```c
/* Illustrative on-wire schema, not current bhyve API. */
struct state_header {
        uint8_t magic[8];
        uint32_t schema_version_be;
        uint32_t device_type_be;
        uint64_t payload_length_be;
        uint8_t payload_hash[32];
};

struct virtio_rng_state_v1 {
        uint64_t negotiated_features_be;
        uint8_t device_status;
        uint8_t isr_status;
        uint16_t queue_size_be;
        uint16_t last_avail_be;
        uint16_t next_used_be;
        uint8_t queue_enabled;
        /* Explicit transport addresses and bounded pending-state records. */
};
```

Restore should follow a transactional pattern:

```text
read bounded header
  -> validate magic, type, length, version, hash
  -> decode into temporary state with checked arithmetic
  -> verify compatibility with configured device and negotiated features
  -> reconstruct mappings/resources without exposing partial state
  -> atomically install decoded state
  -> resume only after every component commits
```

The schema needs subsections or feature-gated fields so a newer implementation
can add state without making older snapshots ambiguous. Backend resources such
as a disk or socket are referenced by product identity and re-established by
the supervisor; a serialized host file descriptor number has no meaning in a
new process.

QEMU is far ahead here. Its migration framework has version-aware VMState
descriptions, iterative RAM/device transfer, multiple transports, ordering,
compatibility conventions, postcopy and dirty-limit mechanisms, and device
migration integration. QEMU is not perfect—some devices and passthrough cases
still constrain migration—but it has a mature framework rather than isolated
serializers.

## 11. Debugging and observability

Available pieces include:

* vCPU/VMM statistics and descriptions through `libvmmapi`;
* `bhyvectl` state inspection and control;
* GDB remote debugging on amd64 and arm64;
* kernel DTrace/SDT facilities;
* userspace logs and device debug switches;
* RFB/serial consoles;
* VM generation IDs; and
* device-specific probes, including vsock USDT in this tree.

The weak point is uniformity. There is no stable per-VM event stream or schema
for queue depth, I/O latency, dropped packets, interrupt rate, exit rate,
blocked vCPU duration, worker saturation, audio underruns, backend disconnects,
memory pressure, and lifecycle transitions. Operators must combine process,
kernel, DTrace, log, and device-specific data.

For an appliance, build a management daemon that owns:

* a versioned API and desired-state model;
* VM lifecycle events and reason codes;
* metrics labeled by VM/device/queue;
* console and diagnostic log collection;
* health checks for backend processes;
* crash reports and retained exit context;
* resource admission, cpuset, NUMA, and memory policy; and
* explicit compatibility data for suspend/restore.

Instrumentation should be designed alongside the external-backend and state
protocols. Bolting metrics onto each device afterward will recreate the current
fragmentation.

## 12. Nested virtualization

### 12.1 Current answer: no

bhyve does not currently expose hardware virtualization to amd64 guests:

* AMD SVM is cleared from guest CPUID (`sys/amd64/vmm/x86.c:161-167`).
* Intel VMX is cleared from guest CPUID (`sys/amd64/vmm/x86.c:318-325`).
* reading AMD `MSR_VM_CR` reports `SVMDIS`, with the source comment “We
  currently don't support nested virt”
  (`usr.sbin/bhyve/amd64/xmsr.c:207-213`).

A bhyve guest therefore cannot use KVM, bhyve, Hyper-V, or another
hardware-assisted hypervisor as an L1 hypervisor to run an L2 guest. It can run
a pure software emulator such as QEMU TCG if the guest software and performance
requirements permit it.

The presence of handlers for VMX-instruction exits does not imply nested
virtualization. Without nesting, those exits exist so the L0 can reject or
handle guest execution of virtualization instructions safely.

The arm64 and RISC-V implementations use the host's virtualization level for
the L0 VMM and do not contain an equivalent complete nested-hypervisor
implementation in this tree.

### 12.2 Could it be implemented?

Yes in principle, but it is a major kernel virtualization project, not a small
CPUID change. Intel and AMD require substantially separate implementations.
Work includes:

* exposing and virtualizing VMX or SVM control state and MSRs;
* validating and emulating VMX instructions/VMCS or SVM instructions/VMCB;
* composing L1 and L0 EPT/NPT translations for L2 memory;
* virtualizing VPID/ASID and TLB invalidation semantics;
* composing exception, interrupt, APIC, and posted-interrupt behavior;
* nested entry/exit state machines and failure reporting;
* virtual timers and time scaling;
* debug/performance counter semantics;
* suspend/restore and eventually migration state;
* extensive hostile-L1 validation; and
* tests across CPU generations and L1 hypervisors.

KVM has mature nested VMX and SVM support; nested VMX has been enabled by
default for years. That implementation represents a large body of correctness,
security, and compatibility work. Unless running customer hypervisors or
container stacks that require nested KVM is a product requirement, bhyve
save/restore, external backends, and core VirtIO scaling offer much higher
near-term value.

# Part V — Perspective and limits

This part compares equivalent layers, separates ecosystem maturity from raw CPU
execution, and states the limits that matter in product planning.

## 13. bhyve versus KVM

| Area | FreeBSD vmm + libvmmapi | Linux KVM | Assessment |
|---|---|---|---|
| Basic model | device/ioctl VM and vCPU execution | `/dev/kvm`, VM/vCPU/device fds and ioctls | conceptually similar |
| Hardware acceleration | VMX/SVM; arm64 and RISC-V ports | broad architecture support | both execute guests in hardware; KVM broader/more mature overall |
| Userspace CPU run | `VM_RUN` ioctl | `KVM_RUN` ioctl with shared run structure | similar control loop |
| ABI contract | FreeBSD-specific, smaller ecosystem | documented stable ABI with capability discovery | KVM substantially stronger |
| Memory | VMM segments mapped into process; NUMA domains | memory slots, dirty logs/rings, many capabilities | bhyve simple; KVM much richer for migration and memory managers |
| In-kernel virtual devices | interrupt/timer core and passthrough support | irqchip plus vhost and many KVM devices/capabilities | KVM broader acceleration ecosystem |
| Nested virtualization | absent, VMX/SVM hidden | mature nested VMX/SVM | major bhyve gap |
| Confidential computing | no comparable production framework visible here | SEV/TDX and related APIs | KVM ahead |
| Ecosystem | bhyve/libvmmapi tools | QEMU, cloud-hypervisor, crosvm, Firecracker, rust-vmm, others | KVM far broader |
| Cross-version management | limited native contract | capability-based API used by multiple VMMs | KVM stronger |

KVM's deepest advantage is not merely faster VM entry. It is the stable,
capability-discoverable kernel ABI and the number of independently developed
userspace VMMs and backend technologies built around it.

bhyve/vmm's advantage is coherence with FreeBSD and a smaller system that can
be evolved as part of one appliance. It can use FreeBSD scheduling, networking,
storage, Capsicum, and tracing without translating Linux-specific APIs.

## 14. bhyve versus QEMU

| Area | bhyve | QEMU with KVM | Assessment |
|---|---|---|---|
| Scope | compact hardware VMM and selected devices | general machine emulator and virtualization runtime | QEMU intentionally much broader |
| CPU | hardware-assisted, same-ISA | KVM acceleration plus TCG software emulation | QEMU supports cross-ISA and no-HW fallback |
| Machine models | narrow virtual PC; smaller arm64/RISC-V platforms | many boards, chipsets, versioned machine types | QEMU compatibility breadth much greater |
| Device object model | linker-set PCI structs and callbacks | QOM/qdev object/bus/property model | bhyve simpler; QEMU more composable |
| Devices | server-focused subset | very large catalog | QEMU far broader |
| VirtIO | split rings, incomplete modern conversion/features | broad modern devices, vhost, vhost-user | QEMU far ahead |
| External devices | ad hoc external endpoints; no general framework | vhost-user, vfio-user, multi-process QEMU | major bhyve architecture gap |
| Block layer | raw/file/GEOM async backend | graph block layer, qcow2, jobs, filters, throttling, protocols | QEMU much richer |
| Network | strong FreeBSD backends; single-queue VirtIO-net | many backends, multiqueue, vhost acceleration | mixed: bhyve integrates well, QEMU scales/features better |
| Graphics | framebuffer/RFB, limited GVT-d/passthrough | many display devices, virtio-gpu, render backends | QEMU ahead |
| USB | xHCI plus mouse/tablet | broad controllers and USB devices/passthrough | QEMU ahead |
| Audio | HDA + OSS | multiple guest devices and host audio backends | QEMU broader; both need product policy outside VMM |
| Management | CLI/config, bhyvectl, external scripts | QMP, HMP, object introspection, events | QEMU far ahead |
| Hotplug | limited/no generic framework | broad device, CPU, memory, and backend hotplug | QEMU ahead |
| Save/restore | experimental and incomplete | mature snapshot/migration framework | largest bhyve gap |
| Security | small process, Capsicum and fd rights | larger attack surface; sandboxing and process separation options | bhyve has a strong base; external isolation still needed |
| Code complexity | comparatively small and direct | very large and complex | bhyve easier to audit/evolve for a fixed product |
| Deterministic placement | direct pthread/cpuset/NUMA model | extensive controls but larger runtime | bhyve is easy to reason about |

### 14.1 What QEMU's breadth buys

QEMU's device frontends are paired with stackable backends, a rich object model,
a machine protocol, versioned migration state, block jobs, external backend
protocols, and a very large compatibility/test community. That makes it a
platform on which management products can be built without modifying QEMU for
every lifecycle operation.

### 14.2 What bhyve's smallness buys

bhyve has less abstraction to traverse. A BAR write reaches an obvious
callback; a VirtIO queue is a small set of C structures; a vCPU is an ordinary
pthread; host resources are FreeBSD descriptors. For a controlled appliance
with a fixed guest hardware profile, this can mean lower cognitive load, a
smaller attack surface, more direct performance work, and tighter integration.

The danger is treating missing framework as simplicity forever. Once many
devices each invent workers, state, backend sockets, reconnection, metrics, and
configuration, local simplicity turns into system-wide inconsistency. The next
stage should add a few strong common abstractions without attempting to clone
all of QEMU.

## 15. Hard and practical limits

### 15.1 No cross-ISA or software execution fallback

bhyve is not a full system CPU emulator. It cannot run an ARM guest on amd64 or
an x86 guest on arm64, and it cannot fall back to interpretation when hardware
virtualization is unavailable. QEMU TCG can do those things, at much lower
performance.

### 15.2 Static topology and weak hotplug

CPU topology, RAM, PCI functions, and most backend resources are established
before Capsicum entry and guest start. This is secure and simple but makes
generic hotplug difficult. Adding hotplug requires a pre-opened broker or a
supervised external backend/resource service because a capability-mode process
cannot simply open arbitrary new host paths.

### 15.3 vCPU blocking exposure

Synchronous register/MMIO callbacks execute on a vCPU thread. Any blocking host
operation, oversized parse, contended lock, or expensive queue walk on that path
directly affects guest latency. Device review must distinguish control-plane
register work from deferred data-plane work.

### 15.4 Thread scaling

The fixed eight workers for each block backend are simple but can create many
threads for VMs with many disks. Conversely, single-thread/single-queue network
processing can underuse a large host. There is no unified executor that sizes
workers by VM/service policy.

### 15.5 Guest memory exposure to device code

All mapped guest RAM is in the bhyve process. This is fast, but external complex
backends should receive only the mappings and permissions they need, with
careful revocation and lifecycle rules.

### 15.6 Passthrough limits lifecycle

Passthrough can solve device-stack gaps immediately, but generally prevents
portable snapshots and migration. It also ties the VM to specific hardware and
reset behavior.

### 15.7 Feature parity is not standard conformance

Implementing the VirtIO 1.x PCI common configuration does not implement every
VirtIO 1.4 optional feature or every device. Conformance must be tracked per:

* transport;
* ring type and generic feature;
* device type;
* device-specific negotiated feature;
* reset/error behavior;
* endian/ordering rule;
* malformed descriptor behavior; and
* suspend/restore state.

### 15.8 Selected implementation limits

These constants describe this implementation, not a promise that every value is
practical or supported by every guest:

| Resource | Code limit/default | Consequence |
|---|---|---|
| Host memory domains per VM | `VM_MAXMEMDOM` = 8 (`sys/dev/vmm/vmm_mem.h:12`) | NUMA layouts have a fixed domain-count ceiling |
| vCPUs | hard ceiling is `min(65534, CPU_SETSIZE)`; runtime `hw.vmm.maxcpu` defaults to host `mp_ncpus` | requested topology is checked against the kernel VM maximum |
| PCI address space | 256 buses, 32 slots, 8 functions from PCI field widths | BAR windows and platform layout usually become practical constraints first |
| Generic VirtIO queue size | power of two, modern layer accepts up to 32768 | each device selects a much smaller fixed queue size |
| Descriptor chain traversal | at most 512 descriptors in the generic walker (`virtio.c:266`) | bounds malicious loops/work even when a queue is larger |
| VirtIO block queue | 128 entries | backed by the 128-request `block_if` pending ring |
| VirtIO network | one RX and one TX queue, 1024 entries each | no multi-queue scaling |
| VirtIO SCSI | 64 entries per queue | worker/request objects are preallocated |
| VirtIO console | 64 entries per queue | queue count derives from configured port maximum |
| VirtIO input/random | 64 entries per queue | intentionally small devices |
| VirtIO vsock | three queues, 256 entries each | RX, TX, and event queues |
| VirtIO 9P | one 256-entry queue | no multi-queue filesystem data plane |
| Block backend | eight workers, 128 pending requests, 128 iovecs/request | thread count grows per disk and request fan-out is bounded |
| NVMe queue entries | controller maximum 2048 | `maxq`, `qsz`, and `ioslots` are configurable within implementation checks |

Guest RAM has no single useful constant to quote here: effective limits depend
on architecture GPA width, VMM mappings, host virtual/physical memory, wiring,
NUMA placement, and product admission policy. An appliance should publish limits
it continuously tests rather than expose source-level maxima as a service
guarantee.

# Part VI — Building the appliance

This part turns the review into an engineering direction, operating examples,
and a test strategy for a FreeBSD system domain with Linux or Android
application domains.

## 16. Implications for a FreeBSD-system/Linux-application appliance

The target architecture can exploit bhyve rather than force it to become QEMU.

### 16.1 Keep roles explicit

```text
FreeBSD system domain
  hardware ownership, boot, policy, updates, storage, networking,
  resource admission, observability, recovery, VM supervision

Linux/Android application domains
  application ABI, ecosystem runtimes, media/framework stacks,
  selected hardware stacks, container engines where appropriate

Narrow transports
  virtio block/net/fs/gpu/snd/input/rng/vsock and PCI passthrough
```

VirtIO defines a guest driver/device protocol. It does not require all service
logic to live on the host side. A Linux service VM can own a complex stack and
export a narrow service back to FreeBSD. For example, Linux could own Bluetooth
HCI/controller policy, a GPU userspace stack, media codecs, or a vendor hardware
SDK. FreeBSD can pass through the hardware and communicate over vsock or shared
queues.

That is often better than writing an entire new host stack. But the ownership
choice has consequences:

* if Linux owns hardware by passthrough, FreeBSD cannot simultaneously own it;
* reset and recovery become VM lifecycle operations;
* early boot and safe-mode behavior need a fallback;
* suspend/update/state compatibility cross the service boundary; and
* the product protocol must include authorization and versioning.

### Practical example: launch a Linux appliance VM

This command illustrates the current mixed transport reality. It uses legacy
VirtIO block and network because those device models have not yet been converted,
while explicitly selecting modern random and vsock. Replace paths, tap setup,
firmware, and resource policy with product-owned values.

```sh
install -d -m 0700 /var/run/bhyve/linux-app

bhyve -c 4 -m 8G -H -w \
  -s 0,hostbridge \
  -s 2,virtio-blk,/zroot/vm/linux-app.raw \
  -s 3,virtio-net,tap0 \
  -s 4,virtio-rnd,transport=modern \
  -s 5,virtio-vsock,cid=42,path=/var/run/bhyve/linux-app,transport=modern \
  -s 31,lpc \
  -l com1,stdio \
  -l bootrom,/usr/local/share/uefi-firmware/BHYVE_UEFI.fd \
  linux-app
```

Important production differences from a shell example are:

* create the tap, storage object, socket directory, and firmware-variable copy
  through a privileged supervisor;
* do not expose serial, RFB, GDB, or control endpoints without access control;
* use a strict generated config rather than accepting arbitrary user fragments;
* set cpusets, NUMA domains, memory wiring, and limits from admission policy;
* capture stdout/stderr and the process exit reason; and
* clean up the kernel VM and ephemeral resources after every failure path.

To add modern VirtIO-input, a physical or uinput-created evdev device must exist
before bhyve starts:

```sh
bhyve ... \
  -s 6,virtio-input,path=/dev/input/event11,transport=modern \
  linux-app
```

Do not hard-code `event11` in a product. The provider should create the device,
discover the assigned event node, validate that it belongs to the intended
provider, pass it through a trusted launch description, and keep it alive for
the VM lifetime.

### Practical example: inspect the running layers

The following commands view different parts of the architecture:

```sh
# Kernel VM objects. A running VM named linux-app appears here.
ls -l /dev/vmm

# Per-vCPU VMM counters, including exit classes supported by this kernel.
bhyvectl --vm=linux-app --get-stats

# Find the bhyve process, then inspect its vCPU and device worker threads.
pgrep -fl bhyve
procstat -t <bhyve-pid>

# Observe open capabilities/resources before diagnosing a backend failure.
procstat -f <bhyve-pid>
```

Interpret them together. `/dev/vmm` proves that the kernel VM exists, not that
firmware booted. A `vcpu N` thread proves a vCPU was created, not that it is
making progress. Block, network, audio, or event workers can explain latency
that vCPU counters alone cannot. The serial console and guest logs establish
the guest side of the boundary.

### Code example: a service protocol over vsock without inventing a framework

Suppose a Linux service VM provides one concrete operation on port 7000. For a
guest-to-host connection, bhyve maps guest host-CID port 7000 to the Unix socket
`/var/run/bhyve/linux-app/7000`.

The FreeBSD service can listen with an ordinary Unix seqpacket socket:

```c
/* FreeBSD host-side sketch; error handling shortened. */
#include <sys/socket.h>
#include <sys/un.h>

int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
struct sockaddr_un sun = {
        .sun_len = sizeof(struct sockaddr_un),
        .sun_family = AF_UNIX,
};
strlcpy(sun.sun_path, "/var/run/bhyve/linux-app/7000",
    sizeof(sun.sun_path));
unlink(sun.sun_path);
bind(fd, (struct sockaddr *)&sun, sizeof(sun));
listen(fd, 16);

int client = accept(fd, NULL, NULL);
uint8_t request[4096];
uint8_t response[4096];
ssize_t n = recv(client, request, sizeof(request), 0); /* one record */
/* Validate version, operation, lengths, identity, and authorization. */
size_t response_length = build_response(response, sizeof(response), request, n);
send(client, response, response_length, 0);
```

The Linux guest uses its standard AF_VSOCK driver:

```c
/* Linux guest-side sketch. */
#include <linux/vm_sockets.h>
#include <sys/socket.h>

int fd = socket(AF_VSOCK, SOCK_SEQPACKET, 0);
uint8_t request[4096], response[4096];
size_t request_length = build_request(request, sizeof(request));
struct sockaddr_vm svm = {
        .svm_family = AF_VSOCK,
        .svm_cid = VMADDR_CID_HOST,
        .svm_port = 7000,
};
connect(fd, (struct sockaddr *)&svm, sizeof(svm));
send(fd, request, request_length, 0);
ssize_t n = recv(fd, response, sizeof(response), 0);
```

Seqpacket preserves message records, but it does not define the record format
and does not make the peer trustworthy. A small product protocol might use a
fixed header containing magic, version, operation, request ID, and payload
length followed by a bounded payload. Stream sockets are equally reliable but
require explicit framing and partial-read/write loops.

The endpoint directory is a security boundary. Its owner, mode, socket names,
peer credentials, VM CID assignment, and cleanup rules should be controlled by
the supervisor. Do not let an untrusted process pre-create a socket that bhyve
will treat as a privileged host service.

### 16.2 Recommended foundation sequence

1. **Define one supported virtual hardware profile.** Version PCI layout, CPU
   policy, firmware, devices, features, and boot behavior.
2. **Finish modern VirtIO for block, network, console, and SCSI.** Preserve
   legacy defaults where compatibility requires it; make selection explicit.
3. **Add multi-queue where measurements justify it.** Start with VirtIO-net and
   block; design queue-to-worker/CPU placement.
4. **Build a general external backend protocol.** It should negotiate device
   and queue features, pass memory descriptors safely, deliver notifications
   and interrupts, support reconnect/quiesce/reset, expose metrics, and carry
   versioned state.
5. **Make save/restore a first-class contract.** Local suspend/resume before
   live migration; version state from day one.
6. **Add a strict management daemon/API.** Own schema validation, lifecycle,
   events, resource brokers, backend supervision, and audit.
7. **Implement virtio-fs with a sandboxed daemon.** Avoid putting a complex
   filesystem protocol parser into the main VM process.
8. **Choose graphics/audio architectures from application requirements.** Add
   virtio-gpu/virtio-snd only together with the required renderer/audio
   services, scheduling, security, and lifecycle behavior.
9. **Add memory cooperation.** Balloon/reporting first if density matters;
   virtio-mem and memory hotplug only with a concrete policy.
10. **Treat passthrough as an explicit non-migratable profile.** Test reset,
    IOMMU isolation, and recovery per supported device.

Nested virtualization belongs later unless running customer hypervisors inside
Linux is an explicit requirement.

## 17. Testing requirements implied by the architecture

The recent VM-free adversarial harnesses and full Linux matrix are the right
shape. A complete architecture test strategy should have layers:

### 17.1 Kernel/VMM tests

* register and capability validation;
* invalid guest physical mappings and overflow;
* instruction-emulation corner cases;
* interrupt/timer ordering and races;
* VM create/destroy/reinitialize stress;
* concurrent vCPU suspend/resume;
* IOMMU mapping and teardown failures;
* hostile nested-virtualization instructions even though nesting is disabled.

### 17.2 VM-free device tests

* malformed direct and indirect descriptors;
* loops, out-of-range indices, integer overflow, zero/huge lengths;
* wrong descriptor direction and short status buffers;
* queue reset during in-flight work;
* feature-negotiation invalid states;
* event-index interrupt boundaries and wraparound;
* backend EOF, partial I/O, EAGAIN, cancellation, and disconnect;
* resource caps and memory-budget exhaustion;
* pause/drain/resume and reset races;
* fuzzing of config and restore input.

### 17.3 Guest end-to-end tests

For every supported transport/profile:

* guest discovery and correct PCI identity/capabilities;
* driver bind and negotiated feature verification;
* data in both directions where applicable;
* high-volume and multi-record boundary tests;
* reset/reboot/reconnect;
* combined-device operation to reveal BAR/IRQ/thread interactions;
* modern and historical compatibility profiles;
* Linux LTS kernels and the exact Android kernels shipped by the product.

### 17.4 Lifecycle tests

* kill/restart of backends and bhyve;
* host memory pressure and CPU starvation;
* suspend at every I/O phase;
* repeated save/restore across supported software versions;
* storage snapshot rollback and VM-state mismatch rejection;
* power loss/corrupt/truncated state files;
* passthrough reset and failed reset containment;
* long-duration latency and leak tests.

### 17.5 Performance and predictability tests

Measure distributions, not only throughput:

* VM-exit rate and time;
* vCPU runnable/blocking latency;
* per-queue service latency and depth;
* host worker saturation;
* interrupt/coalescing behavior;
* network p50/p99/p99.9 latency and packets per second;
* block flush and tail latency;
* audio underruns and clock drift;
* cross-VM noisy-neighbor effects;
* cpuset/NUMA placement correctness.

### Practical example: run the confidence ladder

Start without a VM. These harnesses exercise device code with hostile queues and
injected backend failures, so failures are fast and reproducible:

```sh
cd /usr/src
SRCTOP=/usr/src sh tests/sys/kern/vsock_device_harness/run.sh

cd /usr/src/tests/sys/kern/vsock_e2e
make
./host-tools-selftest.sh
```

Then isolate one device and transport before running the combined matrix:

```sh
cd /usr/src/tests/sys/kern/vsock_e2e

env \
  ISO=/home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
  TRANSPORTS=modern \
  DEVICES=vsock \
  WORKDIR=/tmp/bhyve-vsock-isolated \
  ./run-alpine-auto.sh

env \
  ISO=/home/koryheard/vm/alpine-virt-3.24.1-x86_64.iso \
  WORKDIR=/tmp/bhyve-virtio-full-matrix \
  ./run-alpine-matrix.sh
```

The matrix deliberately treats topology and transport as separate dimensions.
Modern combined tests run vsock, random, and input together. Historical input
is omitted from the Alpine legacy topology because upstream Linux does not bind
that old bhyve identity; this is reported as an explicit skip rather than a
false pass.

A useful development loop is:

```text
one pure function or parser test
  -> one VM-free device harness
  -> host helper self-test
  -> one device + one transport VM
  -> both transports where supported
  -> combined topology
  -> long stress/fault run
```

Do not jump straight to the full matrix for every failure. A guest timeout
combines firmware, console automation, provisioning, guest drivers, virtual
hardware, host providers, and cleanup. The lower layer should first prove its
own invariants.

### Test-writing example: attack the contract, not only the happy path

For a device expecting one writable eight-byte status descriptor, the useful
test table looks like this:

```c
struct descriptor_case {
        const char *name;
        int chain_count;
        uint32_t length;
        uint16_t flags;
        bool address_in_ram;
        bool should_complete;
        uint32_t expected_used_length;
};

static const struct descriptor_case cases[] = {
        { "valid",          1, 8, VRING_DESC_F_WRITE, true,  true,  8 },
        { "read-only",      1, 8, 0,                   true,  false, 0 },
        { "short",          1, 7, VRING_DESC_F_WRITE, true,  false, 0 },
        { "long",           1, 9, VRING_DESC_F_WRITE, true,  false, 0 },
        { "two buffers",    2, 8, VRING_DESC_F_WRITE, true,  false, 0 },
        { "outside RAM",    1, 8, VRING_DESC_F_WRITE, false, false, 0 },
};
```

Then add stateful cases the table cannot express easily: a direct loop, an
indirect loop, unnegotiated indirect use, available-index jumps, queue reset
during callback, backend EOF, repeated notify with no buffers, and index
wraparound. Assert not just “did not crash,” but also used-index movement,
reported length, interrupt behavior, unchanged sentinel memory, and resource
accounting after the failure.

# Appendices

## 18. Source map

Use this map when reading or changing the implementation.

### Runtime and common infrastructure

* `usr.sbin/bhyve/bhyverun.c` — main, VM open, vCPU threads, run loop, startup.
* `usr.sbin/bhyve/vmexit.c` — common userspace exit handlers.
* `usr.sbin/bhyve/config.c` — hierarchical nvlist configuration.
* `usr.sbin/bhyve/mem.c` — userspace MMIO range registration/dispatch.
* `usr.sbin/bhyve/mevent.c` — kqueue event reactor.
* `usr.sbin/bhyve/pci_emul.c` and `.h` — PCI bus, resources, config, IRQs,
  device registration, snapshot dispatch.
* `usr.sbin/bhyve/pci_irq.c` — PCI interrupt routing.
* `usr.sbin/bhyve/bootrom.c`, `acpi.c`, `basl.c`, `smbiostbl.c`,
  `qemu_fwcfg.c`, `vmgenc.c` — boot/firmware interfaces.

### Kernel/API

* `sys/amd64/vmm/` — amd64 VMM, VMX/SVM, EPT/NPT, interrupt/timer, IOMMU/ppt.
* `sys/arm64/vmm/` — arm64 EL2, MMU, VGIC, timers.
* `sys/riscv/vmm/` — RISC-V H-mode, APLIC, SBI, timers.
* `sys/dev/vmm/` and architecture device glue — VM device/ioctl layer.
* `lib/libvmmapi/vmmapi.c` and `.h` — userspace VMM wrapper.
* `usr.sbin/bhyvectl/` — control and inspection utility.

### Devices and backends

* `usr.sbin/bhyve/virtio.c`, `virtio.h` — split-ring and legacy transport core.
* `usr.sbin/bhyve/virtio_pci_modern.c` — modern non-transitional PCI transport.
* `usr.sbin/bhyve/pci_virtio_*.c` — VirtIO device models.
* `usr.sbin/bhyve/block_if.c` — async file/raw/GEOM block backend.
* `usr.sbin/bhyve/net_backends.c`, `net_backend_*.c` — network backends.
* `usr.sbin/bhyve/pci_ahci.c`, `pci_nvme.c`, `pci_e82545.c` — conventional
  storage/NIC models.
* `usr.sbin/bhyve/pci_passthru.c` — physical PCI assignment.
* `usr.sbin/bhyve/pci_fbuf.c`, `rfb.c`, `pci_xhci.c`, `usb_mouse.c` — display
  and USB input.
* `usr.sbin/bhyve/pci_hda.c`, `hda_codec.c`, `audio.c` — audio.
* `usr.sbin/bhyve/tpm_*.c` — TPM CRB and backends.
* `usr.sbin/bhyve/snapshot.c` — experimental userspace checkpoint/restore.

## 19. Glossary

**Backend**
: Host-side implementation that performs real work for a virtual device, such
  as reading a disk image or sending a packet to tap.

**Device model**
: Implementation of guest-visible registers, queues, interrupts, and device
  semantics.

**DMA**
: Direct Memory Access. A device reads or writes memory independently of CPU
  load/store instructions. Physical passthrough requires IOMMU containment.

**EPT / NPT / stage-2 / G-stage**
: Hardware-assisted second translation from guest physical to host physical
  memory on Intel, AMD, Arm, and RISC-V respectively.

**Guest physical address (GPA)**
: Address the guest kernel believes refers to machine RAM or MMIO. The VMM maps
  it to host memory or a device handler.

**Hypervisor / VMM**
: Software controlling guest CPU execution and isolation. In bhyve this role is
  split between the FreeBSD kernel VMM and userspace bhyve process.

**IOMMU**
: Hardware translating and restricting device DMA. Essential for safe PCI
  passthrough.

**Legacy VirtIO PCI**
: Historical pre-1.0/transitional register interface using I/O BAR registers
  and PFN-based queue setup.

**Modern VirtIO PCI**
: VirtIO 1.x non-transitional PCI capability layout with 64-bit features and
  explicit queue addresses/configuration.

**MMIO**
: Memory-Mapped I/O. A CPU load or store to an address range interpreted as a
  device register rather than RAM.

**MSI / MSI-X**
: Message-Signaled Interrupts. A PCI device raises an interrupt by issuing a
  configured memory message rather than toggling a legacy wire. MSI-X supports
  more independently configured vectors.

**Paravirtualization**
: A guest uses a virtualization-aware interface, such as VirtIO, rather than an
  exact model of physical hardware.

**Passthrough**
: Assignment of a real host device to a guest, normally with an IOMMU and
  interrupt remapping.

**QEMU**
: A broad userspace machine emulator/runtime. With KVM it commonly provides the
  machine and device model while KVM executes guest CPUs.

**QMP**
: QEMU Machine Protocol, a machine-readable control and event protocol used by
  management systems.

**Split virtqueue**
: VirtIO ring format with separate descriptor, available, and used structures.

**vCPU**
: Guest-visible processor state plus the execution context used to run it. In
  bhyve, each active vCPU is driven by a host pthread.

**vhost / vhost-user**
: Mechanisms used primarily in the KVM/QEMU ecosystem to process VirtIO queues
  in the host kernel or an external userspace backend.

**VM entry / VM exit**
: Hardware transitions into guest execution and back to the host VMM.

**VMCS / VMCB**
: Intel and AMD hardware control structures describing guest/host CPU state and
  virtualization controls.

**VirtIO**
: OASIS standard family of paravirtual devices, transports, feature negotiation,
  and shared-memory queues.

**Virtqueue**
: Shared guest-memory queue containing descriptor chains published by a VirtIO
  driver and completed by a device.

**vsock**
: Host/guest socket transport using context IDs and ports rather than IP
  addresses. It supplies transport semantics, not an application RPC format.

## 20. Bottom line

bhyve is not a deficient QEMU clone. It is a smaller, FreeBSD-native
virtualization stack with a good kernel/userspace split, a direct execution
model, strong host integration, and enough devices to run ordinary server
guests efficiently. Those properties make it attractive as the virtualization
foundation of a controlled appliance.

Its limits become serious when the product needs the things a mature VM runtime
does around CPU execution: versioned machine contracts, external device
services, hotplug, multi-queue scaling, broad modern VirtIO, durable
save/restore, live migration, graphics/media integration, and a stable
management/observability API. KVM+QEMU has spent years building those layers and
is far ahead in them.

The right strategy is not to add devices randomly and not to reproduce every
QEMU feature. Preserve bhyve's small, auditable core, then add the few
foundations that let complex services live outside it: a safe backend protocol,
a versioned state model, a strict control plane, and complete high-performance
modern VirtIO for the product's supported hardware profile. That approach lets
FreeBSD remain the reliable system layer while Linux and Android provide the
application and hardware ecosystems they are best at.

## 21. External primary references used for the comparison

These are not evidence for the local bhyve implementation; the source paths
above are. They document the comparison targets:

* Linux KVM API: <https://docs.kernel.org/virt/kvm/api.html>
* Linux KVM nested VMX: <https://docs.kernel.org/virt/kvm/x86/nested-vmx.html>
* QEMU system-emulation introduction:
  <https://www.qemu.org/docs/master/system/introduction.html>
* QEMU device model terminology:
  <https://www.qemu.org/docs/master/system/device-emulation.html>
* QEMU VirtIO devices:
  <https://www.qemu.org/docs/master/system/devices/virtio/index.html>
* QEMU vhost-user backends:
  <https://www.qemu.org/docs/master/system/devices/virtio/vhost-user.html>
* QEMU vhost-user protocol:
  <https://www.qemu.org/docs/master/interop/vhost-user.html>
* QEMU vfio-user:
  <https://www.qemu.org/docs/master/system/devices/vfio-user.html>
* QEMU multi-process architecture:
  <https://www.qemu.org/docs/master/devel/multi-process.html>
* QEMU migration framework:
  <https://www.qemu.org/docs/master/devel/migration/>
* QEMU disk images and snapshots:
  <https://www.qemu.org/docs/master/system/images.html>
* QEMU Machine Protocol:
  <https://www.qemu.org/docs/master/interop/qmp-spec.html>
