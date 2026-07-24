# vsock End-to-End Test Plan (bhyve host + guests)

Manual/system test plan for the AF_VSOCK stack: the bhyve **host device**
(`usr.sbin/bhyve/pci_virtio_vsock.c`), the **guest transport driver**
(`sys/dev/virtio/vsock/virtio_vsock.c`), and the **socket domain**
(`sys/kern/uipc_vsock.c`). The device-level unit harness
(`vsock_device_harness/`) and the ATF tests (`vsock_test`, `vsock_wire_test`)
cover the pieces in isolation; this document covers the missing layer:
**a real bhyve VM talking vsock to the host and to a second implementation
(Linux) for interop/conformance.**

---

## 1. Architecture under test

```
   +--------------------------- 5BSD HOST -----------------------------+
   |                                                                   |
   |   host app  <-- AF_UNIX bridge or host AF_VSOCK -->  bhyve       |
   |                                   |  virtio PCI                   |
   |                                   v                               |
   |   +----------------- GUEST (CID = N >= 3) ----------------------+ |
   |   |  virtio_vsock.ko  ->  vsock.ko (AF_VSOCK)  ->  guest app    | |
   |   +-------------------------------------------------------------+ |
   +-------------------------------------------------------------------+
```

Key facts that drive the setup (from the device header comment and
`pci_vtvsock_init`):

* **bhyve is always CID 2** (`VSOCK_CID_HOST`). The guest CID is whatever you
  pass as `cid=` and **must be `>= 3` and `< 0xffffffff`**.
* The default `backend=userspace` mode uses **AF_UNIX sockets rooted in a
  directory** supplied via `path=`.  It needs no host vsock kernel support.
* `backend=kernel` instead attaches bhyve to the host `/dev/vsock` transport.
  Host applications then use ordinary AF_VSOCK sockets, `path=` is invalid,
  and the host `vsock` module must be loaded.  The provider is exclusive and
  every running guest must have a unique CID.
* **Guest → host (`backend=userspace`):** guest connects to `CID 2 : <port>`;
  bhyve `connectat()`s to
  `<dir>/<port>` (e.g. `<dir>/80`). A host process must be **listening on that
  Unix socket** or the guest gets `OP_RST` (ECONNRESET).
* **Host → guest (`backend=userspace`):** a host app connects to the control socket
  `<dir>/sock`,
  sends a `struct vsock_ctl_msg{cmd=VSOCK_CTL_CONNECT, port, type}`, and on
  success bhyve returns `status=0` plus one end of a socketpair via
  `SCM_RIGHTS`. There is no off-the-shelf tool for this handshake — use the
  `vsh-connect` helper in Appendix B.
* In `backend=kernel` mode the same directions use host AF_VSOCK bind/connect
  calls; the automated Alpine matrix covers both directions and transport
  reset through this path.
* Loopback inside a guest uses **CID 1** (`VSOCK_CID_LOCAL`).

The userspace backend matches the Firecracker/QEMU "hybrid vsock" model, while
the kernel backend exposes the conventional host AF_VSOCK API.  A **stock Linux
guest virtio-vsock driver works unmodified** with either backend, which is what
makes Linux a useful independent conformance oracle.

---

## 2. Host prerequisites (5BSD, common to all guests)

Do this once on the physical/host machine running your 5BSD fork.

### 2.1 Build & install bhyve with the vsock device

The device is already wired into the build (`usr.sbin/bhyve/Makefile` lists
`pci_virtio_vsock.c` and the `vsock_provider.d` USDT provider).

```sh
# From your src tree:
cd /usr/src
make -C usr.sbin/bhyve            # or: make buildworld for a full build
sudo make -C usr.sbin/bhyve install
bhyve -h 2>&1 | grep -i vsock     # sanity: device should be linkable
```

Optionally build the DTrace scripts you added under `share/dtrace/vsock-*`
if you want host-side probes during tests.

### 2.2 Load vmm and set up a VM directory

```sh
sudo kldload vmm            # bhyve kernel module
sudo sysctl hw.vmm.* | head # confirm vmm present

# A working directory for images + the vsock unix-socket dir:
mkdir -p ~/vm/vsock-sockdir     # this becomes path=<dir>
```

The directory is needed only by `backend=userspace`. To test
`backend=kernel`, load `vsock.ko` on the host and choose a guest CID not
already attached by another provider. Distinct CIDs may run concurrently.

The root host suite also runs the MAC capability AF_VSOCK ownership cases.
Before invoking `run_vsock_tests.sh`, stop `oracled` and any other capability
broker holding an isolation claim on `/dev/mac_capability`.  Such a claim
correctly makes the control device inaccessible to the test process and would
otherwise turn every MAC/vsock case into the same `EACCES` setup failure.
Restart the broker after the suite completes.

After the single-VM matrices pass, run the concurrent kernel-provider gate:

```sh
ISO=/path/to/alpine-virt.iso \
    /usr/tests/sys/kern/vsock_e2e/run-alpine-multi-vsock.sh
```

It requires two distinct guest CIDs, uses separate console and socket port
ranges, and requires the provider-count sysctl to return to zero afterward.

### 2.3 (Linux guests only) UEFI firmware

Linux guests boot via UEFI. Install the edk2 firmware for bhyve:

```sh
sudo pkg install edk2-bhyve      # provides BHYVE_UEFI.fd
# typical path: /usr/local/share/uefi-firmware/BHYVE_UEFI.fd
```

(FreeBSD/5BSD guests boot with `bhyveload` and do **not** need this.)

### 2.4 Networking (optional but recommended for downloads inside guests)

```sh
sudo sysctl net.link.tap.up_on_open=1
sudo ifconfig tap0 create
sudo ifconfig bridge0 create addm <your-nic> addm tap0 up
```

Networking is **not** required for vsock itself (vsock is independent of IP),
but it's convenient for installing packages/tools inside guests.

---

## 3. Guest A — 5BSD (tests the guest driver + AF_VSOCK domain)

This guest must run **your fork's** `virtio_vsock` + `vsock` code, so build the
guest image from the same source tree.

### 3.1 Produce a 5BSD guest disk image

Any of these work; pick one:

* **Reuse your build:** `make buildworld buildkernel`, then install into a raw
  image:

  ```sh
  truncate -s 20G ~/vm/bsd-guest.img
  mdconfig -a -t vnode -f ~/vm/bsd-guest.img -u 0
  gpart create -s gpt md0
  gpart add -t freebsd-boot -s 512k -a 4k md0 && gpart bootcode -b /boot/pmbr -p /boot/gptboot -i 1 md0
  gpart add -t freebsd-ufs -a 1m md0
  newfs -U /dev/md0p2 && mount /dev/md0p2 /mnt
  make installworld installkernel distribution DESTDIR=/mnt
  # set up /mnt/etc/fstab, /mnt/etc/rc.conf, root password, then:
  umount /mnt && mdconfig -d -u 0
  ```

* **Or** install a FreeBSD release ISO into the VM, then `installkernel` and the
  two kmods from your tree over it (guest driver is what's under test, so its
  bits must come from your fork).

### 3.2 Ensure the vsock modules are present in the guest

```sh
# Build the two modules from the tree if not already in the image:
make -C sys/modules/vsock            # -> vsock.ko   (AF_VSOCK domain)
make -C sys/modules/virtio/vsock     # -> virtio_vsock.ko (PCI transport)
```

In the guest, autoload at boot via `/boot/loader.conf`:

```
virtio_vsock_load="YES"
```

Loading `virtio_vsock` pulls in `vsock` automatically
(`MODULE_DEPEND(virtio_vsock, vsock, ...)`). Note the `vsock` domain registers
via `DOMAIN_SET` and is **intentionally non-unloadable** (MOD_UNLOAD returns
EBUSY), so load it once and leave it — don't script kldunload of it.

### 3.3 Launch the guest with the vsock device

```sh
CID=3
DIR=~/vm/vsock-sockdir
bhyveload -m 2G -d ~/vm/bsd-guest.img bsdguest

bhyve -c 2 -m 2G -H -w \
  -s 0,hostbridge \
  -s 3,virtio-blk,~/vm/bsd-guest.img \
  -s 4,virtio-net,tap0 \
  -s 5,virtio-vsock,cid=${CID},backend=userspace,path=${DIR} \
  -s 31,lpc -l com1,stdio \
  bsdguest
```

The userspace device string is
`virtio-vsock,cid=<N>,backend=userspace,path=<dir>` (parsed by
`pci_vtvsock_legacy_config`).  Omitting `backend` selects `userspace` for
compatibility.  The kernel form is
`virtio-vsock,cid=<N>,backend=kernel` and does not accept `path`.  Set
`BHYVE_VTVSOCK_DEBUG=1` in bhyve's environment for lifecycle and error
tracing, or use level 2 for per-packet metadata.

### 3.4 Verify attach inside the guest

```sh
dmesg | grep -i vtvsock                 # driver attached
sysctl kern.vsock.guest_cid             # should print N (e.g. 3)
ls -l /dev/vsock                         # cdev present
```

### 3.5 Test tools in the 5BSD guest

FreeBSD's base `nc`/`socat` don't speak AF_VSOCK, so use the ATF tests plus the
tiny C helpers in Appendix A:

```sh
# Run the in-guest unit/ABI tests (no VM-to-host needed):
kyua test -k /usr/tests/sys/kern/Kyuafile vsock_test vsock_wire_test

# Build the appendix helpers:
cc -o vsock-echo   Appendix-A-server.c
cc -o vsock-client Appendix-A-client.c
```

---

## 4. Guest B — Linux (independent conformance / interop oracle)

Linux has upstream AF_VSOCK + virtio-vsock, so it validates that our **host
device** is spec-conformant against code we didn't write.

### 4.1 Get a Linux image

Easiest is a cloud image with a serial console:

* **Alpine** virt image (tiny), **Debian/Ubuntu** cloud `.img`, or a Fedora
  Cloud raw image. Download the `.img`/`.qcow2` (convert qcow2 to raw with
  `qemu-img convert -O raw in.qcow2 out.raw`).
* Seed cloud-init or set a root password via the distro's documented method so
  you can log in on the serial console.

### 4.2 Confirm vsock support in the Linux guest

Modern distro kernels ship these as modules:

```sh
modprobe vsock
modprobe vmw_vsock_virtio_transport   # the guest-side virtio transport
lsmod | grep vsock
```

If `/dev/vsock` exists and `modprobe` succeeds, you're set. (Kernel configs:
`CONFIG_VSOCKETS=m`, `CONFIG_VIRTIO_VSOCKETS=m`.)

### 4.3 Launch the Linux guest with the vsock device

```sh
CID=4
DIR=~/vm/vsock-sockdir-linux      # use a SEPARATE dir per running guest
mkdir -p $DIR
UEFI=/usr/local/share/uefi-firmware/BHYVE_UEFI.fd

bhyve -c 2 -m 2G -H -w \
  -s 0,hostbridge \
  -s 3,virtio-blk,~/vm/linux-guest.raw \
  -s 4,virtio-net,tap1 \
  -s 5,virtio-vsock,cid=${CID},backend=userspace,path=${DIR} \
  -s 29,fbuf,tcp=0.0.0.0:5900,w=800,h=600 \
  -s 31,lpc -l com1,stdio \
  -l bootrom,${UEFI} \
  linuxguest
```

> Each concurrently running guest needs a **unique CID and its own `path=`
> directory** — the directory holds that guest's `sock` control socket and the
> per-port listener sockets.

### 4.4 Test tools in the Linux guest

Linux has rich AF_VSOCK tooling — good for quick checks:

```sh
# socat (recent versions):
socat - VSOCK-CONNECT:2:1234           # connect to host CID 2, port 1234
socat VSOCK-LISTEN:1234 -              # listen for a host-initiated connect

# ncat (nmap) with vsock, or python one-liners:
python3 - <<'PY'
import socket
s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
s.connect((2, 1234))          # (CID_HOST, port)
s.sendall(b"hello from linux\n"); print(s.recv(64))
PY

# read local CID:
python3 -c 'import socket,fcntl,struct;\
f=open("/dev/vsock");print(fcntl.ioctl(f,0x7b9,struct.pack("I",0)))' 2>/dev/null
```

---

## 5. Connectivity bring-up (do this first, before the matrix)

### 5.1 Guest → host

Host listens on the per-port Unix socket; guest connects to CID 2.

```sh
# HOST: listen on <dir>/1234  (FreeBSD nc supports -U for unix sockets)
nc -lU ~/vm/vsock-sockdir/1234

# GUEST (5BSD): ./vsock-client 2 1234    (Appendix A)
# GUEST (Linux): socat - VSOCK-CONNECT:2:1234
```

Expect bidirectional echo. If the host has no listener at `<dir>/1234`, the
guest connect must fail with **ECONNRESET** (device sends `OP_RST`) — that's a
valid negative test.

### 5.2 Host → guest

Guest listens on a vsock port; host drives the control handshake via
`vsh-connect` (Appendix B).

```sh
# GUEST (5BSD): ./vsock-echo 1234                 (Appendix A, listens on port 1234)
# GUEST (Linux): socat VSOCK-LISTEN:1234 -

# HOST: connect through the control socket:
./vsh-connect ~/vm/vsock-sockdir/sock 1234
# then type; you should see the guest echo back
```

### 5.3 In-guest loopback (CID 1)

```sh
# 5BSD guest, two shells:
./vsock-echo 1234                          # listener
./vsock-client 1 1234                      # connect to CID_LOCAL

# Linux guest:
socat VSOCK-LISTEN:1234 - &                # listener
socat - VSOCK-CONNECT:1:1234
```

---

## 6. Test matrix

Run each row for **both** guests (5BSD and Linux) and, where applicable, both
directions. `S` = SOCK_STREAM, `SP` = SOCK_SEQPACKET.

| # | Scenario | Type | Direction | Pass criteria |
|---|----------|------|-----------|---------------|
| 1 | Basic echo | S | G→H, H→G, loopback | data round-trips intact |
| 2 | Basic echo | SP | G→H, H→G, loopback | message boundaries preserved |
| 3 | Large transfer (≥256 MiB) | S | both | byte-exact (`sha256` compare); no stall/hang |
| 4 | Many small writes (credit churn) | S | both | no deadlock; credit updates flow |
| 5 | SEQPACKET record sizes: 0, 1, MAX, MAX+1 | SP | both | 0/1/MAX delivered; MAX+1 → EMSGSIZE, conn survives |
| 6 | MSG_EOR / partial records | SP | both | EOR flag preserved end-to-end |
| 7 | Connect to dead host port | S | G→H | guest gets ECONNRESET, not hang |
| 8 | Connect to non-listening guest port | S | H→G | `vsh-connect` returns non-zero status |
| 9 | Concurrent connections (≥256) | S | both | up to device cap; excess refused cleanly (no crash) |
| 10 | Graceful close both directions | S/SP | both | EOF observed both sides; no leaked conns |
| 11 | Abrupt peer kill (SIGKILL client) | S | both | server sees EOF/reset; host conn reaped |
| 12 | Guest reboot with conns open | S | both | host device resets cleanly; no bhyve crash |
| 13 | bhyve/guest detach with blocked sender | S | G→H | sender unblocks promptly (≤1s) — see note |
| 14 | Reserved-CID connects (0, 2 spoofed) | S | guest | rejected per domain rules; no host reach |
| 15 | Port 0 bind / auto-bind | S | guest | auto-assign works; literal port 0 needs priv |
| 16 | Loopback (CID 1) isolation | S | guest | never leaves guest onto the wire |

**Notes**

* Row 13 exercises the credit-stall wakeup fixed in
  `vsock_transport_reset_locked()` (now wakes `&pcb->tx_cnt`). Start a large/slow
  transfer, then kill bhyve (host) or `kldunload virtio_vsock` (guest) mid-send
  and confirm the sender returns within ~1s rather than hanging.
* Rows 5/6 are the SEQPACKET EOM/EOR conformance cases — most valuable when the
  peer is the **Linux** implementation.
* Row 9's cap comes from `VTVSOCK_MAX_CONNS` (host) / `vtvsock_max_conn`
  (guest); verify excess is refused with RST and that closing frees slots
  (no permanent lockout).

### 6.1 Cross-implementation interop (the high-value runs)

Do these explicitly with **5BSD host + Linux guest** and compare against
**5BSD host + 5BSD guest**:

* Rows 1–6 with Linux as the guest exercise our host device against an
  independent transport — the strongest conformance signal.
* Capture `BHYVE_VTVSOCK_DEBUG=2` host logs and/or the `share/dtrace/vsock-*`
  scripts during rows 3, 4, 9 to watch credit accounting under load.

---

## 7. What to watch / instrumentation

* **Host, both backends:** run bhyve with `BHYVE_VTVSOCK_DEBUG=1` for lifecycle
  and error diagnostics or `BHYVE_VTVSOCK_DEBUG=2` for per-packet metadata.
  `vsock-overview` shows the combined host view.  The `vsock-security` script
  likewise includes both bhyve descriptor rejections and kernel-provider
  rejects.
* **Host, `backend=userspace`:** `vsock-connections` and `vsock-perf` report
  bhyve's relay lifecycle, credit, and bounded-resource state.
* **Host, `backend=kernel`:** `vsock-provider` traces privileged
  `/dev/vsock` provider attach/detach/reset, packet queue depth, backpressure,
  invalid provider packets, and host AF_VSOCK connection churn.  When kernel
  auditing is enabled and the relevant class is selected, the standard
  FreeBSD audit trail records privileged provider control ioctls as
  `AUE_IOCTL`.  Neither backend has a dedicated BSM event for every packet or
  vsock connection; DTrace supplies the vsock-specific CID, feature, queue,
  and lifecycle metadata without recording payloads.
* **5BSD guest:** `sysctl kern.vsock` (guest_cid, counters, max_conn); `netstat`
  additions if present; `dtrace` on the guest driver.
* **Leak checks:** after each teardown scenario confirm host conn/ctl-conn and
  reasm/txbuf byte budgets return to baseline (they're bounded and must not
  ratchet up across connect/close cycles).

---

## Appendix A — 5BSD guest AF_VSOCK helpers

`Appendix-A-server.c` (echo server, listens on a port):

```c
#include <sys/socket.h>
#include <sys/vsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <port>\n", argv[0]); return 2; }
    int s = socket(AF_VSOCK, SOCK_STREAM, 0);
    struct sockaddr_vm sa = {0};
    sa.svm_family = AF_VSOCK;
    sa.svm_cid = VSOCK_CID_ANY;
    sa.svm_port = (unsigned)atoi(argv[1]);
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind"); return 1; }
    if (listen(s, 16) < 0) { perror("listen"); return 1; }
    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) { perror("accept"); continue; }
        char buf[4096]; ssize_t n;
        while ((n = read(c, buf, sizeof buf)) > 0)
            if (write(c, buf, n) != n) break;
        close(c);
    }
}
```

`Appendix-A-client.c` (connect to `<cid> <port>`, relay stdin/stdout):

```c
#include <sys/socket.h>
#include <sys/vsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <cid> <port>\n", argv[0]); return 2; }
    int s = socket(AF_VSOCK, SOCK_STREAM, 0);
    struct sockaddr_vm sa = {0};
    sa.svm_family = AF_VSOCK;
    sa.svm_cid = (unsigned)strtoul(argv[1], NULL, 0);
    sa.svm_port = (unsigned)atoi(argv[2]);
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("connect"); return 1; }
    char buf[4096]; ssize_t n;
    while ((n = read(0, buf, sizeof buf)) > 0) {
        if (write(s, buf, n) != n) { perror("write"); return 1; }
        n = read(s, buf, sizeof buf);
        if (n > 0) write(1, buf, n);
    }
    close(s);
    return 0;
}
```

For SEQPACKET, change `SOCK_STREAM` to `SOCK_SEQPACKET`.

---

## Appendix B — Host → guest control-socket connector (`vsh-connect`)

There is no stock tool for the `<dir>/sock` control handshake, so build this
small helper on the **host**. It connects to the control socket, requests a
guest port, receives the relayed socketpair fd via `SCM_RIGHTS`, then relays
stdin/stdout.

```c
/* vsh-connect.c — cc -o vsh-connect vsh-connect.c */
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* mirrors struct vsock_ctl_msg in pci_virtio_vsock.c */
struct vsock_ctl_msg { uint32_t cmd, port, type; int32_t status; };
#define VSOCK_CTL_CONNECT 1

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <dir>/sock <port> [seqpacket]\n", argv[0]); return 2; }
    int cs = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un sun = { .sun_family = AF_UNIX };
    strncpy(sun.sun_path, argv[1], sizeof(sun.sun_path) - 1);
    if (connect(cs, (struct sockaddr *)&sun, sizeof sun) < 0) { perror("connect ctl"); return 1; }

    struct vsock_ctl_msg m = { VSOCK_CTL_CONNECT,
        (uint32_t)atoi(argv[2]),
        (uint32_t)(argc > 3 ? SOCK_SEQPACKET : SOCK_STREAM), 0 };
    if (write(cs, &m, sizeof m) != sizeof m) { perror("write ctl"); return 1; }

    /* reply: status word + one fd via SCM_RIGHTS */
    struct vsock_ctl_msg r; int datafd = -1;
    char cbuf[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec io = { &r, sizeof r };
    struct msghdr mh = { .msg_iov = &io, .msg_iovlen = 1,
                         .msg_control = cbuf, .msg_controllen = sizeof cbuf };
    if (recvmsg(cs, &mh, 0) < 0) { perror("recvmsg"); return 1; }
    if (r.status != 0) { fprintf(stderr, "connect refused: status=%d\n", r.status); return 1; }
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c))
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS)
            memcpy(&datafd, CMSG_DATA(c), sizeof datafd);
    if (datafd < 0) { fprintf(stderr, "no data fd returned\n"); return 1; }

    /* relay stdin/stdout over the data fd */
    char buf[4096]; ssize_t n;
    while ((n = read(0, buf, sizeof buf)) > 0) {
        if (write(datafd, buf, n) != n) break;
        n = read(datafd, buf, sizeof buf);
        if (n > 0) write(1, buf, n);
    }
    return 0;
}
```

---

## Appendix C — Per-environment download/install checklist

| Item | 5BSD host | 5BSD guest | Linux guest |
|------|-----------|-----------|-------------|
| bhyve + `virtio-vsock` device | build from tree (§2.1) | — | — |
| `vmm.ko` | `kldload vmm` | — | — |
| edk2 UEFI (`BHYVE_UEFI.fd`) | `pkg install edk2-bhyve` (Linux guest only) | — | — |
| `vsock.ko` + `virtio_vsock.ko` | — | build from tree (§3.2) | — (built into distro kernel) |
| vsock kernel modules | `vsock_load=YES` for `backend=kernel`; not needed for `backend=userspace` | `virtio_vsock_load=YES` | `modprobe vsock vmw_vsock_virtio_transport` |
| Guest OS image | — | build/install from fork (§3.1) | download distro cloud image (§4.1) |
| Test tooling | `vsh-connect` (App. B), `nc -U` | App. A helpers, `kyua`/ATF | `socat`, `python3`, `ncat` |

---

## Appendix D — Quick smoke test (copy/paste)

```sh
# HOST
CID=3; DIR=~/vm/vsock-sockdir; mkdir -p $DIR
kldload vmm
# ... launch 5BSD guest with backend=userspace,path=$DIR (see §3.3)
nc -lU $DIR/1234 &                 # host listener for guest->host

# GUEST (5BSD)
kldload virtio_vsock
sysctl kern.vsock.guest_cid        # expect 3
./vsock-client 2 1234              # type -> should echo via host nc

# HOST -> GUEST (guest runs ./vsock-echo 1234 first)
./vsh-connect $DIR/sock 1234       # type -> should echo via guest
```

If all three directions echo, the datapath is up; proceed to the §6 matrix.
```
