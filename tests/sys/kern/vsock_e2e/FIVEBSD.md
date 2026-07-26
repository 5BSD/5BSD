# 5BSD modern VirtIO validation

`run-5bsd-auto.sh` boots the existing 5BSD raw image twice.  The modern run
opts both vsock and RNG into the non-transitional PCI transport.  The legacy
run omits the `transport` option entirely, proving that existing bhyve command
lines retain their old PCI identities and behavior.

Run it as root from the source tree:

```sh
cd /path/to/vsock_e2e
env IMAGE=/path/to/guest-base.img \
    WORKDIR=/tmp/bhyve-vsock-5bsd \
    TRANSPORTS="modern legacy" \
    BULK_MB=256 \
    sh ./run-5bsd-auto.sh
```

The image must provide a root serial-console login and `/root/vsock-pipe`,
`/root/vsock-conntest`, and `/root/vsock-recrx`.  The runner verifies the
expected vsock and RNG PCI IDs, driver attachment, RNG reads, and the configured
guest CID before starting the complete bidirectional vsock matrix.
For each transport it creates a sparse private copy, repairs that copy with a
forced UFS check, and requests a clean guest shutdown.  The base image is never
attached writable.  The runner refuses to start if another bhyve process is
using the base, since a concurrently changing source cannot be copied safely.

Set `TRANSPORTS=modern` for a shorter development pass or reduce `BULK_MB` for
a smoke test.  Logs are retained below `WORKDIR`; unique VM names and socket
directories are used for each run.

The declarative release suite includes this runner as the serialized
`fivebsd-virtio` case.  Supply its raw base image separately from the Alpine
ISO:

```sh
/usr/libexec/flua ./virtio-lab.lua run --profile release \
    --iso /path/to/alpine-virt.iso \
    --fivebsd-image /path/to/guest-base.img \
    --workdir /tmp/virtio-release
```

`VM_FREE_GATES=no` is set by the lab because its exclusive host gate has
already built and validated the helper programs.
