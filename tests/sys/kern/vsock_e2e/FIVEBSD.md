# 5BSD modern VirtIO validation

`run-5bsd-auto.sh` boots the existing 5BSD raw image twice.  The modern run
opts both vsock and RNG into the non-transitional PCI transport.  The legacy
run omits the `transport` option entirely, proving that existing bhyve command
lines retain their old PCI identities and behavior.

Run it as root from the source tree:

```sh
cd /usr/src/tests/sys/kern/vsock_e2e
env IMAGE=/home/koryheard/vm/bsd-guest.img \
    WORKDIR=/root/bhyve-vsock-5bsd \
    TRANSPORTS="modern legacy" \
    BULK_MB=256 \
    sh ./run-5bsd-auto.sh
```

The image must provide a root serial-console login and `/root/vsock-pipe`,
`/root/vsock-conntest`, and `/root/vsock-recrx`.  The runner verifies the
expected vsock and RNG PCI IDs, driver attachment, RNG reads, and the configured
guest CID before starting the complete bidirectional vsock matrix.  It refuses
to start if another bhyve process is already using the same writable image.

Set `TRANSPORTS=modern` for a shorter development pass or reduce `BULK_MB` for
a smoke test.  Logs are retained below `WORKDIR`; unique VM names and socket
directories are used for each run.
