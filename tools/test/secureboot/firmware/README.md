# Independent firmware qualification

This harness tests OVMF Secure Boot enforcement and authenticated db updates.
It does not boot the BSD loader, kernel or installed system, and does not
implement BIP. All keys are disposable; host firmware variables are untouched.

Build `firmware_probe.efi` here and `firmware_update.efi` in `update/` using the
matching source tree's `make buildenv`. The Makefiles reuse the maintained EFI
ABI, startup code and PE conversion. The current target is native amd64.

`suite.py --help` lists required explicit inputs: both EFI probes, firmware code
and variable template, variable-store tool, OpenSSL, uefisign, makefs, mkimg,
QEMU executable/data and a fresh output directory under `/usr/obj/usr/src`.
The maintained frontend integration invokes this suite as its firmware case.

The suite runs one 2048 MiB VM at a time, booting a disk-backed FAT ESP. It checks
setup mode, approved and secondary signers, unsigned/untrusted/altered images,
certificate revocation with a surviving signer control, and authenticated db
replacement. A new signer must be rejected before enrollment and accepted after
it, while the retired signer becomes rejected. Invalid update signatures and
same-boot/cross-reboot replay are rejected without changing db bytes/attributes.
A newer authorized update must still succeed. Inputs, transcripts, resulting
stores and per-case receipts are hash-bound; private keys stay outside the guest.

Run native checks with:

```sh
env FIRMWARE_TEST_OPENSSL=/usr/bin/openssl python3.12 -B -m unittest discover \
    -s tools/test/secureboot/firmware -p '*_test.py'
```

Qualification on 2026-10-24: 24 native tests and 13 sequential firmware cases
passed through build-bsd. Local evidence is retained at
`/usr/obj/usr/src/security-qualification/firmware-replay-frontend-20261024`.
PK/KEK rotation, recovery, interrupted updates, OS runtime updates, factory-key
hardware/shim and the complete verified OS boot chain remain unqualified.
