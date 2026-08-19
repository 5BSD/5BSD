# WASPNest reference-corpus status

The reference catalog at
`tests/sys/kern/vsock_device_harness/virtio-reference-corpus.tsv` is the
authoritative list of the normative and explanatory inputs used by the
WASPNest review process.  A catalog entry is not equivalent to a locally
authenticated artifact.

## Current local-cache finding

On 2026-08-10, `/tmp/waspnest-reference` was inspected with
`validate-virtio-reference-corpus.sh` and direct SHA-256 calculation.  It is
an exploratory reference cache, not a qualification-ready artifact bundle:

* It contains extracted Linux and QEMU trees and duplicate convenience
  archives, whereas the validator requires exactly one regular,
  non-symbolic artifact for every catalog row and nothing else.
* The Intel SDM volume 3 and volume 4 PDFs match their catalog digests.
* One QEMU archive matches `QEMU-300438`, but the duplicate archive means the
  cache as a whole is still not an acceptable bundle.
* The required OASIS VirtIO 1.4 CS01 PDF is absent from the cache; a cached
  HTML rendering is not a substitute for the catalogued PDF.  A fresh
  download on 2026-08-10 did match the catalog digest, but it was intentionally
  not mixed into this exploratory cache.
* The cached Linux archive does not match `LINUX-7.2-RC4`'s recorded digest.
  A fresh download from the catalog URL on 2026-08-10 also produced
  `529d0949c64043a9f909a8a78eae6b91af5177fa3afa82f55b22e3c0959d4b51`,
  rather than the catalogued
  `325dc159b02912717a73998997052a5806b283589682ff8a989fa66bec8a9cc3`.
  It must not be substituted merely because it purports to name the same
  upstream commit.  The catalog needs an independently reviewed correction
  or an artifact whose bytes match its current digest.

Consequently, no privileged VirtIO, checkpoint, migration, or nested-VMX
qualification run may cite that directory through
`VIRTIO_REFERENCE_ARTIFACT_DIR`.  The metadata validator may still establish
catalog syntax and traceability, but it cannot establish artifact
authentication.

## Required remediation before live qualification

Create a new empty mode-0700 staging directory containing exactly the five
files whose SHA-256 values match the catalog.  Obtain each artifact from the
recorded HTTPS URL, verify its digest before placing it in the staging
directory, and then run:

```
sh tests/sys/kern/vsock_device_harness/validate-virtio-reference-corpus.sh \
  tests/sys/kern/vsock_device_harness/virtio-reference-corpus.tsv \
  --waspnest /path/to/sealed-reference-bundle
```

Only a successful command is evidence that the reference corpus is sealed.
The downloaded artifacts remain review inputs; neither Linux nor QEMU code is
copied into bhyve, and the VirtIO and Intel specifications remain the
normative authorities.
