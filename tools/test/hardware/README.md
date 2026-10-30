# Hardware artifact checks

`i915-support.py` checks an unstripped amd64 i915kms module without loading it.
Supply the matching DRM source header and the upstream `i915_pci.c.orig` saved
by the ports patch stage, together with explicit compiler, readelf, nm and
kldxref executables:

```
python3.12 /usr/src/tools/test/hardware/i915-support.py \
    --module /path/to/i915kms.ko \
    --pci-ids-header /path/to/include/drm/intel/i915_pciids.h \
    --upstream-pci /path/to/drivers/gpu/drm/i915/i915_pci.c.orig \
    --cc /usr/bin/cc --readelf /usr/bin/readelf --nm /usr/bin/nm \
    --kldxref /path/to/matching/kldxref
```

The explicit retirement policy names the pre-generation-6 device groups. The
compiler expands their PCI IDs and the complete upstream table from the supplied
header. The audit requires the complete ordered compiled PCI match records to equal
the upstream records minus those retired IDs, including subsystem matches. It also requires complete module metadata and
rejects AGP dependencies and unresolved legacy GTT symbols. Input hashes are
recorded and checked again after inspection.

This proves artifact properties only. Matching-kernel VM module loading and
physical supported-GPU display, rendering and suspend/resume remain separate
gates. In particular, a QEMU display device does not emulate an Intel GPU.

## Ports license directories

`ports-license-directories.py` queries the supplied ports framework for each
selected package's license directory and packing-list directory declarations.
It checks normal and disabled license installation, then uses the explicit pkg
executable to package a small payload through the real packing-list parser and
verifies directory ownership/mode in the resulting manifest. Ports themselves
are not built by this test; this is not complete generation qualification.

Supply `--ports`, `--pkg`, a new `--work`, target `--osversion`, repeated
`--origin category/port[@flavor]`, and repeated `--prefix /absolute/path`.
Inputs, commands, cases and archive hashes are retained in `result.json`.
Use a private work directory under /usr/obj/usr/src. The test does not install
packages, consult the installed package database or modify a host repository.

## Bluetooth firmware layout

`bluetooth-layout.py --source /usr/src --ports /usr/obj/5BSD-ports
--osversion 1600027` checks the selected custom ports against the base Intel
and Realtek Bluetooth loaders. It queries ports metadata, checks declared
firmware directories and plist destinations, and requires devd to use the
loader default. It records source hashes and package versions. This is a
source/metadata check; rebuilt archives, installed defaults and physical
Bluetooth initialization require separate qualification.
