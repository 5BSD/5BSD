# HardenedBSD standalone defensive ports

2026-09-24. Implements the independent defensive-fix portion of the
[compatibility-first selection](hardenedbsd-import.md). These changes preserve
normal interfaces and focus on failed calls, memory exhaustion, and safe
cleanup. They do not enable new runtime restrictions or compiler defaults.

Reviewed against the pinned HardenedBSD and official FreeBSD revisions in
the import ledger. The three selected fixes remain absent from the pinned
FreeBSD tree and the initial 5BSD checkout. Source copyrights and licenses
are retained; provenance below credits the HardenedBSD work.

## Implemented

| Location | Trigger and resulting behavior | HardenedBSD provenance |
| --- | --- | --- |
| `usr.bin/logger/logger.c` | `gethostname()` fails, partially fills its destination, or fills the supplied extent without a terminator. Initialize the buffer, reserve a trailing NUL, and use an empty hostname on failure. Preserve domain stripping and the explicit `-H` override. Avoid scanning stale/uninitialized stack bytes or past the buffer. | Shawn Webb, `2c4078dd70af8aed09279cd43d5d4805d1df06e5`, plus the retained hostname-buffer hardening at `377c16e8de65d1b5885c4aa26e404f37b90aa2ca`. |
| `sys/dev/qlnx/qlnxe/qlnx_os.c:qlnx_zalloc` | Nonblocking allocation returns NULL. Return NULL to the caller instead of passing it to `bzero`. Successful allocations remain zeroed. This fixes the helper, not every possible caller error path. | Shawn Webb, `4aefbf23f7bbfc5b14a739313229c1aacb10922d`. |
| `sys/dev/mrsas/mrsas.c:mrsas_get_pd_list` and `mrsas_get_ld_list` | Allocation of a temporary command descriptor fails after a firmware command was reserved. Release that command and return ENOMEM before DMA setup. Zero successful descriptor allocations so partial DMA setup cleanup sees NULL/zero for resources that were never acquired. | Shawn Webb, `ca99b1d7e369eaad670a380da5d413817b7d9ec1` and `21e1924852dc2ac376b5912b220d7312511af391`, adapted for 5BSD. |

The MegaRAID adaptation intentionally omits the source patches' calls to
`mrsas_free_tmp_dcmd(NULL)`: that cleanup routine dereferences its argument.
Local `M_ZERO` initialization is required because 5BSD does not enable
HardenedBSD's blanket kernel allocation zeroing. This also protects existing
cleanup after partial DMA setup, which checks the descriptor's tag, memory,
and physical-address fields.

The standalone MegaRAID build exposed a missing `vnode_if.h` dependency:
`mrsas_ioctl.h` includes `mount.h` for COMPAT_FREEBSD32, and the current tree's
mount header includes vnode declarations. Added `vnode_if.h` to the module's
generated sources so a fresh object directory can build it.

## Review decisions

| Candidate | Decision |
| --- | --- |
| Kernel iconv negative-length check | Not imported. Despite `ia_datalen` being signed, `ICONV_CSMAXDATALEN` is a `size_t` expression made from `sizeof`. The existing comparison converts negative values to a large unsigned value and rejects them. This corrects the initial suspicion during review; it is not a demonstrated missing bounds check in this tree. |
| Whole-structure zeroing in `shm_fill_kinfo_locked` | Not imported. `export_file_to_kinfo` has already populated descriptor number, reference count and other metadata before calling the file-specific fill hook. Clearing the entire structure there erases valid information. The list caller already initializes its local structure. |
| Blanket `M_ZERO` additions to statfs output allocations | Not imported. `__vfs_statfs` copies the entire mount statistics structure into the destination before filesystem-specific updates. Initial zeroing would be overwritten; it does not establish a fix for stale output in this path. |
| `init_unrhdr` whole-structure zeroing | No demonstrated missing live-field initialization in the reviewed implementation; not added merely to increase the number of imported patches. |
| Driver checks with incomplete failure unwinding | Deferred for deeper review. The retained MMC/Tegra/PowerPC changes include early returns after resource acquisition or leave counts/state set. The PowerPC hunk also has a syntax error. They are not safe mechanical imports. |
| New visibility, execution, tracing or device-access restrictions | Outside this compatibility-first batch. |

## Validation

Built from the source-tree make files on amd64, using empty make/src
configuration overrides and `/tmp/5bsd-defensive-obj` as the object root:

- `usr.bin/logger` with the normal Casper-enabled configuration;
- `sys/modules/qlnx/qlnxe` (`if_qlnxe.ko`);
- `sys/modules/mrsas` (`mrsas.ko` and `mrsas_linux.ko`).

The [fault-injection suite](../../tools/test/hardenedbsd/README.md) passes all
ten cases: seven logger hostname cases and three driver allocation groups.
The driver groups cover allocation failure, zeroed successful allocation,
and, for both MegaRAID queries, command-pool exhaustion and exactly-once
release on descriptor allocation failure.

Running the same suite against the original three source files reproduces
five failing cases: partially written hostname failure, a full unterminated
hostname, QLogic allocation failure, and both MegaRAID allocation paths.
This verifies that the tests distinguish the fixes from the original code.

The logger tests compile the full logger source with a controlled hostname
provider and captured send output; they do not send logs. The driver tests
compile the actual helper/entry-path source with allocator and command-pool
stubs. MegaRAID extraction stops before DMA setup, so it does not exercise
real DMA cleanup or firmware behavior. No hardware test, kernel boot, module
load, installation, or full world build was performed. Device qualification
remains necessary before claiming those paths tested on hardware.

Build logs are `/tmp/5bsd-defensive-{logger,qlnxe,mrsas}-build.log`. The test
suite is reproducible with:

```sh
python3 tools/test/hardenedbsd/regress.py
```
