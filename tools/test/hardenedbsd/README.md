# Defensive-port fault tests

Run on a FreeBSD/5BSD build host with a C compiler and Python 3:

```sh
python3 tools/test/hardenedbsd/regress.py
```

The logger test compiles the complete source with gethostname failure injection
and captures sendto output without sending any datagrams. Casper is disabled in
this test binary. Cases cover untouched and partially written failure buffers,
short names, domain stripping, an empty name, a full MAXHOSTNAMELEN buffer
(256 bytes on FreeBSD), and the explicit `-H` override.

The allocation tests extract the complete qlnx_zalloc function and the entry
paths of mrsas_get_pd_list/mrsas_get_ld_list up to DMA setup from the selected
source tree. Allocator and command-pool stubs exercise failed allocation,
command release, and zero initialization of successful allocations. Extraction
fails if the expected function/setup boundary changes. Driver operations after
DMA setup are not covered. These checks complement full module builds; they
do not replace device testing or booting a rebuilt kernel.

Use `--source-root /path/to/tree` to compare the same tests against a pre-fix
tree. All generated binaries and test files are created in a temporary
directory. No modules are loaded, devices modified, or system logs written.
