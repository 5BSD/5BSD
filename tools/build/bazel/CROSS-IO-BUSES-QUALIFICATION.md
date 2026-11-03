# ARM64/RISC-V I/O-bus module qualification

## Qualified scope (2026-11-03)

Sixty-one selected GPIO/I2C/1-Wire/PWM/SPI module leaves per architecture pass
ARM64/RISC-V Bazel builds and artifact checks. Of 122 plain modules, 110 equal
untouched Make bytes; 12 equal explicit identical-source canonical-filename
controls. CTF/runtime checks retain the same 110/12 distinction. The review
covers 340 actual compilers/34,550 canonical consumed pairs, 488 ordered links
and 366 install records. A real 1-Wire export defect is fixed in both backends
and additionally qualified on amd64. All twelve positive/negative provider
tests pass. Separate DWARF, runtime and performance gates remain open. See
[CROSS-IO-BUSES-QUALIFICATION.md](CROSS-IO-BUSES-QUALIFICATION.md).

The cohort has 85 source groups and 77 physical C sources. Ten selected leaves
had no amd64 declaration and now have native cross-target metadata. All 244
untouched original Make controls pass after correcting the export defect;
six normal build-bsd profiles pass, including two amd64 regression profiles.
No target module is loaded or executed.

All 122 cross-target CTF/runtime comparisons preserve section contents and
layout except explicit build-ID/debuglink values, against the declared
comparison reference. Both original and native debug CRCs pass. All 122
separate debug files differ; semantic DWARF and debugger source lookup remain
unqualified. The amd64 exporter/consumer regression adds three untouched
whole-byte plain matches, three CTF/runtime/debug CRC comparisons, ten actual
compilations/940 consumed pairs, six links and nine install records. Its three
separate debug files also differ.

## Honest filename comparison boundary

Make passes some source filenames containing redundant slashes or parent
components from .PATH. Native Bazel compiler provenance uses the declared
canonical source paths. Embedded __FILE__ strings consequently differ.
Untouched original artifacts and their raw section differences are retained.
They are never reported as whole-byte matches when they differ.

Filename controls are derived from both builders' actual captured compiler
arguments. Each mapping checks same-file identity and source hashes, and
changes only the explicitly declared compiler macro-prefix mapping to the
existing native provenance. The controls retain ordinary Make build/link/
install recipes and actual dependency files. Their compiler policy and
consumed source/generated-header pairs must match the untouched controls.

Twenty-six architecture/module pairs have spelling differences, producing
52 separate plain/CTF controls. Only twelve plain and twelve CTF comparisons
need them; the other 110/110 use untouched Make. Those controlled plain bytes
match exactly; the controlled CTF/runtime contracts pass the same strict
section checks as untouched comparisons. These controls are qualification
evidence, not a normal build input, replacement compiler, runtime wrapper or
Make invocation from native Bazel. No Make source-path cleanup or per-program
provenance exception is introduced into production code.

## Source-owned architecture and policy

The source/list audit retains 122 actual parent-chain-aware queries, GENERIC
KERN_OPTS and 104 regular Makefiles. The /dev/null configuration sentinel is
explicitly separate. Before/after checks preserve 8,665 original inputs.
Native declarations own sources, complete object order, exports, package and
aliases. Runtime builds do not discover targets through Make or consume
Make-produced objects/headers.

ARM64 retains ACPI objects omitted on RISC-V in gpiobus, ig4, iicbus and spibus.
FDT adds OFW/PWM/bus sources, and GPIO LEDs select gpioled_fdt.c. These choices
come from original target configuration/source queries and compiled dependency
records, not an assumption that amd64 lists cover other architectures.
Existing exact source-header providers are reused with consumer visibility
extensions; nine additional precise views cover missing physical closures.
Options are extracted from actual target config trees, including empty values;
interfaces are produced by the native KOBJ pipeline. No fabricated header or
broad undeclared include directory substitutes for a dependency.

The normal build-bsd format-5 kernel/architecture/CTF/debug/test inputs carry
all six profiles through existing maintained backend rules. No frontend C/CLI,
SDK, signing, publication, runtime authority or BIP change is needed. The
manual and roadmap record this bounded expansion. All compilation uses the
sixteen logical CPUs; private NO_ROOT stages and disk guards protect the host.
Resource counters are retained but do not establish performance equivalence.

## Real 1-Wire export defect

Original ow builds localized own/owll method descriptors imported by ow_temp
and owc. The independent provider inspection rejected eight hidden interfaces
on each cross architecture even though compilation succeeded. ow now declares
EXPORT_SYMS=YES, matching other public bus providers; the existing amd64 and
new cross-target Bazel declarations preserve that policy. The complete fresh
244-control cross run and six amd64 controls pass after the fix. amd64 linker
script and export-helper inputs are explicitly before/after bound.

Six positive artifact tests require the eight actual descriptor edges. Six
negative tests relocalize the real native exporter and must reproduce exactly
those eight hidden-provider findings. They use actual consumer artifacts;
no invented symbol fixture replaces the real defect. External kernel/provider
availability and live loading remain outside these artifact checks.

## Observability and remaining work

The bounded 77-source scan finds eleven explicit instrumentation marker lines
in iiconf.c. Its four cross-target iicbus variants retain exact matching
compiled probe sections. Other scanned sources have no matching explicit
markers; framework/FBT coverage and live probe/audit delivery remain open.
Keep runtime checks for bus enumeration, GPIO permissions/events, I2C/SMBus
transactions and arbitration, RTC/sensor access, 1-Wire discovery/CRC/errors,
PWM configuration, SPI transfer/flash operations, interrupt/timeouts and
attach/detach/suspend lifetime behavior. No instrumentation source is changed.

Remaining cross kernels/modules/options, complete world/rescue/pkgbase,
aggregate installation, hardware/verified combined publication, independent
bootstrap and helper/toolchain hermeticity, semantic DWARF/source lookup,
VM/runtime and controlled CPU/memory/disk-I/O/disk-allocation/cache/sandbox
qualification remain required. Make remains production/default. BIP is excluded.
No host installation, upgrade, module load or reboot occurs.

## Retained failures and corrections

The first configured native inventory rejected an invalid repository-root
package spelling (//.: rather than //:); its metadata producer and emitted
label were corrected before fresh r2 profiles. The original provider defect,
raw filename differences and failed observer attempts remain retained.
The first filename controls omitted dependency files because of explicit
CFLAGS; the accepted controls restore ordinary per-object dependency flags.
The expanded controls also cover actual parent-component filename spellings.
No rejected attempt is counted as a pass. The amd64 observer was corrected to
use its existing unprefixed target names; its accepted r2 review passes.

## Selected leaves

- gpio/gpiobus
- gpio/gpioiic
- gpio/gpiokeys
- gpio/gpioled
- gpio/gpiopps
- gpio/gpiospi
- gpio/gpioths
- i2c/ads111x
- i2c/controllers/alpm
- i2c/controllers/amdpm
- i2c/controllers/amdsmb
- i2c/controllers/ichiic
- i2c/controllers/ichsmb
- i2c/controllers/intpm
- i2c/controllers/ismt
- i2c/controllers/nfsmb
- i2c/controllers/pcf
- i2c/controllers/viapm
- i2c/cyapa
- i2c/ds1307
- i2c/ds13rtc
- i2c/ds1672
- i2c/ds3231
- i2c/htu21
- i2c/hym8563
- i2c/icee
- i2c/if_ic
- i2c/iic
- i2c/iicbb
- i2c/iicbus
- i2c/iicsmb
- i2c/isl
- i2c/isl12xx
- i2c/jedec_dimm
- i2c/max44009
- i2c/mux/iic_gpiomux
- i2c/mux/iicmux
- i2c/mux/ltc430x
- i2c/mux/pca954x
- i2c/nxprtc
- i2c/pcf8574
- i2c/pcf8591
- i2c/rs5c372a
- i2c/rtc8583
- i2c/rv3032
- i2c/rx8803
- i2c/s35390a
- i2c/smb
- i2c/smbus
- i2c/tca64xx
- i2c/tmp461
- i2c/w83793g
- ow/ow
- ow/ow_temp
- ow/owc
- pwm/pwmbus
- pwm/pwmc
- spi/at45d
- spi/mx25l
- spi/spibus
- spigen

## Evidence

Under /usr/obj/usr/src/:

- bazel-cross-io-buses-work-r1-20261103/: declarations, original policy/fix
  bindings, source/dependency inventory, explicit filename mappings, guarded
  staging and reproduction scripts. ow-export-defect-r1.json retains rejection.
- bazel-cross-io-buses-context-r2-20261103/: accepted original source queries.
- bazel-cross-io-buses-make-r2-20261103/: 244 accepted untouched original builds.
- bazel-cross-io-buses-make-filename-controls-r3-20261103/: 52 explicit filename
  controls; earlier control attempts remain separately retained.
- bazel-cross-io-buses-{arm64,riscv}-{plain,ctf}-r2-20261103/: four accepted
  normal profiles/tests with corresponding -actual-capture directories.
- bazel-ow-export-amd64-{plain,ctf}-r2-20261103/: two accepted amd64 profiles.
- bazel-ow-export-amd64-make-r2-20261103/: six original amd64 controls.
- bazel-cross-io-buses-review-r4-20261103/: accepted strict cross artifact,
  compiler/input/link/install and provider/instrumentation review.
- bazel-ow-export-amd64-review-r2-20261103/: accepted amd64 regression review.
