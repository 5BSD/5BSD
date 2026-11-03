# VMM module qualification (November 2, 2026)

## Native declarations and original controls

The amd64 GENERIC vmm module now has explicit native declarations for 185
original module objects, in 183 source groups. It uses existing module/CTF,
source-header, component-object and kernel_constants rules. No C source,
original Make recipe, shared helper or compiler policy changes are introduced.
Original export stripping, object order and kernel package identity are retained.
The two custom VMX/SVM assembly recipes keep their original no-CTF policy.
Other source groups follow the selected CTF/debug settings.

Both VMX/SVM layout producers compile their actual genassym C sources with the
original common-symbol policy and selected kernel/debug inputs. The resulting
objects feed the maintained genassym script through declared native component
objects; the checked genoffset object is an explicit prerequisite. Layout
objects are excluded from the module link. Generated headers are not copied
from Make. Four original metadata-only compiler replays reproduce complete
original ELF objects byte-for-byte and record 454 prerequisite occurrences for
both profiles. Native header namespaces list precise consumed files and retain
original search precedence, including physical parent-package namespaces.

Adding the VMM source package relocates existing bhyve source/header labels to
their physical owner. The original instruction emulator and two I/O headers stay
in place with unchanged bytes. Root header views retain their existing logical
include prefixes and consumers. An additional actual native bhyve build passes
with the relocated labels. Its instruction-emulator and kernemu compiler actions
bind unchanged physical source/header inputs; actual dependency files, final link
parameters and output digest are retained. A reused libutil regression test is
not a bhyve runtime test. This proves the affected consumer build, not independent
full Make bhyve parity or guest execution.

## Current evidence

The native CTF/debug module passes its original runtime ELF/CTF and installation
comparison, with only the explicit build-ID/debug-link differences; both debug
CRCs verify. Its actual 185 compiler contexts reconcile 15,693 consumed
prerequisite occurrences per side and 204 selected-kernel option occurrences.
Complete ordered compiler/CTF-to-link identities and parameters are retained.
Both actual layout compiler/extractor chains independently pass original
macros/warnings/code options and 227 consumed occurrences; generated headers are
byte-for-byte identical to the originals. Original script and actual compiler
output/symlink/extractor input hashes are bound.

The native plain build passes, and the complete installed module is byte-for-byte
identical to Make with exact installation metadata. Its independent full
compiler/layout/link review passes the same 185 contexts, 15,693 consumed
occurrences, 204 option occurrences and two layout chains (227 occurrences).
All module and layout witnesses come from each successful profile's own log;
raw dependency files, layout outputs and link parameters were retained before
switching profiles. A bounded 185-source scan records 109 candidate
SDT/DTrace/KTR/audit lines including comments/macros; original compiled SDT/DTrace
sections and relocations are preserved. This is not live-event qualification.

Evidence: /usr/obj/usr/src/bazel-vmm-module-review-r1-20261102; original layout
chain inventory: bazel-vmm-generated-input-review-r1-20261102; metadata-only
helper replays: bazel-vmm-helper-dependency-controls-r1-20261102. Native builds
use maintained build-bsd format-5 inputs, sixteen logical CPUs and disk reserve
guards. These existing interfaces require no new frontend-C or manual option.

Separate DWARF/source lookup, runtime VM creation/execution, nondefault VMM
options, other targets and complete world/kernel/pkgbase/bootstrap/cache/runtime/
performance gates remain open. Make stays production/default. BIP is excluded;
no host installation, module loading, upgrade or reboot is performed.
