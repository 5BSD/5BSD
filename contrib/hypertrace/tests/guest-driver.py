#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise actual guest-driver TX ownership and ELF validation with a fake ring."""
from pathlib import Path
import re, subprocess, sys
root = Path(__file__).resolve().parents[3]
out = Path(sys.argv[1]).resolve()
if not out.is_relative_to('/usr/obj'): raise SystemExit('Use /usr/obj')
out.mkdir(parents=True, exist_ok=True)
source = (root / 'sys/dev/virtio/dtrace/virtio_dtrace.c').read_text()
def function(name):
    m = re.search(r'static [^\n]+\n' + name + r'\(', source)
    if not m: raise SystemExit('Missing function: ' + name)
    return source[m.start():source.index('\n}', m.start()) + 2]
start = source.index('struct virtio_dtrace_control {')
end = source.index('\nstruct virtio_dtrace_queue', start)
header = (root / 'sys/dev/virtio/dtrace/virtio_dtrace.h').read_text()
constants = '\n'.join(x for x in header.splitlines() if re.match(r'#define\s+VIRTIO_DTRACE_', x))
maxlen = re.search(r'^#define VIRTIO_DTRACE_MAXELFLEN .*$', source,
    re.MULTILINE)
if maxlen is None: raise SystemExit('Missing guest wire length alias')
state_assert = re.search(r'^#define\tVTDTR_STATE_ASSERT\(sc\).*?\} while \(0\)$',
    source, re.MULTILINE | re.DOTALL)
if state_assert is None: raise SystemExit('Missing VTDTR_STATE_ASSERT')
(out / 'driver-types.inc').write_text(constants + '\n' + maxlen.group() +
    '\n' + source[start:end])
(out / 'driver-assert.inc').write_text(
    '#define KASSERT(e, m) assert(e)\n' + state_assert.group() + '\n')
parts = [function(x) for x in ('vtdtr_negotiate_features',
    'vtdtr_setup_features', 'vtdtr_vq_enable_intr',
    'vtdtr_enable_interrupts', 'vtdtr_cq_init', 'vtdtr_cq_enqueue',
    'vtdtr_cq_empty', 'vtdtr_cq_dequeue', 'vtdtr_elf_valid',
    'vtdtr_notify_ready', 'vtdtr_query_node_id',
    'ctrl_from_dttentry', 'vtdtr_identity', 'vtdtr_cleanup_query',
    'vtdtr_rekey_commit',
    'vtdtr_rekey_query_send',
    'vtdtr_clear_node_identity',
    'vtdtr_enqueue',
    'vtdtr_fill_desc', 'vtdtr_session_stop_notify', 'vtdtr_activate_fresh',
    'vtdtr_run', 'vtdtr_ctrl_process_event')]
parts += [function('vtdtr_queue_requeue_ctrl'),
          function('vtdtr_rxq_tq_intr')]
(out / 'driver-functions.inc').write_text('\n'.join(parts))
subprocess.run(['cc', '-pthread', '-Wall', '-Wextra', '-Werror',
    '-Wno-unused-parameter', '-fsanitize=address,undefined', '-I' + str(out),
    '-I' + str(root / 'sys'), str(Path(__file__).with_name('guest-driver.c')),
    '-o', str(out / 'guest-driver-test')], check=True)
subprocess.run([str(out / 'guest-driver-test')], check=True, timeout=30)
