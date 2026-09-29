#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Late module startup uses the broker; early boot keeps its existing path."""
from pathlib import Path
import subprocess
import unittest

SRC = Path(__file__).resolve().parents[2]
RC = SRC / 'libexec/rc/rc.subr'
KLD = SRC / 'libexec/rc/rc.d/kld'

class ModuleStartup(unittest.TestCase):
    def invoke(self, modules, plane='YES', denied=False, early=False,
               restore_status=0, trace_restore=False, loaded=False):
        seams = '''
kldstat() { [ "__LOADED__" = YES ] || return 1; [ "$1" != -v ] || echo "$kld_list.ko"; return 0; }
kenv() { [ "$2" = capability_plane ] || return 1; printf '%s\\n' "$test_plane"; }
kldload() { echo "raw:$*"; }
sysextctl() { if [ "$1" = restore ]; then __TRACE_RESTORE__; return __RESTORE_STATUS__; fi; echo "broker:$*"; return __BROKER_STATUS__; }
info() { :; }
warn() { :; }
startmsg() { :; }
test_plane="$2"
kld_list="$3"
'''.replace('__BROKER_STATUS__', '1' if denied else '0')
        seams = seams.replace('__LOADED__', 'YES' if loaded else 'NO')
        seams = seams.replace('__RESTORE_STATUS__', str(restore_status))
        seams = seams.replace('__TRACE_RESTORE__', 'echo restore' if trace_restore else ':')
        if early:
            script = '. "$1"\n' + seams + '\nload_kld "$3"\n'
        else:
            # Execute the shipping script with only configuration discovery and
            # the final rc dispatcher replaced; exercise the real kld_start.
            script = KLD.read_text().replace('. /etc/rc.subr', '. "$1"\n' + seams)
            script = script.replace('load_rc_config $name', ':')
            script = script.replace('run_rc_command "$1"', 'kld_start')
        return subprocess.run(['sh', '-c', script, 'test', str(RC), plane, modules],
                              text=True, capture_output=True)

    def test_late_modules_use_broker_without_gpu_special_cases(self):
        result = self.invoke('i915kms amdgpu if_tun')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(),
                         ['broker:load i915kms', 'broker:load amdgpu', 'broker:load if_tun'])

    def test_denial_has_no_raw_fallback(self):
        result = self.invoke('i915kms', denied=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.strip(), 'broker:load i915kms')

    def test_explicit_plane_disable_uses_raw_load(self):
        for value in ('NO', 'no', 'Off', 'OFF', '0'):
            result = self.invoke('i915kms', value)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), 'raw:i915kms')

    def test_absent_or_unknown_loader_knob_keeps_broker(self):
        for value in ('', 'false', 'typo', '1'):
            result = self.invoke('i915kms', value)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), 'broker:load i915kms')

    def test_loaded_module_still_claims_broker_ownership(self):
        result = self.invoke('i915kms', loaded=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'broker:load i915kms')
        result = self.invoke('i915kms', loaded=True, denied=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.strip(), 'broker:load i915kms')

    def test_restore_runs_with_empty_kld_list(self):
        result = self.invoke('', trace_restore=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'restore')

    def test_restore_failure_stops_late_loads(self):
        result = self.invoke('i915kms', restore_status=69, trace_restore=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.strip(), 'restore')

    def test_early_boot_keeps_existing_path(self):
        result = self.invoke('geom_eli', early=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'raw:geom_eli')

class DeviceAutoload(unittest.TestCase):
    def invoke(self, plane='YES', denied=False, blocklist='', loaded=False):
        script = (SRC / 'libexec/rc/rc.d/devmatch').read_text()
        seams = r'''
kldstat() { return __KLD_STATUS__; }
kenv() { [ "$2" = capability_plane ] || return 1; printf '%s\n' "$test_plane"; }
sysctl() { :; }
devmatch() { printf '%s\n' if_iwlwifi.ko i915kms.ko; }
devctl() { echo "devctl:$*"; }
kldload() { echo "raw:$*"; }
sysextctl() { echo "broker:$*"; return __STATUS__; }
checkyesno() { return 1; }
warn() { :; }
startmsg() { :; }
test_plane="$1"
devmatch_blocklist="$2"
'''.replace('__STATUS__', '1' if denied else '0')
        seams = seams.replace('__KLD_STATUS__', '0' if loaded else '1')
        script = script.replace('. /etc/rc.subr', seams)
        script = script.replace('load_rc_config $name', ':')
        script = script.replace('one_nomatch="$2"', 'one_nomatch=')
        script = script.replace('run_rc_command "$1"', 'devmatch_start')
        return subprocess.run(['sh', '-c', script, 'test', plane, blocklist],
                              text=True, capture_output=True)

    def test_device_loads_use_broker_and_thaw_on_denial(self):
        for denied in (False, True):
            result = self.invoke(denied=denied)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ['devctl:freeze',
                'broker:load i915kms', 'broker:load if_iwlwifi', 'devctl:thaw'])

    def test_loaded_device_modules_still_claim_ownership(self):
        result = self.invoke(loaded=True)
        self.assertEqual(result.stdout.splitlines(), ['devctl:freeze',
            'broker:load i915kms', 'broker:load if_iwlwifi', 'devctl:thaw'])

    def test_blocklist_and_explicit_plane_disable(self):
        result = self.invoke('Off', blocklist='if_iwlwifi.ko')
        self.assertEqual(result.stdout.splitlines(),
                         ['devctl:freeze', 'raw:-n i915kms', 'devctl:thaw'])

if __name__ == '__main__':
    unittest.main()
