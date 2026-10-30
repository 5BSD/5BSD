# SPDX-License-Identifier: BSD-2-Clause
"""Actual packaged startup with real Lua contract parsing and injected loader calls."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[3]
HARNESS = r'''
local startup, policy, scenario = arg[1], arg[2], arg[3]
local base = scenario:gsub("^disk%-", ""):gsub("^plan%-", "")
local plan = scenario:sub(1,10) == "disk-plan-"
local disk = scenario:sub(1, 5) == "disk-"
local native_loadfile = loadfile
local events = {}
local function record(event) events[#events + 1] = event end
loadfile = function(path, mode, environment)
    assert(path == "/boot/boot-policy.lua" and mode == "t")
    assert(type(environment) == "table" and next(environment) == nil)
    record("contract")
    if scenario == "unauthenticated" then return nil, "injected verification failure" end
    return native_loadfile(policy, mode, environment)
end
require = function(name)
    record(name)
    if name == "cli" then return {} end
    if name == "config" then return {
        processFile = function(path, optional)
            assert(optional == false)
            record(path)
            return not ((base == "defaults-fail" and path == "/boot/defaults/loader.conf") or
                (base == "config-fail" and path == "/boot/loader.conf"))
        end,
        loadelf = function() record("loadelf"); return base ~= "kernel-fail" end,
    } end
    assert(name == "core")
    return {loadEntropy = function() record("entropy") end}
end
loader = {perform = function(command)
    if command == "verity-require" then
        record("require-image");return base == "require-fail" and 2 or 0
    end
    if command:sub(1, 14) == "verity-select " then
        assert(command == "verity-select /boot/images/base.verity /boot/roots/base.root " ..
            string.rep("0", 64) .. " 8 65536" ..
            (plan and (" /boot/root-transition.bin " .. arg[4]) or ""))
        record("select-image");return base == "select-fail" and 2 or 0
    end
    if command == "verity-preload" then
        record("preload-descriptor");return base == "preload-fail" and 2 or 0
    end
    assert(command == "boot"); record("boot")
    if base ~= "boot-return" then error("TEST_HANDOFF") end
end}
local ok, message = pcall(assert(native_loadfile(startup)))
assert(not ok)
local expected = {"contract"}
local continues = base == "valid" or base == "defaults-fail" or base == "config-fail" or
    base == "kernel-fail" or base == "boot-return" or base == "preload-fail" or
    base == "require-fail" or base == "select-fail"
if disk and continues then
    expected[#expected + 1] = "require-image"
    if base ~= "require-fail" then expected[#expected + 1] = "select-image" end
end
if continues and base ~= "require-fail" and base ~= "select-fail" then
    for _, value in ipairs({"cli", "config", "core", "/boot/defaults/loader.conf"}) do
        expected[#expected + 1] = value
    end
    if base ~= "defaults-fail" then expected[#expected + 1] = "/boot/loader.conf" end
    if base ~= "defaults-fail" and base ~= "config-fail" then
        expected[#expected + 1] = "loadelf"
        if base ~= "kernel-fail" then
            if disk then expected[#expected + 1] = "preload-descriptor" end
            if base ~= "preload-fail" then
                expected[#expected + 1] = "entropy"; expected[#expected + 1] = "boot"
            end
        end
    end
end
assert(table.concat(events, "|") == table.concat(expected, "|"), table.concat(events, "|"))
if base == "valid" then assert(message:find("TEST_HANDOFF", 1, true)) end
if base == "boot-return" then assert(message:find("verified boot returned", 1, true)) end
'''

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lua', default='/usr/libexec/flua')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('generation_boot', ROOT / 'tools/build/capimage/generation_boot.py')
    backend = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend)
    valid = backend.render_boot_policy({'version': 1, 'mode': 'preloaded'})
    cases = {name: valid for name in ('valid', 'defaults-fail', 'config-fail', 'kernel-fail', 'boot-return', 'unauthenticated')}
    cases.update({'missing': None, 'syntax': b'return {', 'nil': b'return nil',
                  'scalar': b'return 1', 'version': b'return {version=2,mode="preloaded"}',
                  'mode': b'return {version=1,mode="verity"}',
                  'unknown-field': b'return {version=1,mode="preloaded",image="/x"}',
                  'missing-field': b'return {version=1}', 'no-globals': b'return _G'})
    disk = backend.render_boot_policy(dict(version=1, mode='verity', image='/boot/images/base.verity',
        descriptor='/boot/roots/base.root', cache_blocks=8, heap_bytes=65536),
        dict(result='PASS', scope='collected-boot-transport-consistency',
             verity=dict(internal_consistency_verified=True, descriptor_sha256='0'*64)))
    for name in ('valid', 'require-fail', 'select-fail', 'preload-fail', 'defaults-fail',
                 'config-fail', 'kernel-fail', 'boot-return'):
        cases['disk-'+name] = disk
    for name, old, new in (
            ('path-space', b'/boot/images/base.verity', b'/boot/images/bad name'),
            ('path-parent', b'/boot/images/base.verity', b'/boot/../base.verity'),
            ('path-command', b'/boot/images/base.verity', b'/boot/base;boot'),
            ('path-alias', b'/boot/roots/base.root', b'/boot/images/base.verity'),
            ('digest', ('0'*64).encode(), b'xyz'),
            ('number-type', b'cache_blocks="8"', b'cache_blocks=8'),
            ('zero-heap', b'heap_bytes="65536"', b'heap_bytes="0"'),
            ('overflow', b'heap_bytes="65536"', b'heap_bytes="9223372036854775808"')):
        cases['disk-'+name] = disk.replace(old, new)
    plan_policy = dict(version=1, mode='verity', image='/boot/images/base.verity',
        descriptor='/boot/roots/base.root', cache_blocks=8, heap_bytes=65536,
        transition=dict(version=1, transport_fs='ufs', transport_device='/dev/gpt/boot',
                        provider='root', workers=2, cache_blocks=64,
                        window_bytes=131072, buffer_bytes=1048576))
    checked = dict(result='PASS', scope='collected-boot-transport-consistency',
        verity=dict(internal_consistency_verified=True, descriptor_sha256='0'*64))
    plan_payload = backend.render_boot_policy(plan_policy, checked)
    plan_hash = hashlib.sha256(backend.render_boot_transition(plan_policy, checked)).hexdigest()
    for name in ('valid','require-fail','select-fail','preload-fail','kernel-fail','boot-return'):
        cases['disk-plan-'+name] = plan_payload
    for name, old, new in (
            ('missing-pin', (', transition_sha256="'+plan_hash+'"').encode(), b''),
            ('bad-pin', plan_hash.encode(), b'xyz'),
            ('alias', b'/boot/root-transition.bin', b'/boot/images/base.verity'),
            ('path-command', b'/boot/root-transition.bin', b'/boot/a;boot'),
            ('path-parent', b'/boot/root-transition.bin', b'/boot/../a')):
        cases['disk-plan-'+name] = plan_payload.replace(old,new)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory); harness = root / 'test.lua'; harness.write_text(HARNESS)
        for name, payload in cases.items():
            policy = root / name
            if payload is not None:
                policy.write_bytes(payload)
            subprocess.run([args.lua, str(harness), str(ROOT / 'stand/lua/secureboot.lua'),
                            str(policy), name, plan_hash], check=True, timeout=3)
    print(f'PASS: {len(cases)} startup contract and prerequisite ordering cases; loader/verification calls injected')
if __name__ == '__main__':
    main()
