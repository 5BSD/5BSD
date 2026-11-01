-- SPDX-License-Identifier: BSD-2-Clause
-- Adapt the maintained generator module API to explicitly declared outputs.
-- Parsing, compatibility selection and generated contents remain upstream APIs.
assert(#arg >= 5 and (#arg - 3) % 2 == 0,
    "usage: syscall_tables.lua module-root master config kind output [...]")
package.path = arg[1] .. "/?.lua"
package.cpath = ""
local config = require("config")
local FreeBSDSyscall = require("core.freebsd-syscall")
config.merge(arg[3])
config.mergeCompat()
local tbl = FreeBSDSyscall:new{sysfile = arg[2], config = config}
local supported = {
    init_sysent = true, libsys_h = true, syscall_h = true, syscall_mk = true,
    syscall_bzl = true, syscalls = true, syscalls_map = true,
    sysproto_h = true, systrace_args = true,
}
local seen = {}
for i = 4, #arg, 2 do
    local kind, output = arg[i], arg[i + 1]
    assert(supported[kind], "unknown syscall generator: " .. kind)
    assert(not seen[kind], "duplicate syscall generator: " .. kind)
    seen[kind] = true
    local module = require("scripts." .. (kind == "syscall_bzl" and "syscall_mk" or kind))
    if kind == "syscall_bzl" then
        module.generate_bazel(tbl, config, output)
    else
        module.generate(tbl, config, output)
    end
end
