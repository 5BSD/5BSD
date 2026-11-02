-- SPDX-License-Identifier: BSD-2-Clause
--
-- The loader's required modules (stand/lua/config.lua): actual loader.conf
-- parsing and config.loadelf(); the loader, file system and kernel are
-- injected.  Usage: flua lua_required_modules_test.lua .../config.lua
local env, loads, present, files
loader = {
	machine_arch = "amd64",
	getenv = function(key) return env[key] end,
	setenv = function(key, value) env[key] = value; return 0 end,
	unsetenv = function(key) env[key] = nil end,
	printc = function() end,
	module_present = function(name) return present[name] == true end,
}
lfs = {
	attributes = function(path, what)
		assert(what == "mode")
		return files[path] and "file" or nil
	end,
}
function cli_execute_unparsed(command)
	local name = command:match("^load (%S+)$")
	assert(name, "unexpected command " .. command)
	loads[#loads + 1] = name
	return 0
end
package.preload.hook = function()
	return { registerType = function() end, runAll = function() end }
end
local text, config
local report = print
print = function() end
io = {
	open = function() return {} end,
	read = function() return text, #text end,
	close = function() return true end,
}

local REQUIRED = {
	"linux_common", "linux64", "linprocfs", "linsysfs", "vmm",
	"dtraceall", "hypertrace", "kinst", "fasttrap", "hwt", "zfs", "pf",
	"dummynet", "nullfs", "if_bridge", "if_epair", "fdescfs", "mqueuefs",
	"cuse", "mac_ntpd", "uvideo",
}

-- Boot with loader.conf TEXT; every required file exists unless MISSING
-- names it, and the kernel provides the modules in PROVIDED.  Return the
-- sorted list of modules the loader loaded.
local function boot(conf, provided, missing)
	env = { kernel_path = "/boot/kernel" }
	loads, present, files = {}, {}, {}
	for _, name in ipairs(provided or {}) do
		present[name] = true
	end
	for _, name in ipairs(REQUIRED) do
		if not (missing or {})[name] then
			files["/boot/kernel/" .. name .. ".ko"] = true
		end
	end
	-- A fresh copy: config.lua keeps its module table across calls.
	config = dofile(arg[1])
	config.loadKernel = function() return true end
	text = conf
	assert(config.processFile("/boot/loader.conf", false))
	assert(config.loadelf())
	table.sort(loads)
	return table.concat(loads, " ")
end

local function expect(got, want, what)
	if got ~= want then
		error(("%s:\n  got  %s\n  want %s"):format(what, got, want), 2)
	end
end

local function sorted(list)
	local copy = { table.unpack(list) }
	table.sort(copy)
	return table.concat(copy, " ")
end

-- A kernel without any of them gets the whole set.
expect(boot(""), sorted(REQUIRED), "bare kernel")

-- amd64 GENERIC: nothing it compiles in is loaded again; zfs.ko and
-- dtraceall.ko are recognized by the modules they register.
local generic = { "dtrace", "hwt", "zfsctrl", "pf", "dummynet", "nullfs",
	"if_bridge", "if_epair", "fdescfs", "mqueuefs", "cuse", "mac_ntpd" }
local modonly = "fasttrap hypertrace kinst linprocfs linsysfs linux64 " ..
	"linux_common uvideo vmm"
expect(boot("", generic), modonly, "GENERIC")

-- An absent file is skipped.
expect(boot("", generic, { vmm = true }),
	"fasttrap hypertrace kinst linprocfs linsysfs linux64 linux_common " ..
	"uvideo", "missing vmm.ko")

-- <name>_load="NO" and module_blacklist leave out one module each, without
-- force; the rest of the set is still loaded.
expect(boot('uvideo_load="NO"\n', generic),
	"fasttrap hypertrace kinst linprocfs linsysfs linux64 linux_common vmm",
	"uvideo_load=NO")
expect(boot('module_blacklist="vmm kinst"\n', generic),
	"fasttrap hypertrace linprocfs linsysfs linux64 linux_common uvideo",
	"module_blacklist")
expect(boot('zfs_load="NO"\npf_load="NO"\n'),
	(sorted(REQUIRED):gsub(" pf", ""):gsub(" zfs", "")),
	"zfs_load=NO on a kernel without ZFS")

-- The installer media's lines (release/Makefile INSTALLER_NOLOAD_KMODS)
-- keep ZFS, DTrace and pf on a kernel that lacks them.
local media = ""
for _, name in ipairs({ "linux_common", "linux64", "linprocfs", "linsysfs",
    "vmm", "hypertrace", "kinst", "fasttrap" }) do
	media = media .. name .. '_load="NO"\n'
end
expect(boot(media),
	"cuse dtraceall dummynet fdescfs hwt if_bridge if_epair mac_ntpd " ..
	"mqueuefs nullfs pf uvideo zfs", "installer media")

-- required_modules="NO" is the global switch.
expect(boot('required_modules="NO"\n'), "", "required_modules=NO")

-- A module the administrator also enables loads once.
expect(boot('vmm_load="YES"\n', generic), modonly, "vmm_load=YES")

report("PASS: required modules honour *_load=NO, module_blacklist and " ..
    "required_modules=NO")
