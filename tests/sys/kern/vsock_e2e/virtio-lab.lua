#!/usr/libexec/flua
--
-- Declarative bhyve VirtIO real-VM test orchestrator.
--

local lfs = require("lfs")
local lyaml = require("lyaml")
local unistd = require("posix.unistd")

local function die(message)
	io.stderr:write("virtio-lab: ", message, "\n")
	os.exit(2)
end

local function read_file(path)
	local file, error = io.open(path, "r")
	if file == nil then
		die(path .. ": " .. tostring(error))
	end
	local contents = file:read("*a")
	file:close()
	return contents
end

local function write_file(path, contents)
	local file, error = io.open(path, "w")
	if file == nil then
		die(path .. ": " .. tostring(error))
	end
	assert(file:write(contents))
	assert(file:close())
end

local function append_file(path, contents)
	local file, error = io.open(path, "a")
	if file == nil then
		die(path .. ": " .. tostring(error))
	end
	assert(file:write(contents))
	assert(file:close())
end

local function shell_quote(value)
	value = tostring(value)
	if value:find("\0", 1, true) ~= nil then
		die("NUL byte in command value")
	end
	return "'" .. value:gsub("'", "'\\''") .. "'"
end

local function command_ok(command)
	local ok, _, status = os.execute(command)
	return ok == true or status == 0
end

local function path_identity(path)
	local stat = io.popen("/usr/bin/stat -f '%HT\t%u\t%Lp' " ..
	    shell_quote(path) .. " 2>/dev/null", "r")
	if stat == nil then
		return nil
	end
	local line = stat:read("*l")
	stat:close()
	if line == nil then
		return nil
	end
	local kind, uid, permissions =
	    line:match("^([^\t]+)\t([0-9]+)\t([0-7]+)$")
	if kind == nil then
		die("cannot parse identity for " .. path)
	end
	return {
		kind = kind,
		uid = tonumber(uid),
		permissions = permissions,
	}
end

local function mkdir(path)
	local ok, error = lfs.mkdir(path)
	if not ok and lfs.attributes(path, "mode") ~= "directory" then
		die("cannot create " .. path .. ": " .. tostring(error))
	end
end

local function script_directory()
	local path = arg[0] or "."
	if path:find("/", 1, true) == nil then
		for directory in (os.getenv("PATH") or ""):gmatch("[^:]+") do
			local candidate = directory .. "/" .. path
			if lfs.attributes(candidate, "mode") == "file" then
				path = candidate
				break
			end
		end
	end
	local realpath = io.popen("/bin/realpath " .. shell_quote(path) ..
	    " 2>/dev/null", "r")
	if realpath ~= nil then
		local resolved = realpath:read("*l")
		realpath:close()
		if resolved ~= nil and resolved ~= "" then
			path = resolved
		end
	end
	return path:match("^(.*)/[^/]+$") or "."
end

local function list_contains(values, wanted)
	for _, value in ipairs(values or {}) do
		if value == wanted then
			return true
		end
	end
	return false
end

local function table_copy(source)
	local copy = {}
	for key, value in pairs(source or {}) do
		copy[key] = value
	end
	return copy
end

local function valid_scalar(value)
	return type(value) ~= "table" and
	    tostring(value):find("[\000\r\n\t]") == nil
end

local function validate_environment(environment, description)
	if environment ~= nil and type(environment) ~= "table" then
		die(description .. " must be a mapping")
	end
	for key, value in pairs(environment or {}) do
		if type(key) ~= "string" or
		    key:match("^[A-Z][A-Z0-9_]*$") == nil then
			die("invalid environment name in " .. description)
		end
		if not valid_scalar(value) then
			die("environment values must be control-free scalars in " ..
			    description)
		end
	end
end

local function validate_string_list(values, description, allow_empty)
	if type(values) ~= "table" then
		die(description .. " must be a sequence")
	end
	local count = 0
	local seen = {}
	for key, value in pairs(values) do
		count = count + 1
		if type(key) ~= "number" or key % 1 ~= 0 or key < 1 or
		    type(value) ~= "string" or value == "" then
			die(description .. " must contain non-empty strings")
		end
		if seen[value] then
			die(description .. " contains duplicate value " .. value)
		end
		seen[value] = true
	end
	if not allow_empty and count == 0 then
		die(description .. " must not be empty")
	end
end

local function merge_environment(base, overlay)
	local result = table_copy(base)
	for key, value in pairs(overlay or {}) do
		result[key] = tostring(value)
	end
	return result
end

local function parse_options(first)
	local options = {
		jobs = 1,
		profile = "smoke",
		sets = {},
	}
	local index = first
	while index <= #arg do
		local option = arg[index]
		if option == "--resume" then
			options.resume = true
			index = index + 1
		elseif option == "--prepare-host" then
			options.prepare_host = true
			index = index + 1
		elseif option == "--manifest" or option == "--profile" or
		    option == "--jobs" or option == "--iso" or
		    option == "--fivebsd-image" or
		    option == "--workdir" or option == "--bridge" or
		    option == "--uplink" or option == "--set" then
			local value = arg[index + 1]
			if value == nil then
				die(option .. " requires a value")
			end
			if option == "--manifest" then
				options.manifest = value
			elseif option == "--profile" then
				options.profile = value
			elseif option == "--jobs" then
				options.jobs = tonumber(value)
				if options.jobs == nil or options.jobs < 1 or
				    options.jobs > 32 or options.jobs % 1 ~= 0 then
					die("--jobs must be an integer from 1 through 32")
				end
			elseif option == "--iso" then
				options.iso = value
			elseif option == "--fivebsd-image" then
				options.fivebsd_image = value
			elseif option == "--workdir" then
				options.workdir = value
			elseif option == "--bridge" then
				options.bridge = value
			elseif option == "--uplink" then
				options.uplink = value
			else
				local key, setting = value:match("^([A-Z][A-Z0-9_]*)=(.*)$")
				if key == nil then
					die("--set requires NAME=value")
				end
				if not valid_scalar(setting) then
					die("--set value contains a control character")
				end
				options.sets[key] = setting
			end
			index = index + 2
		else
			die("unknown option: " .. option)
		end
	end
	return options
end

local executors = {
	["alpine-auto"] = "run-alpine-auto.sh",
	["alpine-multi-vsock"] = "run-alpine-multi-vsock.sh",
	["fivebsd-auto"] = "run-5bsd-auto.sh",
	["device-harness"] = "../vsock_device_harness/run.sh",
	["requirements"] = "../vsock_device_harness/validate-virtio-requirements.sh",
	["rx-harness"] = "../vsock_rx_harness/run.sh",
	["host-selftest"] = "host-tools-selftest.sh",
	["host-regression"] = "virtio-host-regression.sh",
	["orchestrator-probe"] = "virtio-lab-probe.sh",
}

local function load_manifest(path)
	local document = lyaml.load(read_file(path))
	if type(document) ~= "table" or document.version ~= 1 or
	    type(document.cases) ~= "table" then
		die("manifest must contain version: 1 and a cases sequence")
	end
	if document.defaults ~= nil and type(document.defaults) ~= "table" then
		die("defaults must be a mapping")
	end
	validate_environment(document.defaults and document.defaults.env,
	    "defaults.env")
	if document.allowed_overrides ~= nil then
		validate_string_list(document.allowed_overrides,
		    "allowed_overrides", true)
		for _, setting in ipairs(document.allowed_overrides) do
			if setting:match("^[A-Z][A-Z0-9_]*$") == nil then
				die("invalid allowed override: " .. setting)
			end
		end
	end
	if document.behavior_overrides ~= nil then
		validate_string_list(document.behavior_overrides,
		    "behavior_overrides", false)
		for _, setting in ipairs(document.behavior_overrides) do
			if not list_contains(document.allowed_overrides, setting) then
				die("behavior override is not allowed: " .. setting)
			end
			local covered = false
			for _, contract in ipairs(document.coverage or {}) do
				if type(contract) == "table" and
				    contract.variable == setting and
				    (contract.profiles == nil or
				    type(contract.profiles) == "table" and
				    list_contains(contract.profiles, "release")) then
					covered = true
				end
			end
			if not covered then
				die("behavior override lacks release coverage: " .. setting)
			end
		end
	end
	return document
end

local function validate_overrides(document, options)
	if document.allowed_overrides == nil then
		return
	end
	for key in pairs(options.sets) do
		if not list_contains(document.allowed_overrides, key) then
			die("override is not part of the manifest API: " .. key)
		end
	end
end

local function case_timeout(document, case)
	local timeout = tonumber(case.timeout or
	    (document.defaults and document.defaults.timeout) or 1800)
	if timeout == nil or timeout < 1 or timeout > 86400 or
	    timeout % 1 ~= 0 then
		die("invalid timeout for " .. case.id)
	end
	return timeout
end

local function validate_case(case, identifiers)
	if type(case) ~= "table" then
		die("each case must be a mapping")
	end
	if type(case.id) ~= "string" or
	    case.id:match("^[a-z0-9][a-z0-9._-]*$") == nil then
		die("invalid case id: " .. tostring(case.id))
	end
	if identifiers[case.id] then
		die("duplicate case id: " .. case.id)
	end
	identifiers[case.id] = true
	if executors[case.executor] == nil then
		die("unknown executor for " .. case.id .. ": " ..
		    tostring(case.executor))
	end
	validate_string_list(case.profiles, "profiles for " .. case.id, false)
	validate_string_list(case.resources or {}, "resources for " .. case.id, true)
	if case.exclusive ~= nil and type(case.exclusive) ~= "boolean" then
		die("exclusive must be boolean in " .. case.id)
	end
	if case.gate ~= nil and type(case.gate) ~= "boolean" then
		die("gate must be boolean in " .. case.id)
	end
	if case.gate and not case.exclusive then
		die("gate must be exclusive in " .. case.id)
	end
	validate_environment(case.env, case.id)
end

local function selected_cases(document, profile)
	local selected = {}
	local identifiers = {}
	local saw_non_gate = false
	for _, case in ipairs(document.cases) do
		validate_case(case, identifiers)
		case_timeout(document, case)
		if list_contains(case.profiles, profile) then
			if case.gate and saw_non_gate then
				die("gates must precede non-gate cases in profile " ..
				    profile .. ": " .. case.id)
			end
			saw_non_gate = saw_non_gate or not case.gate
			table.insert(selected, case)
		end
	end
	if #selected == 0 then
		die("profile selects no cases: " .. profile)
	end
	return selected
end

local function effective_environment(document, case, options, ordinal)
	local environment = merge_environment(
	    document.defaults and document.defaults.env, case.env)
	environment = merge_environment(environment, options.sets)
	if case.executor == "alpine-auto" or
	    case.executor == "alpine-multi-vsock" then
		environment.ISO = options.iso or "<required>"
		environment.GUEST_OS = "alpine"
	elseif case.executor == "fivebsd-auto" then
		environment.IMAGE = options.fivebsd_image or "<required>"
		environment.GUEST_OS = "5bsd"
	end
	environment.VM_FREE_GATES = environment.VM_FREE_GATES or "no"
	local port_lane = (ordinal - 1) * 1024
	if port_lane + 512 > 65535 - 7237 then
		die("profile has too many cases for collision-free port allocation")
	end
	if case.executor == "alpine-auto" then
		environment.CONSOLE_PORT = environment.CONSOLE_PORT or
		    tostring(10000 + ordinal * 4)
		environment.CID = environment.CID or tostring(1000 + ordinal * 4)
		environment.PORT_OFFSET = environment.PORT_OFFSET or
		    tostring(port_lane)
	elseif case.executor == "alpine-multi-vsock" then
		environment.CONSOLE_PORT1 = environment.CONSOLE_PORT1 or
		    tostring(10000 + ordinal * 4)
		environment.CONSOLE_PORT2 = environment.CONSOLE_PORT2 or
		    tostring(10001 + ordinal * 4)
		environment.CID1 = environment.CID1 or
		    tostring(1000 + ordinal * 4)
		environment.CID2 = environment.CID2 or
		    tostring(1001 + ordinal * 4)
		environment.PORT_OFFSET1 = environment.PORT_OFFSET1 or
		    tostring(port_lane)
		environment.PORT_OFFSET2 = environment.PORT_OFFSET2 or
		    tostring(port_lane + 512)
	elseif case.executor == "fivebsd-auto" then
		environment.CONSOLE_PORT = environment.CONSOLE_PORT or
		    tostring(10000 + ordinal * 4)
		environment.CID = environment.CID or tostring(1000 + ordinal * 4)
	end
	return environment
end

local function selector_matches(environment, selector)
	for key, expected in pairs(selector or {}) do
		if tostring(environment[key] or "") ~= tostring(expected) then
			return false
		end
	end
	return true
end

local function coverage_report(document, cases, options)
	local missing = 0
	local identifiers = {}
	for _, contract in ipairs(document.coverage or {}) do
		if type(contract) ~= "table" or type(contract.id) ~= "string" or
		    contract.id:match("^[a-z0-9][a-z0-9._-]*$") == nil or
		    identifiers[contract.id] then
			die("invalid or duplicate coverage contract id")
		end
		identifiers[contract.id] = true
		if type(contract.variable) ~= "string" or
		    contract.variable:match("^[A-Z][A-Z0-9_]*$") == nil then
			die("invalid coverage variable for " .. contract.id)
		end
		validate_string_list(contract.values,
		    "coverage values for " .. contract.id, false)
		if contract.profiles ~= nil then
			validate_string_list(contract.profiles,
			    "coverage profiles for " .. contract.id, false)
		end
		if contract.selector ~= nil and type(contract.selector) ~= "table" then
			die("coverage selector must be a mapping for " .. contract.id)
		end
		for key, value in pairs(contract.selector or {}) do
			if type(key) ~= "string" or
			    key:match("^[A-Z][A-Z0-9_]*$") == nil or
			    not valid_scalar(value) then
				die("invalid coverage selector for " .. contract.id)
			end
		end
		if contract.profiles == nil or
		    list_contains(contract.profiles, options.profile) then
			local found = {}
			for ordinal, case in ipairs(cases) do
				local environment =
				    effective_environment(document, case, options, ordinal)
				if selector_matches(environment, contract.selector) then
					found[tostring(environment[contract.variable] or "")] = true
				end
			end
			local absent = {}
			for _, value in ipairs(contract.values or {}) do
				value = tostring(value)
				if not found[value] then
					table.insert(absent, value)
				end
			end
			if #absent == 0 then
				print("COVERED\t" .. contract.id)
			else
				print("MISSING\t" .. contract.id .. "\t" ..
				    table.concat(absent, ","))
				missing = missing + 1
			end
		end
	end
	return missing
end

local function resources_conflict(left, right)
	for _, resource in ipairs(left.resources or {}) do
		if list_contains(right.resources, resource) then
			return true
		end
	end
	return false
end

local function can_start(case, active)
	if case.exclusive and next(active) ~= nil then
		return false
	end
	for _, running in pairs(active) do
		if running.case.exclusive or resources_conflict(case, running.case) then
			return false
		end
	end
	return true
end

local function tail(path, lines)
	local command = "/usr/bin/tail -n " .. tostring(lines) .. " " ..
	    shell_quote(path)
	os.execute(command)
end

local function emit_event(runroot, event, case_id, status, log)
	local record = table.concat({
	    os.date("!%Y-%m-%dT%H:%M:%SZ"),
	    event,
	    case_id,
	    tostring(status or ""),
	    log or "",
	}, "\t") .. "\n"
	append_file(runroot .. "/events.tsv", record)
	print(record:sub(1, -2))
	io.stdout:flush()
end

local function read_number(path)
	local file = io.open(path, "r")
	if file == nil then
		return nil
	end
	local value = tonumber(file:read("*l"))
	file:close()
	return value
end

local function process_parent(pid)
	if pid == nil or pid <= 1 or pid % 1 ~= 0 then
		return nil
	end
	local ps = io.popen("/bin/ps -p " .. tostring(pid) ..
	    " -o ppid= 2>/dev/null", "r")
	if ps == nil then
		return nil
	end
	local parent = tonumber(ps:read("*l"))
	ps:close()
	return parent
end

local function supervised_case_alive(status_path)
	local supervisor = read_number(status_path .. ".pid")
	local child = read_number(status_path .. ".child")
	return supervisor ~= nil and child ~= nil and
	    process_parent(child) == supervisor
end

local function stale_case_process_alive(status_path)
	local supervisor = read_number(status_path .. ".pid")
	local child = read_number(status_path .. ".child")
	if supervised_case_alive(status_path) then
		return false
	end
	return process_parent(supervisor) ~= nil or process_parent(child) ~= nil
end

local function start_case(document, case, options, runroot, ordinal)
	local environment = effective_environment(document, case, options, ordinal)
	local status = runroot .. "/status/" .. case.id
	local attempt_path = status .. ".attempt"
	local attempt = (read_number(attempt_path) or 0) + 1
	write_file(attempt_path, tostring(attempt) .. "\n")
	os.remove(status)
	local suffix = ".attempt" .. tostring(attempt)
	local case_workdir = runroot .. "/cases/" .. case.id .. suffix
	local log = runroot .. "/logs/" .. case.id .. suffix .. ".log"
	local pidfile = status .. ".pid"
	local child_pidfile = status .. ".child"
	os.remove(pidfile)
	os.remove(child_pidfile)
	environment.WORKDIR = case_workdir
	environment.VIRTIO_LAB_ATTEMPT = tostring(attempt)
	local assignments = {}
	for key, value in pairs(environment) do
		table.insert(assignments, key .. "=" .. shell_quote(value))
	end
	table.sort(assignments)
	local runner = script_directory() .. "/" .. executors[case.executor]
	local timeout = case_timeout(document, case)
	local wrapper = script_directory() .. "/virtio-lab-case.sh"
	local command = table.concat({
	    "/usr/sbin/daemon -f -P", shell_quote(pidfile),
	    "-p", shell_quote(child_pidfile),
	    "-o", shell_quote(log), "-M 0600 /usr/bin/env",
	    table.concat(assignments, " "),
	    "/bin/sh", shell_quote(wrapper), tostring(timeout),
	    shell_quote(status), shell_quote(runner),
	}, " ")
	if not command_ok(command) then
		die("failed to launch case " .. case.id)
	end
	emit_event(runroot, "START", case.id, "", log)
	return {
		case = case,
		log = log,
		child_pidfile = child_pidfile,
		pidfile = pidfile,
		started = os.time(),
		status = status,
	}
end

local function read_status(path)
	return read_number(path)
end

local function prepare_runroot(path, resume, expected_uid)
	local attributes = path_identity(path)
	if resume then
		if attributes == nil or attributes.kind ~= "Directory" or
		    attributes.uid ~= expected_uid or attributes.permissions ~= "700" then
			die("resume directory must be caller-owned mode 0700: " .. path)
		end
		for _, directory in ipairs({ "cases", "logs", "status" }) do
			if lfs.attributes(path .. "/" .. directory, "mode") ~=
			    "directory" then
				die("incomplete resume directory: " .. path)
			end
		end
		return
	elseif attributes ~= nil then
		die("run directory already exists: " .. path)
	end
	mkdir(path)
	if not command_ok("/bin/chmod 0700 " .. shell_quote(path)) then
		die("cannot protect run directory")
	end
	for _, directory in ipairs({ "cases", "logs", "status" }) do
		mkdir(path .. "/" .. directory)
	end
	write_file(path .. "/events.tsv", "time\tevent\tcase\tstatus\tlog\n")
end

local function run_configuration(document, options)
	local sha = io.popen("/sbin/sha256 -q " ..
	    shell_quote(options.manifest) .. " 2>/dev/null", "r")
	local digest = sha ~= nil and sha:read("*l") or nil
	if sha ~= nil then
		sha:close()
	end
	if digest == nil or digest:match("^[0-9a-f]+$") == nil then
		die("cannot hash manifest: " .. options.manifest)
	end
	local settings = {
		"version=1",
		"manifest_sha256=" .. digest,
		"profile=" .. options.profile,
		"iso=" .. tostring(options.iso or ""),
		"fivebsd_image=" .. tostring(options.fivebsd_image or ""),
	}
	for key, value in pairs(options.sets) do
		table.insert(settings, "set." .. key .. "=" .. tostring(value))
	end
	table.sort(settings)
	return table.concat(settings, "\n") .. "\n"
end

local function run_cases(document, cases, options)
	local id = io.popen("/usr/bin/id -u", "r")
	local effective_uid = id ~= nil and tonumber(id:read("*l")) or nil
	if id ~= nil then
		id:close()
	end
	local needs_root = false
	local needs_network_vm = false
	local needs_alpine_iso = false
	local needs_fivebsd_image = false
	for _, case in ipairs(cases) do
		if case.executor == "alpine-auto" or
		    case.executor == "alpine-multi-vsock" then
			needs_root = true
			needs_network_vm = true
			needs_alpine_iso = true
			if options.iso == nil then
				die("--iso (or ISO) is required by case " .. case.id)
			end
		elseif case.executor == "fivebsd-auto" then
			needs_root = true
			needs_fivebsd_image = true
			if options.fivebsd_image == nil then
				die("--fivebsd-image (or FIVEBSD_IMAGE) is required by case " ..
				    case.id)
			end
		end
	end
	for _, input in ipairs({
	    { needed = needs_alpine_iso, path = options.iso, option = "--iso" },
	    { needed = needs_fivebsd_image, path = options.fivebsd_image,
	      option = "--fivebsd-image" },
	}) do
		if input.needed then
			local mode = lfs.attributes(input.path, "mode")
			local file = mode == "file" and io.open(input.path, "rb") or nil
			if file == nil then
				die(input.option .. " must name a readable regular file: " ..
				    input.path)
			end
			file:close()
		end
	end
	if needs_root and effective_uid ~= 0 then
		die("real-VM profiles must execute as root")
	end
	if options.resume and options.workdir == nil then
		die("--resume requires --workdir")
	end
	if needs_root and options.jobs > 1 then
		for _, key in ipairs({
		    "CID", "CID1", "CID2", "CONSOLE_PORT", "CONSOLE_PORT1",
		    "CONSOLE_PORT2", "PORT_OFFSET", "PORT_OFFSET1", "PORT_OFFSET2",
		}) do
			if options.sets[key] ~= nil then
				die("--jobs > 1 cannot use global resource override " .. key)
			end
		end
	end
	if needs_network_vm and options.jobs > 1 then
		local bridge = options.sets.BRIDGE or
		    (document.defaults and document.defaults.env and
		    document.defaults.env.BRIDGE) or "bridge0"
		if not command_ok("/sbin/ifconfig " .. shell_quote(bridge) ..
		    " >/dev/null 2>&1") then
			local route = io.popen(
			    "/sbin/route -n get default 2>/dev/null", "r")
			local uplink
			if route ~= nil then
				for line in route:lines() do
					uplink = uplink or
					    line:match("^%s*interface:%s*([^%s]+)")
				end
				route:close()
			end
			local suggestion = "rerun with --prepare-host --bridge " .. bridge
			if uplink ~= nil then
				suggestion = suggestion .. " --uplink " .. uplink
			else
				suggestion = suggestion .. " --uplink INTERFACE"
			end
			die("parallel runs require managed host networking; " ..
			    suggestion)
		end
	end
	local needs_kernel_vsock = false
	local needs_checkpoint = false
	local needs_mac_control = false
	local prerequisite_errors = {}
	for _, case in ipairs(cases) do
		needs_kernel_vsock = needs_kernel_vsock or
		    list_contains(case.resources, "kernel-vsock")
		needs_mac_control = needs_mac_control or
		    case.executor == "host-regression"
		local environment = effective_environment(document, case, options, 1)
		needs_checkpoint = needs_checkpoint or
		    environment.CHECKPOINT_TEST == "yes"
	end
	if needs_mac_control and
	    lfs.attributes("/dev/mac_capability", "mode") ~= "char device" then
		table.insert(prerequisite_errors,
		    "host regression requires accessible /dev/mac_capability; " ..
		    "stop oracled or another process holding an isolation claim")
	end
	if needs_kernel_vsock then
		local provider = io.popen(
		    "/sbin/sysctl -n kern.vsock.userspace_providers 2>/dev/null", "r")
		local count = provider ~= nil and tonumber(provider:read("*l")) or nil
		if provider ~= nil then
			provider:close()
		end
		if count == nil then
			if lfs.attributes("/dev/vsock", "mode") == "char device" then
				table.insert(prerequisite_errors,
				    "running vsock kernel predates the multi-provider ABI " ..
				    "(missing kern.vsock.userspace_providers); install and " ..
				    "boot the kernel built from this source tree")
			else
				table.insert(prerequisite_errors,
				    "kernel-vsock profile requires /dev/vsock and " ..
				    "kern.vsock.userspace_providers (load or install vsock)")
			end
		elseif count ~= 0 then
			local resumed_provider = false
			if options.resume and options.workdir ~= nil then
				for _, case in ipairs(cases) do
					if list_contains(case.resources, "kernel-vsock") and
					    supervised_case_alive(options.workdir .. "/status/" ..
					    case.id) then
						resumed_provider = true
					end
				end
			end
			if not resumed_provider then
				table.insert(prerequisite_errors,
				    "kernel-vsock provider already active (count=" ..
				    tostring(count) ..
				    "); stop oracle/other VMM providers")
			end
		end
	end
	if needs_checkpoint and not command_ok(
	    "/sbin/sysctl -n kern.conftxt 2>/dev/null | " ..
	    "/usr/bin/grep -Eq " ..
	    shell_quote("^options[[:space:]]+BHYVE_SNAPSHOT([[:space:]]|$)")) then
		table.insert(prerequisite_errors,
		    "checkpoint profile requires a running BHYVE_SNAPSHOT kernel")
	end
	if #prerequisite_errors ~= 0 then
		die("host preflight failed:\n  - " ..
		    table.concat(prerequisite_errors, "\n  - "))
	end
	local runroot = options.workdir or
	    ("/tmp/virtio-lab-" .. os.date("!%Y%m%dT%H%M%SZ") ..
	    "-" .. tostring(unistd.getpid()))
	prepare_runroot(runroot, options.resume, effective_uid)
	local configuration = run_configuration(document, options)
	if options.resume then
		if read_file(runroot .. "/run.config") ~= configuration then
			die("resume configuration differs from the original run")
		end
		append_file(runroot .. "/events.tsv", table.concat({
		    os.date("!%Y-%m-%dT%H:%M:%SZ"), "RESUME", "-", "", "",
		}, "\t") .. "\n")
	else
		write_file(runroot .. "/run.config", configuration)
	end
	if not options.resume then
		write_file(runroot .. "/manifest.path",
		    (options.manifest or "") .. "\n")
	end
	local pending = {}
	local active = {}
	local passed, failed, blocked = 0, 0, 0
	for ordinal, case in ipairs(cases) do
		local status_path = runroot .. "/status/" .. case.id
		local pidfile = status_path .. ".pid"
		if options.resume and read_status(status_path) == 0 then
			passed = passed + 1
			emit_event(runroot, "REUSE", case.id, 0, runroot .. "/logs")
		elseif options.resume and supervised_case_alive(status_path) then
			local attempt = read_number(status_path .. ".attempt") or 1
			active[case.id] = {
				case = case,
				child_pidfile = status_path .. ".child",
				log = runroot .. "/logs/" .. case.id .. ".attempt" ..
				    tostring(attempt) .. ".log",
				pidfile = pidfile,
				started = os.time(),
				status = status_path,
			}
			emit_event(runroot, "REATTACH", case.id, "", active[case.id].log)
		elseif options.resume and stale_case_process_alive(status_path) then
			die("refusing to rerun case with an untracked live process: " ..
			    case.id)
		else
			table.insert(pending, { case = case, ordinal = ordinal })
		end
	end
	while #pending > 0 or next(active) ~= nil do
		local progress = true
		while progress do
			progress = false
			local active_count = 0
			for _ in pairs(active) do
				active_count = active_count + 1
			end
			if active_count < options.jobs then
				for index, item in ipairs(pending) do
					if can_start(item.case, active) then
						local running = start_case(document, item.case,
						    options, runroot, item.ordinal)
						active[item.case.id] = running
						table.remove(pending, index)
						progress = true
						break
					end
				end
			end
		end
		for id, running in pairs(active) do
			local status = read_status(running.status)
			if status == nil and os.time() - running.started >= 3 and
			    not supervised_case_alive(running.status) then
				status = 125
				write_file(running.status, tostring(status) .. "\n")
			end
			if status ~= nil then
				if status == 0 then
					passed = passed + 1
					emit_event(runroot, "PASS", id, status, running.log)
				else
					failed = failed + 1
					emit_event(runroot, "FAIL", id, status, running.log)
					tail(running.log, 30)
					if running.case.gate then
						for _, item in ipairs(pending) do
							blocked = blocked + 1
							emit_event(runroot, "BLOCKED", item.case.id,
							    "gate:" .. id, "")
						end
						pending = {}
					end
				end
				active[id] = nil
			end
		end
		if #pending > 0 or next(active) ~= nil then
			os.execute("/bin/sleep 1")
		end
	end
	local summary = string.format(
	    "passed=%d\nfailed=%d\nblocked=%d\ntotal=%d\n",
	    passed, failed, blocked, passed + failed + blocked)
	write_file(runroot .. "/summary", summary)
	io.write(summary)
	io.write("results=", runroot, "\n")
	if failed ~= 0 then
		os.exit(1)
	end
end

local host_state_directory = "/var/run/virtio-lab"

local function effective_uid()
	local id = io.popen("/usr/bin/id -u", "r")
	local uid = id ~= nil and tonumber(id:read("*l")) or nil
	if id ~= nil then
		id:close()
	end
	return uid
end

local function interface_name(value, description)
	if type(value) ~= "string" or value == "" or #value > 15 or
	    value:match("^[A-Za-z][A-Za-z0-9_.:-]*$") == nil then
		die(description .. " must be a valid interface name")
	end
	return value
end

local function interface_exists(name)
	return command_ok("/sbin/ifconfig " .. shell_quote(name) ..
	    " >/dev/null 2>&1")
end

local function bridge_members(name)
	local members = {}
	local output = io.popen("/sbin/ifconfig " .. shell_quote(name) ..
	    " 2>/dev/null", "r")
	if output == nil then
		return members
	end
	for line in output:lines() do
		local member = line:match("member:%s*([^%s]+)")
		if member ~= nil then
			members[member] = true
		end
	end
	output:close()
	return members
end

local function host_state_path(bridge)
	return host_state_directory .. "/bridge-" .. bridge
end

local function write_host_state(state)
	if lfs.attributes(host_state_directory, "mode") ~= "directory" then
		if not command_ok("/usr/bin/install -d -o root -g wheel -m 755 " ..
		    shell_quote(host_state_directory)) then
			die("cannot create " .. host_state_directory)
		end
	end
	local identity = path_identity(host_state_directory)
	if identity == nil or identity.kind ~= "Directory" or identity.uid ~= 0 or
	    identity.permissions ~= "755" then
		die(host_state_directory .. " must be a root-owned mode-0755 directory")
	end
	local path = host_state_path(state.bridge)
	local temporary = path .. ".tmp-" .. tostring(unistd.getpid())
	write_file(temporary, table.concat({
	    "bridge=" .. state.bridge,
	    "uplink=" .. state.uplink,
	    "bridge_created=" .. (state.bridge_created and "yes" or "no"),
	    "member_added=" .. (state.member_added and "yes" or "no"),
	    "",
	}, "\n"))
	if not command_ok("/bin/chmod 644 " .. shell_quote(temporary)) then
		os.remove(temporary)
		die("cannot protect host state file")
	end
	local ok, error = os.rename(temporary, path)
	if not ok then
		os.remove(temporary)
		die("cannot publish host state: " .. tostring(error))
	end
end

local function read_host_state(bridge)
	local path = host_state_path(bridge)
	local identity = path_identity(path)
	if identity == nil then
		return nil
	end
	if identity.kind ~= "Regular File" or identity.uid ~= 0 or
	    identity.permissions ~= "644" then
		die(path .. " must be a root-owned mode-0644 regular file")
	end
	local values = {}
	for line in read_file(path):gmatch("[^\n]+") do
		local key, value = line:match("^([a-z_]+)=([^=\r\n]+)$")
		if key == nil then
			die("invalid host state in " .. path)
		end
		values[key] = value
	end
	if values.bridge ~= bridge then
		die("host state bridge mismatch in " .. path)
	end
	interface_name(values.bridge, "state bridge")
	interface_name(values.uplink, "state uplink")
	if (values.bridge_created ~= "yes" and values.bridge_created ~= "no") or
	    (values.member_added ~= "yes" and values.member_added ~= "no") then
		die("invalid host state flags in " .. path)
	end
	return {
		bridge = values.bridge,
		uplink = values.uplink,
		bridge_created = values.bridge_created == "yes",
		member_added = values.member_added == "yes",
	}
end

local function host_prepare(options)
	if effective_uid() ~= 0 then
		die("host-prepare must execute as root")
	end
	local bridge = interface_name(options.bridge or "bridge0", "bridge")
	local uplink = interface_name(options.uplink, "uplink")
	if bridge == uplink then
		die("bridge and uplink must be different interfaces")
	end
	if not interface_exists(uplink) then
		die("uplink does not exist: " .. uplink)
	end
	local state = read_host_state(bridge)
	if state ~= nil and state.uplink ~= uplink then
		die(bridge .. " is managed with uplink " .. state.uplink ..
		    "; clean it before selecting " .. uplink)
	end
	if state == nil then
		state = {
			bridge = bridge,
			uplink = uplink,
			bridge_created = false,
			member_added = false,
		}
		write_host_state(state)
	end
	if not interface_exists(bridge) then
		if not command_ok("/sbin/ifconfig " .. shell_quote(bridge) ..
		    " create") then
			die("cannot create " .. bridge)
		end
		state.bridge_created = true
		state.member_added = false
		write_host_state(state)
	end
	local members = bridge_members(bridge)
	if not members[uplink] then
		if not command_ok("/sbin/ifconfig " .. shell_quote(bridge) ..
		    " addm " .. shell_quote(uplink)) then
			die("cannot add " .. uplink .. " to " .. bridge ..
			    "; run host-cleanup to roll back")
		end
		state.member_added = true
		write_host_state(state)
	end
	if not command_ok("/sbin/ifconfig " .. shell_quote(bridge) .. " up") then
		die("cannot bring " .. bridge .. " up; run host-cleanup to roll back")
	end
	print("ready")
	print("bridge=" .. bridge)
	print("uplink=" .. uplink)
	print("bridge_created=" .. (state.bridge_created and "yes" or "no"))
	print("member_added=" .. (state.member_added and "yes" or "no"))
end

local function host_status(options)
	local bridge = interface_name(options.bridge or "bridge0", "bridge")
	local state = read_host_state(bridge)
	print("bridge=" .. bridge)
	print("exists=" .. (interface_exists(bridge) and "yes" or "no"))
	if state == nil then
		print("managed=no")
		return
	end
	local members = bridge_members(bridge)
	print("managed=yes")
	print("uplink=" .. state.uplink)
	print("uplink_member=" .. (members[state.uplink] and "yes" or "no"))
	print("bridge_created=" .. (state.bridge_created and "yes" or "no"))
	print("member_added=" .. (state.member_added and "yes" or "no"))
end

local function host_cleanup(options)
	if effective_uid() ~= 0 then
		die("host-cleanup must execute as root")
	end
	local bridge = interface_name(options.bridge or "bridge0", "bridge")
	local state = read_host_state(bridge)
	if state == nil then
		die(bridge .. " has no virtio-lab ownership record; refusing cleanup")
	end
	if interface_exists(bridge) then
		local members = bridge_members(bridge)
		if state.bridge_created then
			for member in pairs(members) do
				if member ~= state.uplink then
					die(bridge .. " still has member " .. member ..
					    "; stop its VM and retry host-cleanup")
				end
			end
		end
		if state.member_added and members[state.uplink] and
		    not command_ok("/sbin/ifconfig " .. shell_quote(bridge) ..
		    " deletem " .. shell_quote(state.uplink)) then
			die("cannot remove " .. state.uplink .. " from " .. bridge)
		end
		if state.bridge_created and
		    not command_ok("/sbin/ifconfig " .. shell_quote(bridge) ..
		    " destroy") then
			die("cannot destroy " .. bridge)
		end
	end
	assert(os.remove(host_state_path(bridge)))
	print("clean")
	print("bridge=" .. bridge)
	print("uplink=" .. state.uplink)
end

local function usage()
	io.stderr:write([[
usage: virtio-lab.lua plan|coverage [options]
       virtio-lab.lua run [options]
       virtio-lab.lua status --workdir run-directory
       virtio-lab.lua cancel --workdir run-directory
       virtio-lab.lua host-prepare --bridge name --uplink name
       virtio-lab.lua host-status [--bridge name]
       virtio-lab.lua host-cleanup [--bridge name]
options:
  --manifest path   case manifest (default: virtio-lab.yaml beside script)
  --profile name    vmfree, smoke, release, checkpoint, or soak
  --jobs count      bounded parallel case count
  --iso path        Alpine virt ISO for real-VM cases
  --fivebsd-image path
                    immutable 5BSD raw base image
  --workdir path    new run directory, or existing directory for status
  --bridge name     managed shared bridge (default: bridge0)
  --uplink name     explicit physical uplink for host-prepare
  --prepare-host    idempotently prepare bridge before a run
  --resume          reuse passes and rerun failed or incomplete cases
  --set NAME=value  override a runner environment setting
]])
	os.exit(2)
end

local command = arg[1]
if command == nil or command == "-h" or command == "--help" then
	usage()
end
local options = parse_options(2)
options.iso = options.iso or os.getenv("ISO")
options.fivebsd_image = options.fivebsd_image or os.getenv("FIVEBSD_IMAGE")
options.manifest = options.manifest or
    (script_directory() .. "/virtio-lab.yaml")
for name, value in pairs({
    manifest = options.manifest,
    profile = options.profile,
    iso = options.iso,
    fivebsd_image = options.fivebsd_image,
    workdir = options.workdir,
    bridge = options.bridge,
    uplink = options.uplink,
}) do
	if value ~= nil and (not valid_scalar(value) or tostring(value) == "") then
		die(name .. " must be a non-empty control-free string")
	end
end

for option, setting in pairs({
    BRIDGE = options.bridge,
    UPLINK = options.uplink,
}) do
	if setting ~= nil then
		interface_name(setting, option:lower())
		if options.sets[option] ~= nil and
		    options.sets[option] ~= setting then
			die("--" .. option:lower() .. " conflicts with --set " ..
			    option .. "=" .. options.sets[option])
		end
		options.sets[option] = setting
	end
end
if options.sets.BRIDGE ~= nil then
	interface_name(options.sets.BRIDGE, "bridge")
end
if options.sets.UPLINK ~= nil then
	interface_name(options.sets.UPLINK, "uplink")
end
if options.prepare_host and command ~= "run" then
	die("--prepare-host is valid only with run")
end

if command == "host-prepare" then
	if options.uplink == nil then
		die("host-prepare requires --uplink")
	end
	host_prepare(options)
	os.exit(0)
elseif command == "host-status" then
	host_status(options)
	os.exit(0)
elseif command == "host-cleanup" then
	host_cleanup(options)
	os.exit(0)
end

if command == "status" or command == "cancel" then
	if options.workdir == nil then
		die(command .. " requires --workdir")
	end
	local status_directory = options.workdir .. "/status"
	local pidfiles = {}
	local has_status_directory =
	    lfs.attributes(status_directory, "mode") == "directory"
	local has_summary =
	    lfs.attributes(options.workdir .. "/summary", "mode") == "file"
	local has_events =
	    lfs.attributes(options.workdir .. "/events.tsv", "mode") == "file"
	if not has_status_directory and not has_summary and not has_events then
		die("run directory is inaccessible or is not a virtio-lab run: " ..
		    options.workdir)
	end
	if has_status_directory then
		for entry in lfs.dir(status_directory) do
			if entry:match("%.pid$") ~= nil then
				local pidfile = status_directory .. "/" .. entry
				local status_path = pidfile:gsub("%.pid$", "")
				if supervised_case_alive(status_path) then
					table.insert(pidfiles, pidfile)
				end
			end
		end
	end
	table.sort(pidfiles)
	if command == "cancel" then
		local id = io.popen("/usr/bin/id -u", "r")
		local effective_uid = id ~= nil and tonumber(id:read("*l")) or nil
		if id ~= nil then
			id:close()
		end
		local run_identity = path_identity(options.workdir)
		if run_identity == nil or run_identity.kind ~= "Directory" or
		    run_identity.permissions ~= "700" or
		    (effective_uid ~= 0 and run_identity.uid ~= effective_uid) then
			die("cancel requires root or a caller-owned mode-0700 run directory")
		end
		local cancelled = 0
		for _, pidfile in ipairs(pidfiles) do
			local child_pidfile = pidfile:gsub("%.pid$", ".child")
			local child_pid = read_number(child_pidfile)
			local supervisor_pid = read_number(pidfile)
			if child_pid ~= nil and
			    process_parent(child_pid) == supervisor_pid then
				os.execute("/bin/kill -TERM " .. tostring(child_pid))
				cancelled = cancelled + 1
			end
		end
		print("cancelled=" .. tostring(cancelled))
	else
		if #pidfiles ~= 0 then
			io.write("running\nactive=", tostring(#pidfiles), "\n")
		else
			local summary = io.open(options.workdir .. "/summary", "r")
			if summary ~= nil then
				io.write(summary:read("*a"))
				summary:close()
			else
				io.write("not-running\n")
			end
		end
		local events = io.open(options.workdir .. "/events.tsv", "r")
		if events ~= nil then
			io.write(events:read("*a"))
			events:close()
		end
	end
	os.exit(0)
end

local document = load_manifest(options.manifest)
validate_overrides(document, options)
local cases = selected_cases(document, options.profile)
if command == "plan" then
	for ordinal, case in ipairs(cases) do
		local environment =
		    effective_environment(document, case, options, ordinal)
		print(table.concat({
		    case.id,
		    case.executor,
		    tostring(case_timeout(document, case)),
		    table.concat(case.resources or {}, ","),
		    environment.DEVICES or "-",
		    environment.TRANSPORTS or environment.TRANSPORT or "-",
		    environment.CID or
		        table.concat({ environment.CID1 or "-",
		        environment.CID2 or "-" }, ","),
		    environment.PORT_OFFSET or
		        table.concat({ environment.PORT_OFFSET1 or "-",
		        environment.PORT_OFFSET2 or "-" }, ","),
		    environment.CONSOLE_PORT or
		        table.concat({ environment.CONSOLE_PORT1 or "-",
		        environment.CONSOLE_PORT2 or "-" }, ","),
		}, "\t"))
	end
	print("cases=" .. tostring(#cases))
	os.exit(coverage_report(document, cases, options) == 0 and 0 or 1)
elseif command == "coverage" then
	os.exit(coverage_report(document, cases, options) == 0 and 0 or 1)
elseif command == "run" then
	if options.prepare_host then
		if options.uplink == nil then
			die("--prepare-host requires --uplink")
		end
		host_prepare(options)
	end
	if coverage_report(document, cases, options) ~= 0 then
		die("selected profile does not satisfy its option coverage contract")
	end
	run_cases(document, cases, options)
else
	usage()
end
