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

local function valid_profile_name(name)

	return type(name) == "string" and
	    name:match("^[a-z0-9][a-z0-9._-]*$") ~= nil
end

local function profile_closure(document, requested)
	local active = {}
	local visiting = {}

	local function include(name)
		if visiting[name] then
			die("profile group cycle at " .. name)
		end
		if active[name] then
			return
		end
		active[name] = true
		local members = document.profile_groups and
		    document.profile_groups[name]
		if members == nil then
			return
		end
		visiting[name] = true
		for _, member in ipairs(members) do
			include(member)
		end
		visiting[name] = nil
	end

	include(requested)
	return active
end

local function profile_list_matches(profiles, active)

	for _, profile in ipairs(profiles or {}) do
		if active[profile] then
			return true
		end
	end
	return false
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
		case_ids = {},
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
		    option == "--uplink" or option == "--cid-lease-dir" or
		    option == "--case" or
		    option == "--set" then
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
			elseif option == "--cid-lease-dir" then
				options.cid_lease_dir = value
			elseif option == "--case" then
				table.insert(options.case_ids, value)
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
	["fivebsd-module-build"] = "build-5bsd-virtio-modules.sh",
	["vmm-module-build"] = "build-vmm-module.sh",
	["vmm-root"] = "../../vmm/run-vmm-root.sh",
	["kernel-contract-root"] = "run-kernel-contract-root.sh",
	-- Keep the architectural nested-state model in the ordinary rootless
	-- qualification lane.  The hardware executor remains a separate,
	-- explicitly privileged gate below; passing this model must never be
	-- interpreted as enabling nested VMX in the running kernel.
	["nested-vmx-model"] = "../../vmm/run-vmx-nested-model.sh",
	["nested-vmx-live"] = "../../vmm/run-vmx-nested-live.sh",
	["orchestrator-probe"] = "virtio-lab-probe.sh",
}

--
-- lyaml accepts duplicate mapping keys using last-key-wins semantics.  That
-- is unsafe for a qualification manifest because a duplicated executor,
-- timeout, gate, or environment key can silently replace the reviewed value.
-- This manifest uses plain mapping keys and space indentation, so reject a
-- duplicate at the same mapping level before parsing it.
--
local function reject_duplicate_mapping_keys(contents, path)
	local line_number = 0
	local seen = {}

	for line in (contents .. "\n"):gmatch("(.-)\n") do
		local indent_text, body
		local indent, key, sequence_item

		line_number = line_number + 1
		if line:match("^ *\t") ~= nil then
			die(path .. ":" .. line_number ..
			    ": tabs are not allowed for YAML indentation")
		end
		indent_text, body = line:match("^( *)(.*)$")
		indent = #indent_text
		sequence_item = body:match("^%-%s+") ~= nil
		if sequence_item then
			body = body:gsub("^%-%s+", "", 1)
			indent = indent + 2
		end
		for level in pairs(seen) do
			if level > indent or
			    (sequence_item and level >= indent) then
				seen[level] = nil
			end
		end
		key = body:match("^([%a_][%w_-]*):")
		if key ~= nil then
			seen[indent] = seen[indent] or {}
			if seen[indent][key] then
				die(path .. ":" .. line_number ..
				    ": duplicate mapping key: " .. key)
			end
			seen[indent][key] = true
		end
	end
end

local function load_manifest(path)
	local contents = read_file(path)
	reject_duplicate_mapping_keys(contents, path)
	local document = lyaml.load(contents)
	if type(document) ~= "table" or document.version ~= 1 or
	    type(document.cases) ~= "table" then
		die("manifest must contain version: 1 and a cases sequence")
	end
	if document.defaults ~= nil and type(document.defaults) ~= "table" then
		die("defaults must be a mapping")
	end
	if document.profile_groups ~= nil and
	    type(document.profile_groups) ~= "table" then
		die("profile_groups must be a mapping")
	end
	for name, members in pairs(document.profile_groups or {}) do
		if not valid_profile_name(name) then
			die("invalid profile group name: " .. tostring(name))
		end
		validate_string_list(members, "profile group " .. name, false)
		for _, member in ipairs(members) do
			if not valid_profile_name(member) then
				die("invalid member in profile group " .. name)
			end
		end
	end
	validate_environment(document.defaults and document.defaults.env,
	    "defaults.env")
	-- The nested architectural model is a VM-free preflight.  Do not let a
	-- manifest default turn it into an installed-kernel test when the lab is
	-- launched by root; the separate nested-vmx-live executor owns that scope.
	if document.defaults ~= nil and document.defaults.env ~= nil and
	    document.defaults.env.VMX_NESTED_MODEL_LIVE_ATF ~= nil then
		die("defaults.env must not set VMX_NESTED_MODEL_LIVE_ATF")
	end
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

local checkpoint_packed_variable = {
	net = "NET_PACKED",
	vsock = "VSOCK_PACKED",
	rng = "RNG_PACKED",
	crypto = "CRYPTO_PACKED",
	balloon = "BALLOON_PACKED",
	rtc = "RTC_PACKED",
	block = "BLOCK_PACKED",
	scsi = "SCSI_PACKED",
	console = "CONSOLE_PACKED",
	["9p"] = "NINEP_PACKED",
	fs = "FS_PACKED",
	input = "INPUT_PACKED",
	gpu = "GPU_PACKED",
	iommu = "IOMMU_PACKED",
	mem = "MEM_PACKED",
	pmem = "PMEM_PACKED",
	sound = "SOUND_PACKED",
}

local packed_trace_device = {
	net = "vtnet",
	vsock = "vtvsock",
	rng = "vtrnd",
	crypto = "vtcrypto",
	balloon = "vtballoon",
	rtc = "vtrtc",
	block = "vtblk",
	scsi = "vtscsi",
	console = "vtcon",
	["9p"] = "vt9p",
	fs = "vtfs",
	input = "vtinput",
	gpu = "vtgpu",
	iommu = "vtiommu",
	mem = "vtmem",
	pmem = "vtpmem",
	sound = "vtsnd",
}

local function single_case_device(case)
	local device
	local count = 0

	if type(case.env) ~= "table" then
		return nil
	end
	for candidate in tostring(case.env.DEVICES or ""):gmatch("[^,%s]+") do
		device = candidate
		count = count + 1
	end
	if count == 1 then
		return device
	end
	return nil
end

local function case_has_device(case, wanted)
	if type(case.env) ~= "table" then
		return false
	end
	for device in tostring(case.env.DEVICES or ""):gmatch("[^,%s]+") do
		if device == wanted then
			return true
		end
	end
	return false
end

local function case_has_profile(case, wanted)

	for _, profile in ipairs(case.profiles or {}) do
		if profile == wanted then
			return true
		end
	end
	return false
end

local function validate_checkpoint_ring_label(case)
	local device
	local variable
	local expected

	if case.id:match("^checkpoint%-") == nil or type(case.env) ~= "table" then
		return
	end
	device = single_case_device(case)
	if device == nil then
		return
	end
	variable = checkpoint_packed_variable[device]
	if variable == nil then
		return
	end
	expected = case.id:find("packed", 1, true) ~= nil and "yes" or "no"
	if tostring(case.env[variable] or "") ~= expected then
		die(case.id .. " must set " .. variable .. "=" .. expected ..
		    " so its ring-format label is authoritative")
	end
end

local function validate_packed_trace_evidence(case)
	local device
	local variable
	local expected_name

	if case.executor ~= "alpine-auto" or type(case.env) ~= "table" then
		return
	end
	-- The IOMMU is an implicit fabric device: endpoint cases name their
	-- endpoint devices in DEVICES and enable it with VIRTIO_IOMMU.  It
	-- therefore cannot rely on the single-DEVICES entry check below.
	if tostring(case.env.IOMMU_PACKED or "") == "yes" then
		if tostring(case.env.VIRTIO_IOMMU or "") ~= "yes" or
		    tostring(case.env.VERIFY_DEVICE_RING_NAME or "") ~= "vtiommu" or
		    tostring(case.env.VERIFY_DEVICE_RING_LAYOUT or "") ~= "packed" then
			die(case.id .. " must require packed host ring evidence from " ..
		    "vtiommu when IOMMU_PACKED=yes")
		end
	end
	device = single_case_device(case)
	if device == nil then
		return
	end
	variable = checkpoint_packed_variable[device]
	expected_name = packed_trace_device[device]
	if variable == nil or expected_name == nil or
	    tostring(case.env[variable] or "") ~= "yes" then
		return
	end
	if tostring(case.env.VERIFY_DEVICE_RING_NAME or "") ~= expected_name or
	    tostring(case.env.VERIFY_DEVICE_RING_LAYOUT or "") ~= "packed" then
		die(case.id .. " must require packed host ring evidence from " ..
		    expected_name)
	end
end

local function validate_active_checkpoint_evidence(case)
	local device
	local interval

	if case.executor ~= "alpine-auto" or type(case.env) ~= "table" or
	    tostring(case.env.CHECKPOINT_TEST or "") ~= "yes" then
		return
	end
	device = single_case_device(case)
	if device == "balloon" or case_has_device(case, "balloon") then
		interval = tonumber(case.env.BALLOON_STATS_INTERVAL or "0")
		if interval == nil or interval < 1 then
			die(case.id .. " must enable BALLOON_STATS_INTERVAL so " ..
		    "checkpoint qualification has active device state")
		end
	end
	if device == "mem" or case_has_device(case, "mem") then
		if tostring(case.env.CHECKPOINT_ACTIVE_MEM or "") ~= "yes" or
		    (tonumber(case.env.MEM_CHECKPOINT_ALLOC_MB or "0") or 0) < 1 then
			die(case.id .. " must enable CHECKPOINT_ACTIVE_MEM with " ..
			    "a positive MEM_CHECKPOINT_ALLOC_MB so checkpoint " ..
			    "qualification pins verified device-backed pages")
		end
	end
	if case_has_device(case, "vsock") and
	    tostring(case.env.CHECKPOINT_ACTIVE_VSOCK_REJECT or "") ~= "yes" then
		die(case.id .. " must enable CHECKPOINT_ACTIVE_VSOCK_REJECT so " ..
		    "checkpoint qualification proves active-backend rollback")
	end
	if case_has_device(case, "console") and
	    tostring(case.env.CHECKPOINT_ACTIVE_CONSOLE_REJECT or "") ~= "yes" then
		die(case.id .. " must enable CHECKPOINT_ACTIVE_CONSOLE_REJECT so " ..
		    "checkpoint qualification proves active-port rollback")
	end
	if case_has_device(case, "9p") and
	    tostring(case.env.CHECKPOINT_ACTIVE_9P_REJECT or "") ~= "yes" then
		die(case.id .. " must enable CHECKPOINT_ACTIVE_9P_REJECT so " ..
		    "checkpoint qualification proves active-fid rollback")
	end
	-- The active and idle virtio-fs checkpoint lanes intentionally exercise
	-- different reconstruction contracts.  Keep the names authoritative:
	-- otherwise a future manifest edit can leave a case labelled "active"
	-- while silently unmounting the export before snapshot, or call an idle
	-- case a repeated-restore test without retaining an open fid.
	if case.id:match("^checkpoint%-fs%-active") ~= nil then
		if tostring(case.env.CHECKPOINT_ACTIVE_FS or "") ~= "yes" or
		    tostring(case.env.CHECKPOINT_REPEAT_FS_RESTORE or "") ~= "yes" then
			die(case.id .. " must retain active virtio-fs state across a " ..
			    "repeated checkpoint restore")
		end
	end
	if case.id:match("^checkpoint%-fs%-idle") ~= nil then
		-- Defaults are merged after manifest shape validation.  Omission is
		-- therefore the reviewed default "no" here, while an explicit "yes"
		-- would make an idle-labelled lane misleading.
		if tostring(case.env.CHECKPOINT_ACTIVE_FS or "no") ~= "no" or
		    tostring(case.env.CHECKPOINT_REPEAT_FS_RESTORE or "no") ~= "no" then
			die(case.id .. " must remain an idle virtio-fs checkpoint lane")
		end
	end
end

local function token_set(value)
	local result = {}

	for token in tostring(value or ""):gmatch("%S+") do
		if result[token] then
			return nil
		end
		result[token] = true
	end
	return result
end

local function require_exact_tokens(case, variable, expected)
	local actual = token_set(case.env[variable])

	if actual == nil then
		die(case.id .. " has duplicate tokens in " .. variable)
	end
	for _, token in ipairs(expected) do
		if not actual[token] then
			die(case.id .. " must include " .. token .. " in " .. variable)
		end
		actual[token] = nil
	end
	if next(actual) ~= nil then
		die(case.id .. " has an unreviewed token in " .. variable)
	end
end

-- These are deliberately complete-machine checkpoint lanes, not convenient
-- labels for arbitrary multi-device cases.  Validate the configuration behind
-- each coverage marker so a manifest edit cannot claim graph coverage while
-- silently dropping a device, ring format, queue, or active-state workload.
local function validate_checkpoint_combination(case)
	local combination
	local expected_packed
	local packed_variables

	if type(case.env) ~= "table" then
		return
	end
	combination = tostring(case.env.CHECKPOINT_COMBINATION or "")
	if combination == "" then
		return
	end
	if tostring(case.env.CHECKPOINT_TEST or "") ~= "yes" then
		die(case.id .. " checkpoint combination must enable CHECKPOINT_TEST")
	end

	if combination == "alpine-all-split" or
	    combination == "alpine-all-packed" then
		if case.executor ~= "alpine-auto" then
			die(case.id .. " has the wrong executor for " .. combination)
		end
		require_exact_tokens(case, "DEVICES", {
		    "net", "vsock", "rng", "balloon", "rtc", "block", "scsi",
		    "console", "9p", "fs", "input", "gpu", "mem", "pmem",
		    "sound",
		})
		expected_packed = combination:match("packed$") and "yes" or "no"
		packed_variables = {
		    "NET_PACKED", "VSOCK_PACKED", "RNG_PACKED", "BALLOON_PACKED",
		    "RTC_PACKED", "BLOCK_PACKED", "SCSI_PACKED", "CONSOLE_PACKED",
		    "NINEP_PACKED", "FS_PACKED", "INPUT_PACKED", "GPU_PACKED",
		    "MEM_PACKED", "PMEM_PACKED", "SOUND_PACKED",
		}
		for _, variable in ipairs(packed_variables) do
			if tostring(case.env[variable] or "") ~= expected_packed then
				die(case.id .. " must set " .. variable .. "=" ..
				    expected_packed)
			end
		end
		for _, variable in ipairs({ "NET_QUEUES", "BLOCK_QUEUES",
		    "SCSI_QUEUES", "FS_QUEUES" }) do
			if (tonumber(case.env[variable] or "0") or 0) < 2 then
				die(case.id .. " must exercise multiple " .. variable)
			end
		end
		if tostring(case.env.CONSOLE_MULTIPORT or "") ~= "yes" or
		    (tonumber(case.env.INPUT_DEVICES or "0") or 0) < 2 or
		    (tonumber(case.env.BALLOON_STATS_INTERVAL or "0") or 0) < 1 or
		    tostring(case.env.RTC_ALARM or "") ~= "yes" or
		    tostring(case.env.CHECKPOINT_ACTIVE_FS or "") ~= "yes" or
		    tostring(case.env.CHECKPOINT_REPEAT_FS_RESTORE or "") ~= "yes" then
			die(case.id .. " must exercise multiport/input and active " ..
			    "balloon/RTC/virtio-fs state")
		end
	elseif combination == "fivebsd-all-split" or
	    combination == "fivebsd-all-packed" then
		if case.executor ~= "fivebsd-auto" or
		    tostring(case.env.FIVEBSD_CHECKPOINT_TEST or "") ~= "yes" then
			die(case.id .. " has the wrong 5BSD checkpoint executor")
		end
		require_exact_tokens(case, "CHECKPOINT_COMBINATION_DEVICES", {
		    "net", "vsock", "rng", "balloon", "block", "scsi", "console",
		    "gpu", "rtc", "input", "9p", "sound",
		})
		expected_packed = combination:match("packed$") and "yes" or "no"
		packed_variables = {
		    "FIVEBSD_NET_PACKED", "FIVEBSD_VSOCK_PACKED",
		    "FIVEBSD_RNG_PACKED", "BALLOON_PACKED", "FIVEBSD_BLOCK_PACKED",
		    "FIVEBSD_SCSI_PACKED", "FIVEBSD_CONSOLE_PACKED",
		    "FIVEBSD_GPU_PACKED", "FIVEBSD_RTC_PACKED",
		    "FIVEBSD_INPUT_PACKED", "FIVEBSD_NINEP_PACKED",
		    "FIVEBSD_SOUND_PACKED",
		}
		for _, variable in ipairs(packed_variables) do
			if tostring(case.env[variable] or "") ~= expected_packed then
				die(case.id .. " must set " .. variable .. "=" ..
				    expected_packed)
			end
		end
		for _, variable in ipairs({ "FIVEBSD_NET_QUEUES",
		    "FIVEBSD_BLOCK_QUEUES", "FIVEBSD_SCSI_QUEUES" }) do
			if (tonumber(case.env[variable] or "0") or 0) < 2 then
				die(case.id .. " must exercise multiple " .. variable)
			end
		end
		if (tonumber(case.env.FIVEBSD_CONSOLE_PORTS or "0") or 0) < 2 or
		    (tonumber(case.env.FIVEBSD_INPUT_DEVICES or "0") or 0) < 2 or
		    (tonumber(case.env.FIVEBSD_BALLOON_STATS_INTERVAL or "0") or 0) < 1 then
			die(case.id .. " must exercise multiport/input and active " ..
			    "balloon state")
		end
	else
		die(case.id .. " has unknown CHECKPOINT_COMBINATION=" .. combination)
	end
end

local function validate_iommu_translation_evidence(case)

	if case.executor ~= "alpine-auto" or type(case.env) ~= "table" or
	    tostring(case.env.VIRTIO_IOMMU or "") ~= "yes" then
		return
	end
	-- Enumeration, an iommu_group symlink, and negotiated
	-- ACCESS_PLATFORM do not prove that a device request reached the
	-- translated DMA path.  Release and checkpoint lanes therefore need
	-- the host translation probe, correlated with every endpoint found
	-- by the guest.  Soak lanes deliberately avoid retaining an
	-- unbounded trace and validate translation at their bounded
	-- observation intervals instead.
	if (case_has_profile(case, "release") or
	    case_has_profile(case, "checkpoint")) and
	    tostring(case.env.VERIFY_RING_ACTIVITY or "") ~= "yes" then
		die(case.id .. " must set VERIFY_RING_ACTIVITY=yes so live " ..
		    "IOMMU coverage observes translated DMA for every endpoint")
	end
end

local function validate_balloon_optional_evidence(case)

	if case.executor ~= "alpine-auto" or type(case.env) ~= "table" then
		return
	end
	-- PAGE_POISON intentionally prevents the host discard optimization for
	-- reported pages.  Keep separate live cases for the discard and
	-- poison-preservation paths so enabling both features cannot satisfy
	-- both claims with one branch.
	if case.id == "balloon-free-page-reporting-modern" and
	    (tostring(case.env.BALLOON_FREE_PAGE_REPORTING or "") ~= "yes" or
	    tostring(case.env.BALLOON_PAGE_POISON or "") ~= "no") then
		die(case.id .. " must enable reporting with PAGE_POISON=no so " ..
		    "the live lane proves host free-page discard")
	end
	if case.id == "balloon-page-poison-modern" and
	    (tostring(case.env.BALLOON_FREE_PAGE_REPORTING or "") ~= "yes" or
	    tostring(case.env.BALLOON_PAGE_POISON or "") ~= "yes") then
		die(case.id .. " must enable reporting with PAGE_POISON=yes so " ..
		    "the live lane proves poison preservation")
	end
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
	if case.executor == "nested-vmx-model" and case.env ~= nil and
	    case.env.VMX_NESTED_MODEL_LIVE_ATF ~= nil then
		die("VM-free nested model may not set VMX_NESTED_MODEL_LIVE_ATF: " ..
	    case.id)
	end
	validate_checkpoint_ring_label(case)
	validate_packed_trace_evidence(case)
	validate_active_checkpoint_evidence(case)
	validate_checkpoint_combination(case)
	validate_iommu_translation_evidence(case)
	validate_balloon_optional_evidence(case)
end

local function selected_cases(document, profile, requested_ids)
	local selected = {}
	local identifiers = {}
	local requested = {}
	local matched = {}
	local saw_non_gate = false
	local active_profiles = profile_closure(document, profile)
	for _, identifier in ipairs(requested_ids or {}) do
		if type(identifier) ~= "string" or
		    identifier:match("^[a-z0-9][a-z0-9._-]*$") == nil then
			die("invalid --case id: " .. tostring(identifier))
		end
		if requested[identifier] then
			die("duplicate --case id: " .. identifier)
		end
		requested[identifier] = true
	end
	for _, case in ipairs(document.cases) do
		validate_case(case, identifiers)
		case_timeout(document, case)
		if profile_list_matches(case.profiles, active_profiles) then
			if case.gate and saw_non_gate then
				die("gates must precede non-gate cases in profile " ..
				    profile .. ": " .. case.id)
			end
			saw_non_gate = saw_non_gate or not case.gate
			if next(requested) == nil or requested[case.id] then
				table.insert(selected, case)
				matched[case.id] = true
			end
		end
	end
	for identifier, _ in pairs(requested) do
		if not identifiers[identifier] then
			die("unknown --case id: " .. identifier)
		elseif not matched[identifier] then
			die("--case " .. identifier .. " is not in profile " .. profile)
		end
	end
	if #selected == 0 then
		if next(requested) ~= nil then
			die("--case selection is empty")
		end
		die("profile selects no cases: " .. profile)
	end
	return selected
end

local function device_list_contains(devices, wanted)
	for device in tostring(devices or ""):gmatch("[^,%s]+") do
		if device == wanted then
			return true
		end
	end
	return false
end

local function assign_port_lanes(document, cases, options)
	local next_lane = 0
	local lane_width = 512
	local max_base_port = 7473

	for _, case in ipairs(cases) do
		local environment = merge_environment(
		    document.defaults and document.defaults.env, case.env)
		environment = merge_environment(environment, options.sets)
		local lanes = 0
		if case.executor == "alpine-multi-vsock" then
			lanes = 2
		elseif case.executor == "alpine-auto" and
		    device_list_contains(environment.DEVICES, "vsock") then
			lanes = 1
		end
		if lanes ~= 0 then
			case._port_lane = next_lane * lane_width
			next_lane = next_lane + lanes
		end
	end
	if next_lane * lane_width > 65535 - max_base_port then
		die("profile has too many concurrent vsock port namespaces")
	end
end

local function effective_environment(document, case, options, ordinal,
    resource_assignment)
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
	local port_lane = case._port_lane or 0
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
	elseif device_list_contains(environment.DEVICES, "vsock") then
		--
		-- CID leasing is a property of a case that uses an AF_VSOCK
		-- endpoint, not of the particular VM runner.  In particular, the
		-- rootless scheduler probes deliberately exercise the same lease
		-- path without launching bhyve.
		--
		environment.CID = environment.CID or tostring(1000 + ordinal * 4)
		environment.CONSOLE_PORT = environment.CONSOLE_PORT or
		    tostring(10000 + ordinal * 4)
	end
	for key, value in pairs(resource_assignment or {}) do
		environment[key] = value
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
	local active_profiles = profile_closure(document, options.profile)
	--
	-- This command proves that the selected declarative profile contains every
	-- required option combination.  It deliberately does not read a result
	-- directory or infer that a guest booted: `run` and its terminal summary
	-- own that evidence.  Keep the existing COVERED records below because they
	-- are the stable profile-preflight interface, but make the scope visible to
	-- a human invoking `coverage` by itself.
	--
	print("SCOPE\tdeclarative-profile; runtime results are not implied")
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
		if contract.tokens ~= nil and type(contract.tokens) ~= "boolean" then
			die("coverage tokens must be a boolean for " .. contract.id)
		end
		for key, value in pairs(contract.selector or {}) do
			if type(key) ~= "string" or
			    key:match("^[A-Z][A-Z0-9_]*$") == nil or
			    not valid_scalar(value) then
				die("invalid coverage selector for " .. contract.id)
			end
		end
		if contract.profiles == nil or
		    profile_list_matches(contract.profiles, active_profiles) then
			local found = {}
			for ordinal, case in ipairs(cases) do
				local environment =
				    effective_environment(document, case, options, ordinal)
				if selector_matches(environment, contract.selector) then
					local actual =
					    tostring(environment[contract.variable] or "")
					if contract.tokens then
						for token in actual:gmatch("%S+") do
							found[token] = true
						end
					else
						found[actual] = true
					end
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

-- A PID/PPID pair is not an authority to signal a process: both values can
-- be recycled between an interrupted manager and a later --resume or cancel
-- invocation.  Record the same stable process identity used by the case
-- wrapper (start time plus command, hashed by the host utility) before the
-- manager treats a daemon-supervised case as its own.
local function process_fingerprint(pid)
	if pid == nil or pid <= 1 or pid % 1 ~= 0 then
		return nil
	end
	local process = io.popen("/bin/ps -p " .. tostring(pid) ..
	    " -o lstart= -o command= 2>/dev/null", "r")
	if process == nil then
		return nil
	end
	local identity = process:read("*l")
	local closed = process:close()
	-- sha256(1) accepts an empty stream.  A vanished process must not acquire
	-- the digest of that stream as a valid cancellation or resume identity.
	if identity == nil or identity == "" or not closed then
		return nil
	end
	local hash = io.popen("/usr/bin/printf '%s\\n' " .. shell_quote(identity) ..
	    " | /sbin/sha256 -q", "r")
	if hash == nil then
		return nil
	end
	local fingerprint = hash:read("*l")
	hash:close()
	if fingerprint == nil or fingerprint:match("^[0-9a-f]+$") == nil or
	    #fingerprint ~= 64 then
		return nil
	end
	return fingerprint
end

local function process_command(pid)
	if pid == nil or pid <= 1 or pid % 1 ~= 0 then
		return nil
	end
	local process = io.popen("/bin/ps -p " .. tostring(pid) ..
	    " -o command= 2>/dev/null", "r")
	if process == nil then
		return nil
	end
	local command = process:read("*l")
	local closed = process:close()
	if command == nil or command == "" or not closed then
		return nil
	end
	return command
end

local function recorded_process_fingerprint(path)
	local file = io.open(path .. ".fingerprint", "r")
	if file == nil then
		return nil
	end
	local expected = file:read("*l")
	file:close()
	if expected == nil or expected:match("^[0-9a-f]+$") == nil or
	    #expected ~= 64 then
		return nil
	end
	return expected
end

local function process_fingerprint_value_matches(expected, pid)
	return expected ~= nil and expected == process_fingerprint(pid)
end

local function process_fingerprint_matches(path, pid)
	return process_fingerprint_value_matches(
	    recorded_process_fingerprint(path), pid)
end

-- daemon(8) publishes its PID files before its child necessarily finishes the
-- exec chain from env(1) into the case wrapper.  A fingerprint captured at
-- that boundary can therefore become stale without the PID changing.  Only
-- the owning scheduler may fill this control-plane metadata, and it publishes
-- cancellation authority only after the same parent/child identities survive
-- two bounded status scans.  A later cancel/status invocation never turns an
-- unrecorded or merely pending PID into signal authority.
local function record_supervised_case_identity(status_path)
	local supervisor_path = status_path .. ".pid"
	local child_path = status_path .. ".child"
	local supervisor_pending = supervisor_path .. ".pending"
	local child_pending = child_path .. ".pending"
	local supervisor = read_number(status_path .. ".pid")
	local child = read_number(status_path .. ".child")
	local supervisor_fingerprint, child_fingerprint
	local child_command
	if supervisor == nil or child == nil or
	    process_parent(child) ~= supervisor then
		return false
	end
	child_command = process_command(child)
	if child_command == nil or child_command:find(
	    script_directory() .. "/virtio-lab-case.sh", 1, true) == nil then
		-- daemon(8)'s pre-exec env(1) child is not yet the supervised
		-- wrapper and must never become cancellation authority.
		return false
	end
	supervisor_fingerprint = process_fingerprint(supervisor)
	child_fingerprint = process_fingerprint(child)
	if supervisor_fingerprint == nil or child_fingerprint == nil or
	    read_number(supervisor_path) ~= supervisor or
	    read_number(child_path) ~= child or
	    process_parent(child) ~= supervisor then
		return false
	end
	if recorded_process_fingerprint(supervisor_pending) ==
	    supervisor_fingerprint and
	    recorded_process_fingerprint(child_pending) == child_fingerprint then
		write_file(supervisor_path .. ".fingerprint",
		    supervisor_fingerprint .. "\n")
		write_file(child_path .. ".fingerprint", child_fingerprint .. "\n")
		os.remove(supervisor_pending .. ".fingerprint")
		os.remove(child_pending .. ".fingerprint")
		return true
	end
	-- A changed observation restarts stabilization and revokes any partial
	-- authority left by an interrupted launch attempt.
	os.remove(supervisor_path .. ".fingerprint")
	os.remove(child_path .. ".fingerprint")
	write_file(supervisor_pending .. ".fingerprint",
	    supervisor_fingerprint .. "\n")
	write_file(child_pending .. ".fingerprint", child_fingerprint .. "\n")
	return false
end

-- Return a captured, verified identity rather than merely a boolean when a
-- caller will later act on the process.  In particular cancel(1) rechecks
-- this captured identity immediately before kill(2), so PID reuse between
-- directory enumeration and signal delivery cannot retarget a signal.
local function supervised_case_identity(status_path)
	local supervisor = read_number(status_path .. ".pid")
	local child = read_number(status_path .. ".child")
	local supervisor_fingerprint =
	    recorded_process_fingerprint(status_path .. ".pid")
	local child_fingerprint =
	    recorded_process_fingerprint(status_path .. ".child")
	if supervisor == nil or child == nil or
	    process_parent(child) ~= supervisor or
	    not process_fingerprint_value_matches(supervisor_fingerprint, supervisor) or
	    not process_fingerprint_value_matches(child_fingerprint, child) then
		return nil
	end
	return {
		supervisor = supervisor,
		child = child,
		supervisor_fingerprint = supervisor_fingerprint,
		child_fingerprint = child_fingerprint,
	}
end

local function supervised_case_alive(status_path)
	return supervised_case_identity(status_path) ~= nil
end

local function stale_case_process_alive(status_path)
	local supervisor = read_number(status_path .. ".pid")
	local child = read_number(status_path .. ".child")
	if supervised_case_alive(status_path) then
		return false
	end
	-- A live parent/child pair with missing or mismatched fingerprints is not
	-- safe to adopt, cancel, or rerun over.  It may be a corrupted control
	-- record or a recycled PID pair; either way, fail closed and require the
	-- operator to let it exit before resuming.  A lone matching process is
	-- likewise a possible reparented case helper and must block a retry.
	return (supervisor ~= nil and child ~= nil and
	    process_parent(child) == supervisor) or
	    process_fingerprint_matches(status_path .. ".pid", supervisor) or
	    process_fingerprint_matches(status_path .. ".child", child)
end

-- One run directory has one scheduler.  In particular, a resumed supervisor
-- owns release of its case CID leases, so two concurrent --resume commands
-- must not race to reap the same completed case.  A stale owner is reclaimed
-- only after its PID is demonstrably absent; PID reuse is conservatively busy.
local function run_manager_lease_acquire(runroot)
	local path = runroot .. "/manager.lock"
	local owner_path = path .. "/owner"
	local owner, file

	if not lfs.mkdir(path) then
		file = io.open(owner_path, "r")
		owner = file ~= nil and tonumber(file:read("*l")) or nil
		if file ~= nil then
			file:close()
		end
		if owner ~= nil and process_parent(owner) ~= nil then
			die("run directory is already managed by PID " .. tostring(owner))
		end
		if not os.remove(owner_path) or not lfs.rmdir(path) then
			die("cannot reclaim stale run-manager lease: " .. runroot)
		end
		if not lfs.mkdir(path) then
			die("cannot acquire run-manager lease: " .. runroot)
		end
	end
	local wrote, closed
	file = io.open(owner_path, "w")
	if file ~= nil then
		wrote = file:write(tostring(unistd.getpid()), "\n")
		closed = file:close()
	end
	if file == nil or not wrote or not closed or
	    not command_ok("/bin/chmod 600 " .. shell_quote(owner_path)) then
		os.remove(owner_path)
		lfs.rmdir(path)
		die("cannot publish run-manager lease: " .. runroot)
	end
	return { owner = tostring(unistd.getpid()), path = path }
end

local function run_manager_lease_release(lease)
	local owner_path = lease.path .. "/owner"
	local file = io.open(owner_path, "r")
	local owner = file ~= nil and file:read("*l") or nil
	if file ~= nil then
		file:close()
	end
	if owner ~= lease.owner or not os.remove(owner_path) or
	    not lfs.rmdir(lease.path) then
		die("run-manager lease ownership changed unexpectedly")
	end
end

--
-- A test run may be parallel internally and may also overlap another
-- independently invoked virtio-lab process.  The kernel and TCP bind are the
-- authoritative collision checks, but avoid reaching them with a known
-- collision: reserve every real-VM CID and console TCP port in a caller-owned
-- directory for the lifetime of its supervised case.  mkdir(2) gives this
-- small management layer an atomic claim without a long-lived lock or a
-- polling allocator.
--
local function resource_lease_directory(options, owner_uid)
	local path = options.cid_lease_dir or "/var/run/virtio-lab/cid-leases"
	local identity = path_identity(path)

	if identity == nil then
		if owner_uid ~= 0 then
			die("resource lease directory must already exist for a non-root run: " ..
			    path)
		end
		if not command_ok("/usr/bin/install -d -o root -g wheel -m 700 " ..
		    shell_quote(path)) then
			die("cannot create resource lease directory: " .. path)
		end
		identity = path_identity(path)
	end
	if identity == nil or identity.kind ~= "Directory" or
	    identity.uid ~= owner_uid or
	    identity.permissions ~= "700" then
		die("resource lease directory must be caller-owned mode 0700: " .. path)
	end
	return path
end

local function parse_guest_cid(value, description)
	local max_guest_cid = 4294967295

	if type(value) ~= "string" or value:match("^[0-9]+$") == nil then
		die(description .. " must be a decimal CID")
	end
	local cid = tonumber(value)
	if cid == nil or cid < 3 or cid > max_guest_cid or cid % 1 ~= 0 then
		die(description .. " must be from 3 through 4294967295")
	end
	return cid
end

local function parse_tcp_port(value, description)
	if type(value) ~= "string" or value:match("^[0-9]+$") == nil then
		die(description .. " must be a decimal TCP port")
	end
	local port = tonumber(value)
	if port == nil or port < 1 or port > 65535 or port % 1 ~= 0 then
		die(description .. " must be from 1 through 65535")
	end
	return port
end

local function case_uses_vsock(case, environment)
	return case.executor == "alpine-multi-vsock" or
	    case.executor == "fivebsd-auto" or
	    device_list_contains(environment.DEVICES, "vsock")
end

local function case_uses_console(environment)
	return environment.CONSOLE_PORT ~= nil or
	    environment.CONSOLE_PORT1 ~= nil or
	    environment.CONSOLE_PORT2 ~= nil
end

local function resource_lease_try(directory, name, description, owner)
	local path = directory .. "/" .. name
	local ok, error = lfs.mkdir(path)

	if not ok then
		if lfs.attributes(path, "mode") == "directory" then
			return nil
		end
		die("cannot create " .. description .. " lease: " ..
		    tostring(error))
	end
	local owner_path = path .. "/owner"
	local file, write_error = io.open(owner_path, "w")
	local wrote, closed
	if file ~= nil then
		wrote = file:write(owner, "\n")
		closed = file:close()
	end
	if file == nil or not wrote or not closed or
	    not command_ok("/bin/chmod 600 " .. shell_quote(owner_path)) then
		os.remove(owner_path)
		lfs.rmdir(path)
		die("cannot publish " .. description .. " lease: " ..
		    tostring(write_error))
	end
	return { description = description, owner = owner, path = path }
end

local function cid_lease_try(directory, cid, owner)
	return resource_lease_try(directory, tostring(cid),
	    "CID " .. tostring(cid), owner)
end

local function tcp_port_lease_try(directory, port, owner)
	return resource_lease_try(directory, "tcp-" .. tostring(port),
	    "TCP port " .. tostring(port), owner)
end

local function resource_lease_release(lease)
	local owner_path = lease.path .. "/owner"
	local file = io.open(owner_path, "r")
	local owner = file ~= nil and file:read("*l") or nil
	if file ~= nil then
		file:close()
	end
	if owner ~= lease.owner then
		die("resource lease ownership changed unexpectedly: " ..
		    lease.description)
	end
	if not os.remove(owner_path) then
		die("cannot remove resource lease owner record: " ..
		    lease.description)
	end
	if not lfs.rmdir(lease.path) then
		die("cannot remove resource lease: " .. lease.description)
	end
end

local function acquire_case_resources(document, case, options, runroot, ordinal,
    directory)
	local environment = effective_environment(document, case, options, ordinal)
	local names, requested, seen = {}, {}, {}
	local port_requests, port_seen = {}, {}
	local owner
	local max_guest_cid = 4294967295
	local explicit = false
	local port_explicit = false

	if not case_uses_vsock(case, environment) and
	    not case_uses_console(environment) then
		return nil
	end
	if case_uses_vsock(case, environment) then
		if case.executor == "alpine-multi-vsock" then
			names = { "CID1", "CID2" }
		else
			names = { "CID" }
		end
	end
	for _, name in ipairs(names) do
		requested[name] = parse_guest_cid(environment[name], name)
		explicit = explicit or options.sets[name] ~= nil or
		    (case.env ~= nil and case.env[name] ~= nil) or
		    (document.defaults ~= nil and document.defaults.env ~= nil and
		    document.defaults.env[name] ~= nil)
		if seen[requested[name]] then
			die(case.id .. " assigns the same CID more than once")
		end
		seen[requested[name]] = true
	end
	local port_names = {}
	if environment.CONSOLE_PORT1 ~= nil or environment.CONSOLE_PORT2 ~= nil then
		port_names = { "CONSOLE_PORT1", "CONSOLE_PORT2" }
	elseif environment.CONSOLE_PORT ~= nil then
		port_names = { "CONSOLE_PORT" }
	end
	for _, name in ipairs(port_names) do
		local port = parse_tcp_port(environment[name], name)
		if port_seen[port] then
			die(case.id .. " assigns the same TCP console port more than once")
		end
		port_seen[port] = true
		table.insert(port_requests, { name = name, port = port })
		port_explicit = port_explicit or options.sets[name] ~= nil or
		    (case.env ~= nil and case.env[name] ~= nil) or
		    (document.defaults ~= nil and document.defaults.env ~= nil and
		    document.defaults.env[name] ~= nil)
	end
	if environment.NONVIRTIO_DEVICE == "pci-uart" and
	    environment.CONSOLE_PORT ~= nil then
		local port = tonumber(environment.CONSOLE_PORT) + 1
		if port > 65535 then
			die("CONSOLE_PORT leaves no adjacent PCI UART port")
		end
		if port_seen[port] then
			die(case.id .. " aliases its console and PCI UART ports")
		end
		port_seen[port] = true
		table.insert(port_requests, { port = port })
	end
	owner = runroot .. "\t" .. case.id
	--
	-- Preserve the documented four-CID spacing for generated CIDs and advance
	-- the complete case allocation together when another run owns it.  An
	-- operator-supplied CID is never remapped: report its collision instead.
	-- The bounded scan fails safely rather than wrapping into a reserved CID.
	--
	local result = { allocation = {}, leases = {} }
	for slot = 0, explicit and 0 or 16383 do
		local allocation, leases = {}, {}
		local available = true
		for _, name in ipairs(names) do
			local cid = requested[name] + slot * 4
			if cid > max_guest_cid then
				available = false
				break
			end
			local lease = cid_lease_try(directory, cid, owner)
			if lease == nil then
				available = false
				break
			end
			allocation[name] = tostring(cid)
			table.insert(leases, lease)
		end
		if available then
			for name, value in pairs(allocation) do
				result.allocation[name] = value
			end
			for _, lease in ipairs(leases) do
				table.insert(result.leases, lease)
			end
			break
		end
		for _, lease in ipairs(leases) do
			resource_lease_release(lease)
		end
		if requested[names[1]] + (slot + 1) * 4 > max_guest_cid then
			break
		end
	end
	if #names ~= 0 and #result.leases == 0 then
		die("no CID lease available for " .. case.id .. " in " .. directory ..
		    (explicit and " (explicit CID allocation is not remapped)" or ""))
	end
	local cid_lease_count = #result.leases
	for slot = 0, port_explicit and 0 or 16383 do
		local allocation, leases = {}, {}
		local available = true
		for _, request in ipairs(port_requests) do
			local port = request.port + slot * 4
			if port > 65535 then
				available = false
				break
			end
			local lease = tcp_port_lease_try(directory, port, owner)
			if lease == nil then
				available = false
				break
			end
			if request.name ~= nil then
				allocation[request.name] = tostring(port)
			end
			table.insert(leases, lease)
		end
		if available then
			for name, value in pairs(allocation) do
				result.allocation[name] = value
			end
			for _, lease in ipairs(leases) do
				table.insert(result.leases, lease)
			end
			break
		end
		for _, lease in ipairs(leases) do
			resource_lease_release(lease)
		end
	end
	if #port_requests ~= 0 and #result.leases == cid_lease_count then
		for _, lease in ipairs(result.leases) do
			resource_lease_release(lease)
		end
		die("no TCP console port lease available for " .. case.id .. " in " ..
		    directory .. (port_explicit and
		    " (explicit TCP port allocation is not remapped)" or ""))
	end
	return #result.leases == 0 and nil or result
end

local function release_case_resources(allocation)
	if allocation == nil then
		return
	end
	for _, lease in ipairs(allocation.leases) do
		resource_lease_release(lease)
	end
end

local function recover_case_resources(directory, runroot, case)
	local owner = runroot .. "\t" .. case.id
	local leases = {}

	if directory == nil then
		return nil
	end
	for entry in lfs.dir(directory) do
		if entry:match("^[0-9]+$") ~= nil or
		    entry:match("^tcp%-[0-9]+$") ~= nil then
			local path = directory .. "/" .. entry
			local file = io.open(path .. "/owner", "r")
			local recorded_owner = file ~= nil and file:read("*l") or nil
			if file ~= nil then
				file:close()
			end
			if recorded_owner == owner then
				local description = entry:match("^tcp%-(.+)$")
				description = description ~= nil and
				    "TCP port " .. description or "CID " .. entry
				table.insert(leases, {
					description = description, owner = owner, path = path,
				})
			end
		end
	end
	return #leases == 0 and nil or { leases = leases }
end

-- Reclaim only a completed or abandoned case's own allocation.  The caller
-- must first rule out both a supervised process and an untracked survivor;
-- this helper deliberately has no authority to make that liveness decision.
local function release_recovered_case_resources(directory, runroot, case)
	local allocation = recover_case_resources(directory, runroot, case)

	if allocation ~= nil then
		release_case_resources(allocation)
	end
end

local function start_case(document, case, options, runroot, ordinal,
    lease_directory)
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
	os.remove(pidfile .. ".fingerprint")
	os.remove(child_pidfile .. ".fingerprint")
	os.remove(pidfile .. ".pending.fingerprint")
	os.remove(child_pidfile .. ".pending.fingerprint")
	local allocation = acquire_case_resources(document, case, options, runroot,
	    ordinal, lease_directory)
	local environment = effective_environment(document, case, options, ordinal,
	    allocation and allocation.allocation or nil)
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
		release_case_resources(allocation)
		die("failed to launch case " .. case.id)
	end
	local identity_pending = read_number(status) == nil
	if identity_pending then
		-- Very short compiler/self-test cases can have written their terminal
		-- status, or exited, before daemon(8)'s control PID is observable to
		-- this manager.  Do not turn that completed case into a launch failure.
		-- A nonterminal case without both identities is never considered live
		-- or cancellable; the normal bounded supervisor check will publish 125
		-- instead of adopting a bare PID.  Defer the first identity observation
		-- to the supervisor loop so a second observation cannot occur in the
		-- same launch iteration before env(1) finishes its exec chain.
	end
	emit_event(runroot, "START", case.id, "", log)
	return {
		case = case,
		log = log,
		child_pidfile = child_pidfile,
		pidfile = pidfile,
		started = os.time(),
		status = status,
		identity_pending = identity_pending,
		resource_allocation = allocation,
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

local function sha256_command(command, description)
	local sha = io.popen(command .. " 2>/dev/null", "r")
	local digest = sha ~= nil and sha:read("*l") or nil
	local closed = sha ~= nil and sha:close() or nil
	if digest == nil or digest:match("^[0-9a-f]+$") == nil or not closed then
		die("cannot hash " .. description)
	end
	return digest
end

local function sha256_file(path)
	return sha256_command("/sbin/sha256 -q " .. shell_quote(path), path)
end

local function sha256_tree(path)
	-- Hash the ordered stream of per-file digests.  Qualification helpers are
	-- inputs just as much as the top-level executor; changing one in place must
	-- invalidate reusable case results.
	return sha256_command("cd " .. shell_quote(path) ..
	    " && /usr/bin/find -s . -type f -exec /sbin/sha256 -r {} \\; " ..
	    "| /sbin/sha256 -q",
	    "executor tree " .. path)
end

local function run_configuration(document, cases, options)
	local digest = sha256_file(options.manifest)
	if digest == nil or digest:match("^[0-9a-f]+$") == nil then
		die("cannot hash manifest: " .. options.manifest)
	end
	local settings = {
		"version=3",
		"manifest_sha256=" .. digest,
		"profile=" .. options.profile,
		"iso=" .. tostring(options.iso or ""),
		"fivebsd_image=" .. tostring(options.fivebsd_image or ""),
		"cid_lease_dir=" .. tostring(options.cid_lease_dir or ""),
	}
	for _, identifier in ipairs(options.case_ids) do
		table.insert(settings, "case=" .. identifier)
	end
	for key, value in pairs(options.sets) do
		table.insert(settings, "set." .. key .. "=" .. tostring(value))
	end
	local input_files = {}
	local executor_directories = {}
	local base = script_directory()
	input_files[base .. "/virtio-lab.lua"] = true
	input_files[base .. "/virtio-lab-case.sh"] = true
	for ordinal, case in ipairs(cases) do
		local runner = base .. "/" .. executors[case.executor]
		input_files[runner] = true
		executor_directories[runner:match("^(.*)/[^/]+$")] = true
		local environment = effective_environment(document, case, options,
		    ordinal)
		for _, value in pairs(environment) do
			if type(value) == "string" and
			    lfs.attributes(value, "mode") == "file" then
				input_files[value] = true
			end
		end
	end
	if options.iso ~= nil then
		input_files[options.iso] = true
	end
	if options.fivebsd_image ~= nil then
		input_files[options.fivebsd_image] = true
	end
	for path, _ in pairs(input_files) do
		table.insert(settings, "input_sha256." .. path .. "=" ..
		    sha256_file(path))
	end
	for path, _ in pairs(executor_directories) do
		table.insert(settings, "executor_tree_sha256." .. path .. "=" ..
		    sha256_tree(path))
	end
	table.sort(settings)
	return table.concat(settings, "\n") .. "\n"
end

local function verify_run_inputs(workdir)
	local configuration = read_file(workdir .. "/run.config")
	local manifest_path = read_file(workdir .. "/manifest.path")
	manifest_path = manifest_path:match("^([^\r\n]+)\r?\n?$")
	if manifest_path == nil then
		die("invalid manifest.path in run directory")
	end
	local manifest_identity = path_identity(manifest_path)
	if manifest_identity == nil or manifest_identity.kind ~= "Regular File" then
		die("recorded manifest is not a regular file: " .. manifest_path)
	end

	local expected_manifest
	local manifest_count = 0
	local input_count = 0
	local tree_count = 0
	local seen = {}
	for line in configuration:gmatch("[^\n]+") do
		local digest = line:match("^manifest_sha256=([0-9a-f]+)$")
		if digest ~= nil then
			manifest_count = manifest_count + 1
			expected_manifest = digest
		elseif line:match("^manifest_sha256=") ~= nil then
			die("malformed manifest identity in run.config")
		else
			local kind, path, recorded
			path, recorded = line:match(
			    "^input_sha256%.(.*)=([0-9a-f]+)$")
			if path ~= nil then
				kind = "input"
				input_count = input_count + 1
			else
				path, recorded = line:match(
				    "^executor_tree_sha256%.(.*)=([0-9a-f]+)$")
				if path ~= nil then
					kind = "executor tree"
					tree_count = tree_count + 1
				elseif line:match("^input_sha256%.") ~= nil or
				    line:match("^executor_tree_sha256%.") ~= nil then
					die("malformed content identity in run.config")
				end
			end
			if path ~= nil then
				if path == "" or #recorded ~= 64 or seen[kind .. "\0" .. path] then
					die("invalid or duplicate " .. kind ..
					    " identity in run.config")
				end
				seen[kind .. "\0" .. path] = true
				local identity = path_identity(path)
				local expected_kind = kind == "input" and
				    "Regular File" or "Directory"
				if identity == nil or identity.kind ~= expected_kind then
					die("recorded " .. kind .. " is not a " ..
					    expected_kind:lower() .. ": " .. path)
				end
				local actual = kind == "input" and sha256_file(path) or
				    sha256_tree(path)
				if actual ~= recorded then
					die("recorded " .. kind .. " changed since the run: " ..
					    path)
				end
			end
		end
	end
	if manifest_count ~= 1 or expected_manifest == nil or
	    #expected_manifest ~= 64 then
		die("run.config must contain exactly one valid manifest identity")
	end
	if sha256_file(manifest_path) ~= expected_manifest then
		die("recorded manifest changed since the run: " .. manifest_path)
	end
	if input_count == 0 or tree_count == 0 then
		die("run.config lacks complete input and executor-tree identities")
	end
	print("verified")
	print("inputs=" .. tostring(input_count))
	print("executor_trees=" .. tostring(tree_count))
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
	local needs_nested_vmx_live = false
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
		elseif case.executor == "nested-vmx-live" then
			needs_root = true
			needs_nested_vmx_live = true
		elseif case.executor == "vmm-root" or
		    case.executor == "kernel-contract-root" then
			needs_root = true
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
	--
	-- A nested-VMX run has an intentionally external, reviewed L1 driver and
	-- three immutable guest images.  Discovering that one is absent only after
	-- the host-regression gate would waste a costly, otherwise unrelated VM
	-- qualification run.  Validate the effective case environment before any
	-- privilege or host-side work; the root-only wrapper later validates the
	-- paths' ownership, hierarchy, identity, and content stability.
	--
	if needs_nested_vmx_live then
		for _, case in ipairs(cases) do
			if case.executor == "nested-vmx-live" then
				local environment = effective_environment(document, case,
				    options, 1)
				for _, key in ipairs({
				    "NESTED_L1_RUNNER", "NESTED_L1_IMAGE",
				    "NESTED_LINUX_L2_IMAGE", "NESTED_FIVEBSD_L2_IMAGE",
				}) do
					if environment[key] == nil or environment[key] == "" then
						die("nested-vmx-live requires --set " .. key ..
						    "=/absolute/path")
					end
				end
			end
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
	local configuration = run_configuration(document, cases, options)
	--
	-- This check is intentionally before acquiring manager.lock.  A rejected
	-- resume has not started a case and must leave the existing run directory
	-- exactly as it found it; in particular, it must not strand a lease that
	-- prevents the rightful owner from resuming the run.
	--
	if options.resume and read_file(runroot .. "/run.config") ~= configuration then
		die("resume configuration differs from the original run")
	end
	local lease_directory
	for ordinal, case in ipairs(cases) do
		local environment = effective_environment(document, case, options,
		    ordinal)
		if case_uses_vsock(case, environment) or
		    case_uses_console(environment) then
			lease_directory = resource_lease_directory(options, effective_uid)
			break
		end
	end
	-- Validate the shared lease directory before publishing a per-run manager
	-- lease as well.  A malformed or symlinked control path is a caller error,
	-- not a partially started run, and must not require stale-lease recovery.
	local manager_lease = run_manager_lease_acquire(runroot)
	if options.resume then
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
		if options.resume and supervised_case_alive(status_path) then
			local attempt = read_number(status_path .. ".attempt") or 1
			active[case.id] = {
				case = case,
				child_pidfile = status_path .. ".child",
				log = runroot .. "/logs/" .. case.id .. ".attempt" ..
				    tostring(attempt) .. ".log",
				pidfile = pidfile,
				started = os.time(),
				status = status_path,
				identity_pending = false,
				resource_allocation = recover_case_resources(lease_directory,
				    runroot, case),
			}
			local environment = effective_environment(document, case, options,
			    ordinal)
			if (case_uses_vsock(case, environment) or
			    case_uses_console(environment)) and
			    active[case.id].resource_allocation == nil then
				die("active VM case is missing its resource leases: " .. case.id)
			end
			emit_event(runroot, "REATTACH", case.id, "", active[case.id].log)
		elseif options.resume and stale_case_process_alive(status_path) then
			die("refusing to rerun case with an untracked live process: " ..
			    case.id)
		elseif options.resume and read_status(status_path) == 0 then
			-- A terminal success from an interrupted manager is reusable only
			-- after its case-specific allocation is no longer retained.
			release_recovered_case_resources(lease_directory, runroot, case)
			passed = passed + 1
			emit_event(runroot, "REUSE", case.id, 0, runroot .. "/logs")
		else
			-- A previous manager can be interrupted after the supervised case
			-- wrote a terminal status but before it released this case's resource
			-- leases.  We have already rejected a live or untracked process
			-- above, so release only leases whose immutable owner record names
			-- this exact run and case before retrying it.  Without this recovery
			-- a --resume silently advances to a different allocation and leaves
			-- the original leases stranded.
			if options.resume then
				release_recovered_case_resources(lease_directory, runroot, case)
			end
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
						    options, runroot, item.ordinal, lease_directory)
						active[item.case.id] = running
						table.remove(pending, index)
						progress = true
						break
					end
				end
			end
		end
		for id, running in pairs(active) do
			if running.identity_pending and
			    record_supervised_case_identity(running.status) then
				running.identity_pending = false
			end
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
				release_case_resources(running.resource_allocation)
			end
		end
		if #pending > 0 or next(active) ~= nil then
			-- daemon(8) owns the case processes, so this manager cannot
			-- waitpid(2) on them.  This is deliberately the only periodic
			-- wait in the lab: it polls an atomic, terminal status file at a
			-- one-second control-plane cadence.  It is not a device retry
			-- mechanism; guest I/O, queue reset, and backend completion use
			-- their own event/callback paths.  Keep the process model explicit
			-- until the runner can receive a portable child-status event.
			os.execute("/bin/sleep 1")
		end
	end
	local summary = string.format(
	    "passed=%d\nfailed=%d\nblocked=%d\ntotal=%d\n",
	    passed, failed, blocked, passed + failed + blocked)
	write_file(runroot .. "/summary", summary)
	io.write(summary)
	io.write("results=", runroot, "\n")
	run_manager_lease_release(manager_lease)
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
			return nil, "cannot create " .. host_state_directory
		end
	end
	local identity = path_identity(host_state_directory)
	if identity == nil or identity.kind ~= "Directory" or identity.uid ~= 0 or
	    identity.permissions ~= "755" then
		return nil, host_state_directory ..
		    " must be a root-owned mode-0755 directory"
	end
	local path = host_state_path(state.bridge)
	local temporary = path .. ".tmp-" .. tostring(unistd.getpid())
	local contents = table.concat({
		"bridge=" .. state.bridge,
		"uplink=" .. state.uplink,
		"bridge_created=" .. (state.bridge_created and "yes" or "no"),
		"member_added=" .. (state.member_added and "yes" or "no"),
		"",
	}, "\n")
	local file, error = io.open(temporary, "w")
	if file == nil then
		return nil, "cannot create host state file: " .. tostring(error)
	end
	if not file:write(contents) then
		file:close()
		os.remove(temporary)
		return nil, "cannot write host state file"
	end
	if not file:close() then
		os.remove(temporary)
		return nil, "cannot close host state file"
	end
	if not command_ok("/bin/chmod 644 " .. shell_quote(temporary)) then
		os.remove(temporary)
		return nil, "cannot protect host state file"
	end
	local ok
	ok, error = os.rename(temporary, path)
	if not ok then
		os.remove(temporary)
		return nil, "cannot publish host state: " .. tostring(error)
	end
	return true
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
	local function publish(state, action, rollback)
		local ok, error = write_host_state(state)

		if ok then
			return
		end
		if rollback ~= nil and rollback() then
			die(error .. " after " .. action .. "; mutation rolled back")
		end
		die(error .. " after " .. action ..
		    "; rollback failed, host state requires manual recovery")
	end

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
		publish(state, "creating the ownership record")
	end
	if not interface_exists(bridge) then
		if not command_ok("/sbin/ifconfig " .. shell_quote(bridge) ..
		    " create") then
			die("cannot create " .. bridge)
		end
		state.bridge_created = true
		state.member_added = false
		publish(state, "creating " .. bridge, function()
			state.bridge_created = false
			return command_ok("/sbin/ifconfig " .. shell_quote(bridge) ..
			    " destroy")
		end)
	end
	local members = bridge_members(bridge)
	if not members[uplink] then
		if not command_ok("/sbin/ifconfig " .. shell_quote(bridge) ..
		    " addm " .. shell_quote(uplink)) then
			die("cannot add " .. uplink .. " to " .. bridge ..
			"; run host-cleanup to roll back")
		end
		state.member_added = true
		publish(state, "adding " .. uplink .. " to " .. bridge, function()
			state.member_added = false
			return command_ok("/sbin/ifconfig " .. shell_quote(bridge) ..
			    " deletem " .. shell_quote(uplink))
		end)
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
				if member ~= state.uplink or not state.member_added then
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
	-- The ownership record is part of the cleanup transaction.  Do not turn
	-- an unexpected unlink failure into a Lua assertion traceback: callers
	-- need an actionable error and the record must remain for a safe retry.
	if not os.remove(host_state_path(bridge)) then
		die("cannot remove " .. bridge .. " virtio-lab ownership record; " ..
		    "host cleanup is incomplete")
	end
	print("clean")
	print("bridge=" .. bridge)
	print("uplink=" .. state.uplink)
end

local function usage(status)
	io.stderr:write([[
usage: virtio-lab.lua plan|coverage [options]
       virtio-lab.lua run [options]
       virtio-lab.lua status --workdir run-directory
       virtio-lab.lua verify-inputs --workdir run-directory
       virtio-lab.lua cancel --workdir run-directory
       virtio-lab.lua host-prepare --bridge name --uplink name
       virtio-lab.lua host-status [--bridge name]
       virtio-lab.lua host-cleanup [--bridge name]
options:
  --manifest path   case manifest (default: virtio-lab.yaml beside script)
  --profile name    vmfree, kernel-root, vmm-root, smoke, release, checkpoint,
                    soak, soak-smoke,
                    audio, nested,
                    nested-default,
                    qualification, intel-qualification, audio-qualification,
                    or full-qualification
  --case id         run or plan one named profile case; may be repeated
  --jobs count      bounded parallel case count
  --iso path        Alpine virt ISO for real-VM cases
  --fivebsd-image path
                    immutable 5BSD raw base image
  --workdir path    new run directory, or existing directory for status
  --cid-lease-dir path
                    caller-owned mode-0700 CID and TCP-port lease directory
  --bridge name     managed shared bridge (default: bridge0)
  --uplink name     explicit physical uplink for host-prepare
  --prepare-host    idempotently prepare bridge before a run
  --resume          reuse passes and rerun failed or incomplete cases
  --set NAME=value  override a runner environment setting
]])
	os.exit(status or 2)
end

local command = arg[1]
if command == nil or command == "-h" or command == "--help" then
	usage(command == nil and 2 or 0)
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
    cid_lease_dir = options.cid_lease_dir,
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
if #options.case_ids ~= 0 and command ~= "plan" and command ~= "run" and
    command ~= "coverage" then
	die("--case is valid only with plan or run")
end
if command == "coverage" and #options.case_ids ~= 0 then
	die("--case is not valid with coverage; coverage evaluates a full profile")
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

if command == "verify-inputs" then
	if options.workdir == nil then
		die("verify-inputs requires --workdir")
	end
	verify_run_inputs(options.workdir)
	os.exit(0)
end

if command == "status" or command == "cancel" then
	if options.workdir == nil then
		die(command .. " requires --workdir")
	end
	if command == "cancel" then
		local caller_uid = effective_uid()
		local run_identity = path_identity(options.workdir)
		if run_identity == nil or run_identity.kind ~= "Directory" then
			die("cancel requires root or a caller-owned mode-0700 run directory" ..
		    ": workdir is not a directly accessible directory")
		elseif caller_uid == nil then
			die("cancel requires root or a caller-owned mode-0700 run directory" ..
		    ": cannot determine caller uid")
		elseif caller_uid ~= 0 and
		    (run_identity.permissions ~= "700" or
		    run_identity.uid ~= caller_uid) then
			die("cancel requires root or a caller-owned mode-0700 run directory" ..
			    ": caller uid=" .. tostring(caller_uid) ..
			    ", workdir uid=" .. tostring(run_identity.uid) ..
			    " mode=" .. tostring(run_identity.permissions) ..
			    "; rerun cancel as root")
		end
	end
	local status_directory = options.workdir .. "/status"
	local active_cases = {}
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
				local status_path = (status_directory .. "/" .. entry):gsub(
				    "%.pid$", "")
				local identity = supervised_case_identity(status_path)
				if identity ~= nil then
					identity.status_path = status_path
					table.insert(active_cases, identity)
				end
			end
		end
	end
	table.sort(active_cases, function(left, right)
		return left.status_path < right.status_path
	end)
	if command == "cancel" then
		local cancelled = 0
		for _, identity in ipairs(active_cases) do
			-- Revalidate the captured parent/child identities immediately before
			-- sending the signal.  Do not reread the mutable run directory here:
			-- cancellation authority belongs to the identity observed during the
			-- initial trusted scan, not to a later PID-file replacement.
			if process_parent(identity.child) == identity.supervisor and
			    process_fingerprint_value_matches(identity.supervisor_fingerprint,
			    identity.supervisor) and
			    process_fingerprint_value_matches(identity.child_fingerprint,
			    identity.child) then
				-- The case can still exit after identity validation.  Report only
				-- signals that kill(2) actually delivered.
				if command_ok("/bin/kill -TERM " .. tostring(identity.child)) then
					cancelled = cancelled + 1
				end
			end
		end
		print("cancelled=" .. tostring(cancelled))
	else
		if #active_cases ~= 0 then
			io.write("running\nactive=", tostring(#active_cases), "\n")
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
local cases = selected_cases(document, options.profile, options.case_ids)
assign_port_lanes(document, cases, options)
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
	if #options.case_ids ~= 0 then
		os.exit(0)
	end
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
	if #options.case_ids == 0 and
	    coverage_report(document, cases, options) ~= 0 then
		die("selected profile does not satisfy its option coverage contract")
	end
	run_cases(document, cases, options)
else
	usage()
end
