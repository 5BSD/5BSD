-- SPDX-License-Identifier: BSD-2-Clause
-- Required, authenticated startup policy for the EFI Secure Boot loader.
-- This file and every input it reads must belong to the signed generation.
-- The ordinary loader's optional overrides, nextboot and menus are deliberately
-- absent: deleting an input must not select a less restrictive default policy.

-- A required generated input; absence never selects a different boot mode.
-- loadfile authenticates and closes the file before its returned chunk executes.
local contract = assert(loadfile("/boot/boot-policy.lua", "t", {}),
    "required startup contract missing or invalid")()
assert(type(contract) == "table" and getmetatable(contract) == nil,
    "invalid startup contract object")
assert(contract.version == 1 and
    (contract.mode == "preloaded" or contract.mode == "verity"),
    "unsupported startup contract version or mode")
local fields = {version=true, mode=true}
if contract.mode == "verity" then
    fields.image, fields.descriptor, fields.descriptor_sha256 = true, true, true
    fields.cache_blocks, fields.heap_bytes = true, true
    fields.transition, fields.transition_sha256 = true, true
end
for key in pairs(contract) do
    assert(fields[key], "unknown startup contract field")
end
local function artifactPath(path)
    if type(path) ~= "string" or path:sub(1, 6) ~= "/boot/" or
        not path:match("^/[A-Za-z0-9_./+%-]+$") or path:sub(-1) == "/" or
        path:find("//", 1, true) then return false end
    for part in path:gmatch("[^/]+") do
        if part == "." or part == ".." then return false end
    end
    return true
end
local function decimal(value)
    return type(value) == "string" and value:match("^[0-9]+$") and
        (value == "0" or value:sub(1, 1) ~= "0") and
        (#value < 19 or (#value == 19 and value <= "9223372036854775807"))
end
if contract.mode == "verity" then
    assert(artifactPath(contract.image) and artifactPath(contract.descriptor) and
        contract.image ~= contract.descriptor, "invalid startup artifact paths")
    assert(type(contract.descriptor_sha256) == "string" and
        #contract.descriptor_sha256 == 64 and contract.descriptor_sha256:match("^[0-9a-f]+$"),
        "invalid startup descriptor digest")
    assert(decimal(contract.cache_blocks) and decimal(contract.heap_bytes) and
        contract.heap_bytes ~= "0", "invalid startup memory bounds")
    local transition = ""
    assert((contract.transition == nil) == (contract.transition_sha256 == nil),
        "incomplete transition binding")
    if contract.transition ~= nil then
        assert(artifactPath(contract.transition) and
            contract.transition ~= contract.image and contract.transition ~= contract.descriptor and
            type(contract.transition_sha256) == "string" and
            #contract.transition_sha256 == 64 and
            contract.transition_sha256:match("^[0-9a-f]+$"), "invalid transition binding")
        transition = " " .. contract.transition .. " " .. contract.transition_sha256
    end
    assert(loader.perform("verity-require") == 0, "verified image requirement failed")
    assert(loader.perform("verity-select " .. contract.image .. " " .. contract.descriptor ..
        " " .. contract.descriptor_sha256 .. " " .. contract.cache_blocks .. " " ..
        contract.heap_bytes .. transition) == 0, "verified image selection failed")
end

require("cli")
local config = require("config")
local core = require("core")

assert(config.processFile("/boot/defaults/loader.conf", false),
    "required defaults missing or invalid")
assert(config.processFile("/boot/loader.conf", false),
    "required generation configuration missing or invalid")
assert(config.loadelf(), "required kernel or module could not be loaded")
if contract.mode == "verity" then
    assert(loader.perform("verity-preload") == 0, "verified descriptor preload failed")
end
core.loadEntropy()
loader.perform("boot")
error("verified boot returned")
