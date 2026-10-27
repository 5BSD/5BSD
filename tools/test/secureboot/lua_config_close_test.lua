-- Actual config.lua parsing; loader and I/O boundaries are injected.
local closed, reject, failread, text = false, false, false, nil
local values = {}
loader = {
    getenv = function(key) return values[key] end,
    setenv = function(key, value)
        assert(closed, "configuration applied before close")
        values[key] = value
        return 0
    end,
    unsetenv = function(key) values[key] = nil end,
}
package.preload.hook = function()
    return {registerType=function() end, runAll=function() assert(closed) end}
end
local config = dofile(arg[1])
io = {
    open=function() return {} end,
    read=function() if failread then return nil, 0 end return text, #text end,
    close=function()
        if reject then error("injected verification failure") end
        closed = true
        return true
    end,
}
for _, name in ipairs({"case.conf", "case.lua"}) do
    closed=false; reject=false; failread=false; values={}
    text='probe="accepted"'
    assert(config.processFile(name, false))
    assert(closed and values.probe=="accepted")
    closed=false; reject=true; values={}
    local ok, err=pcall(config.processFile, name, false)
    assert(not ok and tostring(err):find("injected verification failure",1,true))
    assert(not closed and next(values)==nil)
    closed=false; reject=false; failread=true; values={}
    assert(not config.processFile(name, false))
    assert(closed and next(values)==nil)
end
print("PASS: actual text/Lua configuration parsing occurs after successful close")
