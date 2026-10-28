-- SPDX-License-Identifier: BSD-2-Clause
local case = arg[1]
for i = 2, #arg, 2 do
  local name, path = arg[i], arg[i + 1]
  if path:match('%.lua$') then
    package.preload[name] = assert(loadfile(path))
  else
    package.preload[name] = assert(package.loadlib(path, 'luaopen_' .. name:gsub('%.', '_')))
  end
end
package.path, package.cpath = '', ''
if case == 'modules' then
  for i = 2, #arg, 2 do assert(type(require(arg[i])) == 'table', arg[i]) end
elseif case == 'hash' then
  local h = require('hash')
  local expected = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  assert(h.sha256('abc'):hexdigest() == expected)
  assert(h.sha256('a'):update('b'):update('c'):hexdigest() == expected)
  local binary = h.sha256('abc'):digest()
  assert(#binary == 32)
  assert((binary:gsub('.', function(c)
    return string.format('%02x', string.byte(c))
  end)) == expected)
elseif case == 'formats' then
  local y, u = require('lyaml'), require('ucl')
  local obj = y.load('count: 42\nitems: [a, b]\n')
  assert(obj.count == 42 and obj.items[2] == 'b')
  local p = u.parser(); assert(p:parse_string(u.to_json(obj)))
  assert(p:get_object().count == 42)
  assert(y.load(y.dump({obj})).items[2] == 'b')
  assert(not pcall(y.load, 'broken: ['))
elseif case == 'filesystem' then
  local l = require('lfs')
  assert(l.mkdir('scratch'))
  local f = assert(io.open('scratch/item', 'w')); f:write('hello'); f:close()
  assert(l.attributes('scratch/item').size == 5)
  local found = false
  for n in l.dir('scratch') do if n == 'item' then found = true end end
  assert(found); assert(os.remove('scratch/item')); assert(l.rmdir('scratch'))
else
  error('unknown case: ' .. tostring(case))
end
print(case .. ' passed')
