-- SPDX-License-Identifier: BSD-2-Clause
-- Use the existing production test-root interface; never default to host paths.
local root = assert(os.getenv('NUAGE_FAKE_ROOTDIR'))
assert(root:sub(1, 1) == '/' and root ~= '/')
for i = 2, #arg, 2 do
  local name, path = arg[i], arg[i + 1]
  if path:match('%.lua$') then
    package.preload[name] = assert(loadfile(path))
  else
    package.preload[name] = assert(package.loadlib(path, 'luaopen_' .. name))
  end
end
package.path, package.cpath = '', ''
require('fixture')
