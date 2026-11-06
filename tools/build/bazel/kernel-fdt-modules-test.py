# SPDX-License-Identifier: BSD-2-Clause
"""Check actual kernel FDT headers against native I2C/GPIO module selection."""
import argparse
import json
from pathlib import Path
import re

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--expected', choices=['yes', 'no'], required=True)
for name in ['header', 'i2c', 'mux', 'gpio', 'gpiobus-recipe', 'gpioled-recipe', 'iicbus-recipe']:
    parser.add_argument('--'+name, type=Path, required=True)
args = parser.parse_args()
enabled = bool(re.search(r'^#define\s+FDT\b', args.header.read_text(), re.M))
assert enabled == (args.expected == 'yes'), 'kernel FDT header disagrees with selector'
conditional = {
    'i2c': {'hym8563.ko', 'rs5c372a.ko', 'rv3032.ko', 'rx8803.ko', 'tca64xx.ko', 'tmp461.ko', 'w83793g.ko', 'iic_gpiomux.ko'},
    'mux': {'iic_gpiomux.ko'},
    'gpio': {'gpiokeys.ko', 'gpiopps.ko'},
}
counts = {}
for parent, optional in conditional.items():
    index = json.loads(getattr(args, parent).read_text())
    assert index['format'] == 1
    names = [Path(row['runtime']).name for row in index['modules']]
    assert len(names) == len(set(names)) and names
    assert (set(names) & optional) == (optional if enabled else set()), parent
    counts[parent] = len(names)
# These source alternatives were missed by an initial membership-only check.
for module, fdt_object in [('gpiobus', 'ofw_gpiobus.o'), ('iicbus', 'ofw_iicbus.o')]:
    recipe = json.loads(getattr(args, module+'_recipe').read_text())
    assert recipe['format'] == 1
    objects = {Path(path).name for path in recipe['ordered_objects']}
    assert (fdt_object in objects) == enabled, module+' source branch disagrees with FDT'
recipe = json.loads(args.gpioled_recipe.read_text())
objects = [Path(path).name for path in recipe['ordered_objects']]
assert objects == (['gpioled_fdt.o'] if enabled else ['gpioled.o']), 'GPIO LED source alternative'
print('KERNEL_FDT_MODULES='+json.dumps(dict(enabled=enabled,counts=counts),sort_keys=True))
