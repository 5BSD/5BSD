#!/bin/sh
set -eu
[ "$(id -u)" = 2001 ]
/usr/bin/policy-probe open system.Notify.System 0
