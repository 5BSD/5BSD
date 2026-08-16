#!/bin/sh
# Resolve a 5BSD guest device through the newbus topology.  Every command
# prints exactly one device name and fails when the lab topology is ambiguous.
set -eu
DEVICE_ROOT=${DEVICE_ROOT:-/dev}

fail()
{
	echo "freebsd-nonvirtio: $*" >&2
	exit 1
}

pci_device()
{
	driver=$1
	bdf=${2:-pci0:0:21:0}
	devices=$(devinfo -rv | awk -v driver="$driver" -v bdf="$bdf" '
	    $1 ~ ("^" driver "[0-9]+$") && index($0, "dbsf=" bdf) { print $1 }
	')
	set -- $devices
	[ "$#" -eq 1 ] || fail "expected one $driver device at $bdf, found $#"
	printf '%s\n' "$1"
}

only_disk()
{
	pattern=$1
	disks=$(sysctl -n kern.disks | tr ' ' '\n' | awk -v pattern="$pattern" '
	    $0 ~ pattern { print }
	')
	set -- $disks
	[ "$#" -eq 1 ] || fail "expected one disk matching $pattern, found $#"
	[ -c "$DEVICE_ROOT/$1" ] || fail "missing $DEVICE_ROOT/$1"
	printf '%s\n' "$1"
}

device_below()
{
	child_prefix=$1
	parent=$2
	children=$(sysctl -aN | awk -F. -v prefix="$child_prefix" '
	    $1 == "dev" && $2 == prefix && $4 == "%parent" { print prefix $3 }
	' | while read -r child; do
		devinfo -p "$child" 2>/dev/null | grep -qw "$parent" &&
		    printf '%s\n' "$child"
	done)
	set -- $children
	[ "$#" -eq 1 ] || fail "expected one $child_prefix device below $parent, found $#"
	printf '%s\n' "$1"
}

case "${1:-}" in
ahci-disk)
	pci_device ahci >/dev/null
	only_disk '^ada[0-9][0-9]*$'
	;;
nvme-controller)
	pci_device nvme
	;;
nvme-disk)
	controller=$(pci_device nvme)
	unit=${controller#nvme}
	if [ -c "$DEVICE_ROOT/${controller}ns1" ]; then
		printf '%s\n' "${controller}ns1"
	elif [ -c "$DEVICE_ROOT/${controller}n1" ]; then
		printf '%s\n' "${controller}n1"
	else
		# nda/nvd numbering is not the controller number.  Reject ambiguity
		# instead of risking an unrelated disk.
		only_disk '^(nda|nvd)[0-9][0-9]*$'
	fi
	;;
e82545-interface)
	pci_device em
	;;
hda-pcm)
	controller=$(pci_device hdac)
	pcm=$(device_below pcm "$controller")
	unit=${pcm#pcm}
	[ -c "$DEVICE_ROOT/dsp$unit" ] || fail "missing $DEVICE_ROOT/dsp$unit"
	printf '%s\n' "dsp$unit"
	;;
xhci-controller)
	pci_device xhci
	;;
xhci-bus)
	controller=$(pci_device xhci)
	bus=$(device_below usbus "$controller")
	printf '%s\n' "${bus#usbus}"
	;;
xhci-ugen)
	controller=$(pci_device xhci)
	bus=$(device_below usbus "$controller")
	bus=${bus#usbus}
	devices=$(usbconfig list | awk -v prefix="ugen${bus}." '
	    index($1, prefix) == 1 && /Tablet|Mouse|HID/ {
	        gsub(/:$/, "", $1); print $1
	    }
	')
	set -- $devices
	[ "$#" -eq 1 ] || fail "expected one HID device on usbus$bus, found $#"
	printf '%s\n' "$1"
	;;
xhci-mouse)
	controller=$(pci_device xhci)
	mouse=$(device_below ums "$controller")
	[ -c "$DEVICE_ROOT/$mouse" ] || fail "missing $DEVICE_ROOT/$mouse"
	printf '%s\n' "$mouse"
	;;
pci-uart)
	pci_device uart
	;;
*)
	fail "usage: $0 ahci-disk|nvme-controller|nvme-disk|e82545-interface|hda-pcm|xhci-controller|xhci-bus|xhci-ugen|xhci-mouse|pci-uart"
	;;
esac
