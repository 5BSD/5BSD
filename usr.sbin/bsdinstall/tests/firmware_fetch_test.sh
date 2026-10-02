#!/usr/bin/env atf-sh

setup()
{
	mkdir -p bin root/boot/kernel state
	echo target-kernel >root/boot/kernel/kernel
	export TEST_DIGEST=$(sha256 -q root/boot/kernel/kernel)
	export TEST_STATE=$(pwd)/state
	export FWGET_ROOT=$(pwd)/root
	export PATH=$(pwd)/bin:/bin:/usr/bin:/sbin:/usr/sbin
	export HELPER=@SRCTOP@/usr.sbin/fwget/hardware-install.sh
	cat >bin/pkg <<-'EOF'
	#!/bin/sh
	if [ "$1" = -v ]; then
		[ "${ASSUME_ALWAYS_YES:-}" = no ] || exit 97
		[ ! -t 0 ] || exit 96
		exit "${TEST_PKG_MISSING:-0}"
	fi
	printf '%s\n' "$*" >>"${TEST_STATE}/calls"
	[ "$1" = -c ] && [ "$2" = "${FWGET_ROOT}" ] || exit 99
	shift 2
	case "$1" in
	update) exit 0 ;;
	rquery)
		shift 4
		format=$1; name=$2
		case "${format}" in
		'%At=%Av')
			if [ "${TEST_MODE:-}" = mismatch ]; then
				echo '5BSD_kernel_sha256=wrong'
			elif [ "${TEST_MODE:-}" = missing ] && [ "${name}" = 5BSD-hw-dependent ]; then
				exit 1
			else
				echo "5BSD_kernel_sha256=${TEST_DIGEST}"
			fi ;;
		'%dn')
			[ "${name}" != 5BSD-hw-test-firmware ] || echo 5BSD-hw-dependent ;;
		esac
		exit 0 ;;
	install)
		if [ "${TEST_MODE:-}" = retry ] && [ ! -f "${TEST_STATE}/retried" ]; then
			touch "${TEST_STATE}/retried"
			exit 1
		fi
		exit 0 ;;
	esac
	exit 98
	EOF
	chmod +x bin/pkg
}

atf_test_case target_kernel_and_dependencies
target_kernel_and_dependencies_body()
{
	setup
	atf_check -s exit:0 -o empty -e empty sh "${HELPER}" test-firmware
	atf_check -s exit:0 -o ignore grep -F '5BSD-hw-dependent' state/calls
	atf_check -s exit:0 -o ignore grep -F 'install -U -qy -r 5BSD-hardware 5BSD-hw-test-firmware' state/calls
}

atf_test_case mismatch_rejected
mismatch_rejected_body()
{
	setup
	atf_check -s exit:1 -o empty -e match:'does not match' env TEST_MODE=mismatch sh "${HELPER}" test-firmware
	atf_check -s exit:1 -o empty grep 'install ' state/calls
}

atf_test_case missing_dependency_rejected
missing_dependency_rejected_body()
{
	setup
	atf_check -s exit:1 -o empty -e match:'Unable to install' env TEST_MODE=missing sh "${HELPER}" test-firmware
	atf_check -s exit:1 -o empty grep 'install ' state/calls
}

atf_test_case stale_catalog_revalidated
stale_catalog_revalidated_body()
{
	setup
	atf_check -s exit:0 -o empty -e empty env TEST_MODE=retry sh "${HELPER}" test-firmware
	atf_check -s exit:0 -o inline:'2\n' grep -c 'update -fq -r 5BSD-hardware' state/calls
	atf_check -s exit:0 -o inline:'2\n' grep -c '%At=%Av 5BSD-hw-dependent' state/calls
}

atf_test_case offline_repository_persists
offline_repository_persists_body()
{
	setup
	mkdir media
	echo '{}' >media/hardware.json
	echo firmware >media/test.pkg
	atf_check -s exit:0 -o empty -e empty env \
	    BSDINSTALL_CHROOT="${FWGET_ROOT}" \
	    BSDINSTALL_HARDWARE_MEDIA="$(pwd)/media" \
	    BSDINSTALL_HARDWARE_INSTALL="${HELPER}" \
	    sh @SRCTOP@/usr.sbin/bsdinstall/scripts/firmware-fetch test-firmware
	atf_check -s exit:0 cmp media/test.pkg root/usr/5bsd-packages/hardware/test.pkg
	atf_check -s exit:0 -o ignore grep 'enabled: yes' root/etc/pkg/5BSD-hardware.conf
}

atf_test_case fwget_graphics_and_usb
fwget_graphics_and_usb_body()
{
	setup
	mkdir detect
	cat >detect/pci <<-'EOF'
	pci_search_packages() {
		local IFS=$'\n'
		addpkg "gpu-firmware-intel-kmod-alderlake gpu-firmware-intel-kmod-tigerlake"
		addpkg "gpu-firmware-intel-kmod-tigerlake"
	}
	EOF
	cat >detect/usb <<-'EOF'
	usb_search_packages() { addpkg "wifi-firmware-mt7601u-kmod"; }
	EOF
	atf_check -s exit:0 -e empty -o inline:'gpu-firmware-intel-kmod-alderlake\ndrm-kmod\ngpu-firmware-intel-kmod-tigerlake\nwifi-firmware-mt7601u-kmod\n' \
	    env LIBEXEC_PATH="$(pwd)/detect" sh @SRCTOP@/usr.sbin/fwget/fwget.sh -qn
}

atf_test_case graphics_startup_preserves_modules
graphics_startup_preserves_modules_body()
{
	setup
	mkdir config
	for repeat in 1 2; do
		atf_check -s exit:0 -o empty -e ignore env \
		    BSDINSTALL_CHROOT="${FWGET_ROOT}" \
		    BSDINSTALL_HARDWARE_MEDIA="$(pwd)/no-media" \
		    BSDINSTALL_HARDWARE_INSTALL="${HELPER}" \
		    BSDINSTALL_TMPETC="$(pwd)/config" \
		    sh @SRCTOP@/usr.sbin/bsdinstall/scripts/firmware-fetch \
		    gpu-firmware-intel-kmod-alderlake
	done
	atf_check -s exit:0 -o inline:'if_iwlwifi i915kms\n' \
	    sh -c 'kld_list=if_iwlwifi; . ./config/rc.conf.hardware; echo "$kld_list"'
}

atf_test_case usb_descriptor_records
usb_descriptor_records_body()
{
	setup
	mkdir detect
	cp @SRCTOP@/usr.sbin/fwget/usb/usb* detect/
	cat >bin/usbconfig <<-'EOF'
	#!/bin/sh
	[ "$1" = dump_device_desc ] || exit 1
	cat <<'DESCRIPTORS'
	ugen0.1: <Intel Bluetooth> at usbus0
	  idVendor = 0x8087
	  idProduct = 0x0033
	ugen0.2: <Ralink WLAN> at usbus0
	  idVendor = 0x148f
	  idProduct = 0x7601
	ugen0.3: <Realtek Ethernet> at usbus0
	  idVendor = 0x0bda
	  idProduct = 0x8153
	  bInterfaceNumber = 0x00
	  bInterfaceClass = 0x02
	  bInterfaceSubClass = 0x06
	  bInterfaceProtocol = 0x00
	ugen0.4: <Realtek Bluetooth> at usbus0
	  idVendor = 0x0bda
	  idProduct = 0xb00c
	  bInterfaceNumber = 0x00
	  bInterfaceClass = 0xe0
	  bInterfaceSubClass = 0x01
	  bInterfaceProtocol = 0x01
	ugen0.5: <OEM Bluetooth> at usbus0
	  idVendor = 0x13d3
	  idProduct = 0x3529
	DESCRIPTORS
	EOF
	chmod +x bin/usbconfig
	atf_check -s exit:0 -e empty -o inline:'iwmbt-firmware\nwifi-firmware-mt7601u-kmod\nrtlbt-firmware\n' \
	    env LIBEXEC_PATH="$(pwd)/detect" sh @SRCTOP@/usr.sbin/fwget/fwget.sh -qn usb
}

atf_test_case raw_firmware_not_kernel_bound
raw_firmware_not_kernel_bound_body()
{
	setup
	# A signed repository identifies data-only firmware without claiming an
	# exact kernel identity. No module may use this path.
	sed 's/echo "5BSD_kernel_sha256=${TEST_DIGEST}"/echo "5BSD_hardware_kind=firmware"/' bin/pkg >bin/pkg.new
	mv bin/pkg.new bin/pkg
	chmod +x bin/pkg
	atf_check -s exit:0 -o empty -e empty sh "${HELPER}" iwmbt-firmware
}

atf_test_case offline_repository_without_devices
offline_repository_without_devices_body()
{
	setup
	mkdir media
	echo '{}' >media/hardware.json
	echo firmware >media/test.pkg
	atf_check -s exit:0 -o empty -e empty env \
	    BSDINSTALL_CHROOT="${FWGET_ROOT}" \
	    BSDINSTALL_HARDWARE_MEDIA="$(pwd)/media" \
	    BSDINSTALL_HARDWARE_INSTALL=/does-not-exist \
	    sh @SRCTOP@/usr.sbin/bsdinstall/scripts/firmware-fetch
	atf_check -s exit:0 cmp media/test.pkg root/usr/5bsd-packages/hardware/test.pkg
	atf_check -s exit:1 test -f state/calls
}

atf_test_case automatic_selection
automatic_selection_body()
{
	setup
	cat >bin/chroot <<-'EOF'
	#!/bin/sh
	[ "$*" = "${FWGET_ROOT} fwget -q -n" ] || exit 99
	[ "${TEST_DETECT_FAIL:-}" != yes ] || exit 42
	printf '%s\n' test-firmware gpu-firmware-intel-kmod-alderlake
	EOF
	chmod +x bin/chroot
	mkdir fragments
	export BSDINSTALL_CHROOT="${FWGET_ROOT}"
	export BSDINSTALL_HARDWARE_MEDIA=$(pwd)/absent
	export BSDINSTALL_HARDWARE_INSTALL="${HELPER}"
	export BSDINSTALL_TMPETC=$(pwd)/fragments
	atf_check -s exit:0 -o empty -e ignore sh @SRCTOP@/usr.sbin/bsdinstall/scripts/firmware-fetch --auto
	atf_check -s exit:0 -o ignore grep -F 'install -U -qy -r 5BSD-hardware 5BSD-hw-test-firmware 5BSD-hw-gpu-firmware-intel-kmod-alderlake' state/calls
	atf_check -s exit:0 -o ignore grep -F i915kms fragments/rc.conf.hardware
	rm state/calls
	atf_check -s exit:42 -o empty -e empty env TEST_DETECT_FAIL=yes sh @SRCTOP@/usr.sbin/bsdinstall/scripts/firmware-fetch --auto
	[ ! -f state/calls ] || atf_fail 'Detection failure must stop installation'
}

atf_test_case mediatek_split_firmware
mediatek_split_firmware_body()
{
	. @SRCTOP@/usr.sbin/fwget/pci/pci_network_mediatek
	addpkg() { printf '%s\n' "$1"; }
	for id in 0x0608 0x0616 0x7920 0x7922 0x7961; do
		selected=$(pci_network_mediatek_mt76 "$id")
		[ "$selected" = wifi-firmware-mt76-kmod-mt7921 ] ||
		    atf_fail "wrong firmware for $id: $selected"
	done
	for id in 0x0717 0x7925; do
		selected=$(pci_network_mediatek_mt76 "$id")
		[ "$selected" = wifi-firmware-mt76-kmod-mt7925 ] ||
		    atf_fail "wrong firmware for $id: $selected"
	done
}

atf_test_case missing_pkg_does_not_bootstrap
missing_pkg_does_not_bootstrap_body()
{
	setup
	atf_check -s exit:1 -o empty -e match:'requires pkg' \
	    env TEST_PKG_MISSING=1 sh "${HELPER}" test-firmware
	[ ! -f state/calls ] || atf_fail 'pkg bootstrap or repository operation was attempted'
}

atf_test_case missing_media_bootstrap_is_reported
missing_media_bootstrap_is_reported_body()
{
	setup
	atf_check -s exit:1 -o empty -e match:'media has no pkg bootstrap' env \
	    TEST_PKG_MISSING=1 BSDINSTALL_CHROOT="${FWGET_ROOT}" \
	    BSDINSTALL_PKG_MEDIA="$(pwd)/absent" \
	    BSDINSTALL_HARDWARE_MEDIA="$(pwd)/absent" \
	    BSDINSTALL_HARDWARE_INSTALL="${HELPER}" \
	    sh @SRCTOP@/usr.sbin/bsdinstall/scripts/firmware-fetch test-firmware
	[ ! -f state/calls ] || atf_fail 'pkg bootstrap or repository operation was attempted'
}

atf_test_case embedded_pkg_static_is_used
embedded_pkg_static_is_used_body()
{
	setup
	mkdir -p media bootstrap/usr/local/sbin private-tmp
	echo '{}' >media/hardware.json
	# The live pkg is only a stub; the archived executable is usable.
	sed 's/exit "${TEST_PKG_MISSING:-0}"/exit 0/' bin/pkg >bootstrap/usr/local/sbin/pkg-static
	chmod +x bootstrap/usr/local/sbin/pkg-static
	tar -cf media/pkg-1.pkg -C bootstrap usr/local/sbin/pkg-static
	atf_check -s exit:0 -o empty -e empty env \
	    TEST_PKG_MISSING=1 BSDINSTALL_CHROOT="${FWGET_ROOT}" \
	    BSDINSTALL_PKG_MEDIA="$(pwd)/media" \
	    BSDINSTALL_HARDWARE_MEDIA="$(pwd)/media" \
	    BSDINSTALL_HARDWARE_INSTALL="${HELPER}" TMPDIR="$(pwd)/private-tmp" \
	    sh @SRCTOP@/usr.sbin/bsdinstall/scripts/firmware-fetch test-firmware
	atf_check -s exit:0 -o ignore grep -F 'install -U -qy' state/calls
	atf_check -s exit:0 -o empty ls private-tmp
}

atf_test_case firmware_failure_retains_stderr
firmware_failure_retains_stderr_body()
{
	setup
	# Exercise the dialog's installation path without running detection or
	# opening a real terminal. Keep the actual execution/logging code.
	sed -n '/^# Initialize/,$p' @SRCTOP@/usr.sbin/bsdinstall/scripts/firmware >dialog-body
	cat >dialog <<-'EOF'
	#!/bin/sh
	printf '%s\n' "$*" >>"${TEST_STATE}/dialog"
	EOF
	cat >fail-install <<-'EOF'
	#!/bin/sh
	echo 'hardware catalogue unavailable' >&2
	exit 1
	EOF
	chmod +x dialog fail-install
	cat >run-dialog <<-'EOF'
	#!/bin/sh
	f_dialog_title() { DIALOG_TITLE=$1; }
	f_dialog_backtitle() { DIALOG_BACKTITLE=$1; }
	dialog_menu_main() { return 0; }
	f_dialog_menutag_fetch() { selected=test-firmware; }
	f_mustberoot_init() { :; }
	f_dprintf() { printf "$@" >>"${TEST_STATE}/debug"; }
	msg_firmware_installation=Hardware
	msg_installer=Installer
	OSNAME=5BSD
	DIALOG="$(pwd)/dialog"
	BSDINSTALL_FIRMWARE_FETCH="$(pwd)/fail-install"
	BSDINSTALL_TMPETC="$(pwd)/absent"
	TMPDIR="$(pwd)"
	. ./dialog-body
	EOF
	atf_check -s exit:1 -o empty -e empty sh run-dialog
	atf_check -s exit:0 -o ignore grep -F 'hardware catalogue unavailable' state/dialog
	atf_check -s exit:0 -o ignore grep -F 'hardware catalogue unavailable' state/debug
	atf_check -s exit:0 -o ignore grep -F 'hardware catalogue unavailable' bsdinstall-firmware-log.*
}

atf_init_test_cases()
{
	atf_add_test_case missing_pkg_does_not_bootstrap
	atf_add_test_case missing_media_bootstrap_is_reported
	atf_add_test_case embedded_pkg_static_is_used
	atf_add_test_case firmware_failure_retains_stderr
	atf_add_test_case mediatek_split_firmware
	atf_add_test_case automatic_selection
	atf_add_test_case target_kernel_and_dependencies
	atf_add_test_case mismatch_rejected
	atf_add_test_case missing_dependency_rejected
	atf_add_test_case stale_catalog_revalidated
	atf_add_test_case offline_repository_persists
	atf_add_test_case fwget_graphics_and_usb
	atf_add_test_case graphics_startup_preserves_modules
	atf_add_test_case usb_descriptor_records
	atf_add_test_case raw_firmware_not_kernel_bound
	atf_add_test_case offline_repository_without_devices
}
