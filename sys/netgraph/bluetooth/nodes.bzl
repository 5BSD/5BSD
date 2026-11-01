# SPDX-License-Identifier: BSD-2-Clause
"""Original Bluetooth module sources, shared across target architectures."""
BLUETOOTH_MODULES = [
    struct(name = "ng_bluetooth", srcs = ["common/ng_bluetooth.c"], usb = False),
    struct(name = "ng_hci", srcs = ["hci/ng_hci_main.c", "hci/ng_hci_cmds.c", "hci/ng_hci_evnt.c", "hci/ng_hci_ulpi.c", "hci/ng_hci_misc.c"], usb = False),
    struct(name = "ng_l2cap", srcs = ["l2cap/ng_l2cap_main.c", "l2cap/ng_l2cap_cmds.c", "l2cap/ng_l2cap_evnt.c", "l2cap/ng_l2cap_ulpi.c", "l2cap/ng_l2cap_llpi.c", "l2cap/ng_l2cap_misc.c"], usb = False),
    struct(name = "ng_btsocket", srcs = ["socket/ng_btsocket.c", "socket/ng_btsocket_hci_raw.c", "socket/ng_btsocket_l2cap_raw.c", "socket/ng_btsocket_l2cap.c", "socket/ng_btsocket_rfcomm.c", "socket/ng_btsocket_sco.c", "socket/ng_btsocket_iso.c"], usb = False),
    struct(name = "ng_ubt", srcs = ["drivers/ubt/ng_ubt.c", "drivers/ubt/ng_ubt_intel.c", "drivers/ubt/ng_ubt_rtl.c"], usb = True),
    struct(name = "ubtbcmfw", srcs = ["drivers/ubtbcmfw/ubtbcmfw.c"], usb = True),
    struct(name = "ng_hci_virt", srcs = ["drivers/vhci/ng_hci_virt.c"], usb = False),
]
