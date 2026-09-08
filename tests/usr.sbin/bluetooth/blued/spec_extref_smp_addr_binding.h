/*
 * EXTERNAL REFERENCE ORACLE: which device addresses bind into the SMP
 * confirm/check value functions.
 *
 * Hand-written.  Every claim is traceable to a named external source; nothing
 * here was derived from blued and no value was produced by running 5BSD code.
 *
 * WHY THIS HEADER EXISTS
 * ----------------------
 * The byte ORDER of the address inside f5/f6/c1 is easy to check and is
 * already covered by spec_extref_smp_vectors.h.  What no vector can catch is
 * feeding the function the WRONG ADDRESS in the right order: the pairing then
 * fails only when the local device is using a resolvable private address, so
 * it passes every unit test and every non-private integration test, and fails
 * in the field on exactly the configuration that privacy-enabled deployments
 * use.
 *
 * SPEC
 * ----
 * /usr/src/bluetooth-specs/Core_Specification_6_3.txt
 *
 *   Vol 3, Part H, Section 2.3.5.5 (text lines 76972-76973), the decisive
 *   sentence, verbatim:
 *     "Initiating and responding device addresses used for confirmation
 *      generation shall be device addresses used during connection setup, see
 *      [Vol 3] Part C, Section 9.3"
 *
 *   Note what that sentence does NOT say: it does not say the identity
 *   address, and it does not say the adapter address.  It says the address
 *   used during connection setup -- which, with link layer privacy enabled, is
 *   a resolvable private address that changes on every rotation.
 *
 *   Vol 3, Part H, Section 2.2.7 / 2.2.8 (text lines 76397-76400), on the A1
 *   and A2 inputs to f5 and f6, verbatim:
 *     "A is the device address of the Central and B is the device address of
 *      the Peripheral. The least significant bit in the most significant octet
 *      in both A and B is set to 1 if the address is a random address and set
 *      to 0 if the address is a public address. The 7 most significant bits of
 *      the most significant octet in both A and B are set to 0."
 *
 *   The type bit is therefore a property of the address that was actually on
 *   the air.  A resolvable private address is a random address, so a device
 *   pairing over an RPA must set that bit to 1 even if its identity address is
 *   public.  Hard-coding the type is wrong for the same reason hard-coding the
 *   address is.
 *
 * REFERENCE IMPLEMENTATIONS: ALL THREE USE THE ON-AIR ADDRESS
 * ----------------------------------------------------------
 *   Linux kernel, net/bluetooth/smp.c (the SMP implementation of the BlueZ
 *   stack; BlueZ userspace does not implement SMP):
 *     sc_mackey_and_ltk() and sc_dhkey_check() take hcon->init_addr and
 *     hcon->resp_addr together with their *_addr_type fields.  Those fields
 *     hold the addresses used to establish the connection, which for a private
 *     connection are the resolvable private addresses, not the identity
 *     addresses -- the kernel keeps the identity separately.
 *   Zephyr, snapshot commit 2665fcca3cced3aefb7202d6289991d8cc1dfcac:
 *     subsys/bluetooth/host/smp.c passes &conn->le.init_addr and
 *     &conn->le.resp_addr into bt_crypto_f5() and bt_crypto_f6().
 *   Apache NimBLE, snapshot commit
 *   1e8ed60276f35a80ed4d4b4f8bb9d9c6fee53845:
 *     nimble/host/src/ble_sm.c passes the connection's our_ota_addr and
 *     peer_ota_addr into ble_sm_alg_f5()/f6().  NimBLE's field name states the
 *     rule outright: OTA is "over the air".
 *
 * All three keep a separate identity address and all three deliberately do not
 * use it here.  There is no ecosystem split on this point.
 */
#ifndef TESTS_BLUETOOTH_SPEC_EXTREF_SMP_ADDR_BINDING_H
#define TESTS_BLUETOOTH_SPEC_EXTREF_SMP_ADDR_BINDING_H

/*
 * Which address a conforming implementation binds into c1 (ia/ra), f5 (A1/A2)
 * and f6 (A1/A2).  Set to 1 to record "the address used during connection
 * setup, i.e. the on-air address", and 0 for "the identity address".
 *
 * Core 6.3, Vol 3, Part H, Section 2.3.5.5, text lines 76972-76973.
 */
#define BT_EXTREF_SMP_BINDS_ON_AIR_ADDRESS		1
#define BT_EXTREF_SMP_BINDS_IDENTITY_ADDRESS		0

/*
 * The address type octet that accompanies it is likewise a property of the
 * on-air address, per Vol 3, Part H, Section 2.2.7 (text lines 76397-76400).
 * A resolvable private address is a random address.  Set to 1 to record that
 * a device whose identity address is PUBLIC but which connected using an RPA
 * must present the RANDOM type bit in A1/A2.
 */
#define BT_EXTREF_SMP_RPA_PRESENTS_RANDOM_TYPE_BIT	1

/*
 * The type bit values, from the same passage: 1 for a random address, 0 for a
 * public address, carried as the least significant bit of the most significant
 * octet of the 7-octet A1/A2 input.
 */
#define BT_EXTREF_SMP_ADDR_TYPE_BIT_PUBLIC		0
#define BT_EXTREF_SMP_ADDR_TYPE_BIT_RANDOM		1

/*
 * Reference corroboration, recorded so a test can assert the unanimity rather
 * than restating it in prose.  1 = uses the on-air connection address.
 */
#define BT_EXTREF_SMP_ADDR_LINUX_USES_ON_AIR		1
#define BT_EXTREF_SMP_ADDR_ZEPHYR_USES_ON_AIR		1
#define BT_EXTREF_SMP_ADDR_NIMBLE_USES_ON_AIR		1

#endif /* TESTS_BLUETOOTH_SPEC_EXTREF_SMP_ADDR_BINDING_H */
