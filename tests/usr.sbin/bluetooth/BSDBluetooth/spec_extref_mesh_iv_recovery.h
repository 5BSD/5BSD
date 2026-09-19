/*
 * EXTERNAL REFERENCE ORACLE: Bluetooth Mesh IV Index Recovery, and the
 * acceptance window for a Secure Network beacon's IV Index.
 *
 * Hand-written.  Every value and every claim below is traceable to a named
 * external source; nothing here was derived from any file under
 * /usr/src/usr.sbin/bluetooth or /usr/src/lib, and no value was produced by
 * running 5BSD code.
 *
 * ANTI-DRIFT CONTRACT
 * ===================
 * /usr/src/bluetooth-specs contains no Mesh Profile or Mesh Protocol
 * specification, so mesh behaviour in this tree has no in-tree external gate
 * and can silently drift into mirroring the implementation it is meant to
 * check.  The same contract as spec_extref_mesh_vectors.h applies here: the
 * sources of record are the two independent reference implementations, and
 * where one of them quotes the specification in a comment, that quotation is
 * reproduced verbatim and labelled as the reference's citation rather than as
 * our own reading of a document we do not have.
 *
 * EXTERNAL SOURCES OF RECORD
 * ==========================
 *   Zephyr, github.com/zephyrproject-rtos/zephyr, snapshot commit
 *     2665fcca3cced3aefb7202d6289991d8cc1dfcac
 *     Primary file: subsys/bluetooth/mesh/net.c, bt_mesh_net_iv_update()
 *   BlueZ, git.kernel.org/pub/scm/bluetooth/bluez.git, snapshot commit
 *     92305dc06ab8a6d89af2dae1d725cc4d51462ad1
 *     Primary file: mesh/net.c, update_iv_ivu_state() and process_beacon()
 *
 * THE NORMATIVE RULE, AS QUOTED BY ZEPHYR
 * =======================================
 * zephyr/subsys/bluetooth/mesh/net.c, in bt_mesh_net_iv_update(), carries this
 * comment immediately before it performs the recovery.  It is Zephyr's own
 * citation of MshPRT v1.1, reproduced verbatim:
 *
 *   "MshPRTv1.1 allows to initiate an IV Index Recovery procedure if previous
 *    IV update has been missed. This allows the node to remain functional.
 *
 *    Upon receiving and successfully authenticating a Secure Network beacon
 *    for a primary subnet whose IV Index is 1 or more higher than the current
 *    known IV Index, the node shall set its current IV Index and its current
 *    IV Update procedure state from the values in this Secure Network beacon."
 *
 * Read the second paragraph carefully.  It is a "shall", its trigger is
 * "receiving and successfully authenticating a Secure Network beacon", and it
 * has no other precondition.  There is no arming step, no separate procedure
 * to enter, and no operator action: authentication of the beacon IS the
 * trigger.  Both references implement it that way.
 *
 * WHAT EACH REFERENCE DOES
 * ========================
 * Zephyr, bt_mesh_net_iv_update():
 *   - rejects iv_index < current, or iv_index > current + 42
 *   - discards the [iv, false] -> [iv, true] transition
 *   - takes the recovery branch when iv_index > current + 1, OR when
 *     iv_index == current + 1 and either an IV update is already in progress
 *     or the beacon's IV Update flag is clear
 *   - the ONLY brake on the recovery branch is
 *     "ivi_was_recovered && ivu_duration < 2 * BT_MESH_IVU_MIN_HOURS",
 *     logged as "IV Index Recovery before minimum delay"
 *   - on recovery it sets ivi_was_recovered, calls bt_mesh_rpl_clear(),
 *     assigns bt_mesh.iv_index = iv_index, and sets bt_mesh.seq = 0
 *
 * BlueZ, update_iv_ivu_state() and process_beacon():
 *   - mesh/net.c:39  #define IV_IDX_DIFF_RANGE 42
 *   - mesh/net.c:2784 rejects a beacon outside
 *     [net->iv_index, net->iv_index + IV_IDX_DIFF_RANGE]
 *   - mesh/net.c:2752-2753 zeroes the sequence number on a forward jump:
 *       if ((iv_index - ivu) > (net->iv_index - net->iv_update))
 *               mesh_net_set_seq_num(net, 0);
 *   - mesh/net.c:2755-2762 persists the new index and prunes the replay
 *     protection list, under the comment
 *       "Cleanup Replay Protection List NVM"
 *   - the only hold state is IV_UPD_NORMAL_HOLD (mesh/net.c:76, entered at
 *     :2550), the 96-hour brake
 *   - there is no arming step of any kind
 *
 * The two agree on every point that matters: the window is [cur, cur+42], the
 * adoption is automatic on an authenticated beacon, the sequence number is
 * reset, and the replay protection list is cleared or pruned.
 */
#ifndef TESTS_BLUETOOTH_SPEC_EXTREF_MESH_IV_RECOVERY_H
#define TESTS_BLUETOOTH_SPEC_EXTREF_MESH_IV_RECOVERY_H

#include <stdint.h>

/*
 * The acceptance window for a Secure Network beacon's IV Index, relative to
 * the node's current index.  Zephyr rejects iv_index > current + 42 in
 * bt_mesh_net_iv_update(); BlueZ defines IV_IDX_DIFF_RANGE as 42 at
 * mesh/net.c:39 and enforces it at mesh/net.c:2784.  Independently identical
 * in both references.
 */
#define BT_EXTREF_MESH_IV_DIFF_RANGE			42

/*
 * A beacon carrying an index BELOW the node's current index is rejected by
 * both references (Zephyr: iv_index < bt_mesh.iv_index; BlueZ: ivi <
 * net->iv_index at mesh/net.c:2784).  Note this concerns the BEACON path only
 * -- accepting a received network PDU at iv-1 is a separate rule and is not
 * what this constant is about.
 */
#define BT_EXTREF_MESH_IV_BEACON_MIN_OFFSET		0

/*
 * Is entering IV Index Recovery gated on any separate arming or enabling step,
 * beyond receiving and authenticating the beacon?  Both references: no.
 * 0 records "no arming step exists".
 */
#define BT_EXTREF_MESH_IV_RECOVERY_REQUIRES_ARMING	0

/*
 * The four beacon cases and whether a conforming node adopts the beacon's IV
 * Index.  Derived from Zephyr's branch structure in bt_mesh_net_iv_update()
 * and confirmed against BlueZ's window check, which admits all of them.
 * 1 = adopt.
 */
/* iv_index == current + 1, beacon IV Update flag SET, node not in progress:
 * the ordinary IV Update, not recovery. */
#define BT_EXTREF_MESH_IV_ADOPT_PLUS1_FLAG_SET		1
/* iv_index == current + 1, beacon IV Update flag CLEAR: the node missed the
 * whole update; recovery branch. */
#define BT_EXTREF_MESH_IV_ADOPT_PLUS1_FLAG_CLEAR	1
/* iv_index == current + 1 while the node already has an update in progress:
 * recovery branch. */
#define BT_EXTREF_MESH_IV_ADOPT_PLUS1_WHILE_IN_PROGRESS	1
/* iv_index in [current + 2, current + 42]: recovery branch. */
#define BT_EXTREF_MESH_IV_ADOPT_PLUS2_TO_42		1

/*
 * Side effects a conforming node performs when it adopts an index by recovery.
 * Zephyr: bt_mesh_rpl_clear() and bt_mesh.seq = 0.  BlueZ:
 * mesh_net_set_seq_num(net, 0) at mesh/net.c:2753 and rpl_update() at :2761.
 * 1 = the reference performs it.
 */
#define BT_EXTREF_MESH_IV_RECOVERY_RESETS_SEQ		1
#define BT_EXTREF_MESH_IV_RECOVERY_CLEARS_RPL		1

/*
 * The rate limit.  Zephyr brakes on
 * "ivi_was_recovered && ivu_duration < 2 * BT_MESH_IVU_MIN_HOURS", i.e. twice
 * the 96-hour minimum, and only for a SECOND recovery -- the first recovery
 * after boot is never rate-limited.  BlueZ's equivalent brake is the
 * IV_UPD_NORMAL_HOLD state.
 */
#define BT_EXTREF_MESH_IVU_MIN_HOURS			96
#define BT_EXTREF_MESH_IV_RECOVERY_MIN_HOURS		(2 * BT_EXTREF_MESH_IVU_MIN_HOURS)
#define BT_EXTREF_MESH_IV_FIRST_RECOVERY_RATE_LIMITED	0

/*
 * The subnet whose beacon drives the node's IV Index: the PRIMARY subnet, per
 * the MshPRT v1.1 text quoted in the file comment above ("a Secure Network
 * beacon for a primary subnet").  1 = primary only.
 */
#define BT_EXTREF_MESH_IV_PRIMARY_SUBNET_ONLY		1

#endif /* TESTS_BLUETOOTH_SPEC_EXTREF_MESH_IV_RECOVERY_H */
