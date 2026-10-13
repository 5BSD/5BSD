/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-SEVENTH.
 * Pointers are opaque. Elapsed time includes blocking and preemption.
 * Start before the workload; drops or nonlocal exits invalidate pairing.
 * PID filters select executing context, not the initiating workload.
 */

mesh*:::manager-transaction
/* @bsdinstruments-predicate */
{
    @transaction[(uint16_t)arg0, (uint32_t)arg1, (int)arg2, (unsigned)arg3] = count();
}

mesh*:::bridge-forward
/* @bsdinstruments-predicate */
{
    @bridge[(uint16_t)arg2, (uint16_t)arg3] = count();
}

mesh*:::directed-expire
/* @bsdinstruments-predicate */
{
    @expired = count();
}

mesh*:::directed-control
/* @bsdinstruments-predicate */
{
    @control[(uint8_t)arg0] = count();
}

mesh*:::remote-timeout
/* @bsdinstruments-predicate */
{
    @remote_timeout = count();
}

mesh*:::remote-transfer
/* @bsdinstruments-predicate */
{
    @remote_bytes = sum(arg2);
}

mesh*:::lpn-state
/* @bsdinstruments-predicate */
{
    @lpn[(uint16_t)arg0, (int)arg1] = count();
}

mesh*:::mesh-keyrefresh-phase
/* @bsdinstruments-predicate */
{
    @keyrefresh[(int)arg0, (int)arg1] = count();
}

mesh*:::mesh-friend-poll
/* @bsdinstruments-predicate */
{
    @poll[(int)arg0, (int)arg1] = count();
}

mesh*:::mesh-proxy-reasm
/* @bsdinstruments-predicate */
{
    @proxy[(int)arg0, (int)arg1] = count();
}

mesh*:::mesh-cfg-appkey
/* @bsdinstruments-predicate */
{
    @appkey_operation[(int)arg0] = count();
}

mesh*:::mesh-model-recv
/* @bsdinstruments-predicate */
{
    @model_opcode[(int)arg0] = count();
}
