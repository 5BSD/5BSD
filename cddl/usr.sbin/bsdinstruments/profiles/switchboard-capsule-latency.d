/* Capsule RPC latency. Start before workload; drops invalidate pairing. */
switchboard*:::capsule-rpc-start
/* @bsdinstruments-predicate */
{
    rpc_depth[pid, tid]++;
    rpc_start[pid, tid, rpc_depth[pid, tid]] = timestamp;
}
switchboard*:::capsule-rpc-done
/rpc_start[pid, tid, rpc_depth[pid, tid]] != 0/
{
    @rpc_us = quantize((timestamp - rpc_start[pid, tid, rpc_depth[pid, tid]]) / 1000);
    @rpc_results[(int)arg0, (int)arg1] = count();
    rpc_start[pid, tid, rpc_depth[pid, tid]] = 0;
    rpc_depth[pid, tid]--;
}
