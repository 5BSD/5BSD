/* SPDX-License-Identifier: BSD-2-Clause
 * Raw MAC callback argument slots, in mac_policy.h declaration order.
 * See tools/test/system-tracing/mac-hook-arguments.json for names/types.
 * Pointer values are identities. By-value structures are borrowed addresses
 * valid only during this probe. Printing every hook can be high volume.
 */
mac_framework:::hook-args
/* @bsdinstruments-predicate */
{
    this->v = (uint64_t *)arg3;
    printf("pid=%d hook=%s policy=%s argc=%u args=%llx,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
        pid, stringof(arg0), stringof(arg1), (uint_t)arg2,
        arg2 > 0 ? this->v[0] : 0,
        arg2 > 1 ? this->v[1] : 0,
        arg2 > 2 ? this->v[2] : 0,
        arg2 > 3 ? this->v[3] : 0,
        arg2 > 4 ? this->v[4] : 0,
        arg2 > 5 ? this->v[5] : 0,
        arg2 > 6 ? this->v[6] : 0,
        arg2 > 7 ? this->v[7] : 0);
}
