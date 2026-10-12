/* Embedded image integrity cost, including exec, O_VERIFY, descriptor checks
 * and executable-capable mmap. SPDX-License-Identifier: BSD-2-Clause
 * Source IDs: 0=exec, 1=O_VERIFY open, 2=descriptor check, 3=mmap.
 * Recognized means an EOF signature marker was found, not signer authority.
 * No paths, descriptor numbers, keys, policy bytes or pointers are recorded. */
#pragma D option quiet

capimage::verify:start
/* @bsdinstruments-predicate */
{
    self->capverify_depth++;
    capverify_start[tid, self->capverify_depth] = timestamp;
    @attempts[execname, arg0, arg2] = count();
    @input_bytes[execname, arg0] = sum(arg1);
}

capimage::verify:done
/self->capverify_depth == 0 /* @bsdinstruments-predicate-and */ /
{
    @unpaired_completions[execname, arg0] = count();
}

capimage::verify:done
/self->capverify_depth > 0/
{
    @results[execname, arg0, arg1, arg2] = count();
    @elapsed_ns[execname, arg0, arg1, arg2] =
        sum(timestamp - capverify_start[tid, self->capverify_depth]);
    @hashed_bytes[execname, arg0, arg1] = sum(arg3);
    capverify_start[tid, self->capverify_depth] = 0;
    self->capverify_depth--;
}
