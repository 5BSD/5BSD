/* library validation failures. See COVERAGE-TWENTYFIRST for scalar argument meanings. */

timecmp*:::wait-start
/* @bsdinstruments-predicate */
{
    @timecmp_wait_start[0] = count();
}

timecmp*:::wait-done
/* @bsdinstruments-predicate */
{
    @timecmp_wait_done[(int)arg1, (int)arg2] = count();
}

timecmp*:::reply-malformed
/* @bsdinstruments-predicate */
{
    @timecmp_reply_malformed[(int)arg0] = count();
}

capsuleclaims*:::rights-parsed
/* @bsdinstruments-predicate */
{
    @capsuleclaims_rights_parsed[(int)arg0, (int)arg1, arg2] = count();
}

shmring*:::record-reject
/* @bsdinstruments-predicate */
{
    @shmring_record_reject[(int)arg0] = count();
}
