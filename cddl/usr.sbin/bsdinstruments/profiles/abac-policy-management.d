/* abac policy management. See COVERAGE-TWENTYFIRST for scalar argument meanings. */

abacdaemon*:::policy-start
/* @bsdinstruments-predicate */
{
    @abacdaemon_policy_start[(int)arg0] = count();
}

abacdaemon*:::policy-done
/* @bsdinstruments-predicate */
{
    @abacdaemon_policy_done[(int)arg0, (int)arg1] = count();
}

abacctl*:::policy-start
/* @bsdinstruments-predicate */
{
    @abacctl_policy_start[(int)arg0] = count();
}

abacctl*:::policy-done
/* @bsdinstruments-predicate */
{
    @abacctl_policy_done[(int)arg0, (int)arg1] = count();
}
