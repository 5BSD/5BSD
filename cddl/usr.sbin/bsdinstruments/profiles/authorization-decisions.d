/* authorization decisions. See COVERAGE-TWENTYFIRST for scalar argument meanings. */

sdt:::abac-check-bypass
/* @bsdinstruments-predicate */
{
    @sdt_abac_check_bypass[arg0, (int)arg1, (int)arg2] = count();
}

sdt:::abac-rule-decision
/* @bsdinstruments-predicate */
{
    @sdt_abac_rule_decision[arg0, arg1, arg2, (int)arg3] = count();
}

sdt:::abac-default-decision
/* @bsdinstruments-predicate */
{
    @sdt_abac_default_decision[arg0, (int)arg1, (int)arg2] = count();
}

sdt:::oes-response-rejected
/* @bsdinstruments-predicate */
{
    @sdt_oes_response_rejected[(int)arg0, (int)arg1, (int)arg2] = count();
}

sdt:::oes-auth-flags
/* @bsdinstruments-predicate */
{
    @sdt_oes_auth_flags[arg0, arg1, arg2, (int)arg3] = count();
}
