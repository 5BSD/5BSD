/* oes client outcomes. See COVERAGE-TWENTYFIRST for scalar argument meanings. */

oesclient*:::batch-read
/* @bsdinstruments-predicate */
{
    @oesclient_batch_read[(int)arg1] = count();
}

oesclient*:::buffer-corrupt
/* @bsdinstruments-predicate */
{
    @oesclient_buffer_corrupt[0] = count();
}

oesclient*:::auth-response
/* @bsdinstruments-predicate */
{
    @oesclient_auth_response[arg0, arg1, arg2, (int)arg3] = count();
}

oeslogger*:::event-handled
/* @bsdinstruments-predicate */
{
    @oeslogger_event_handled[(int)arg0] = count();
}

oeslogger*:::wait-done
/* @bsdinstruments-predicate */
{
    @oeslogger_wait_done[(int)arg0, (int)arg1] = count();
}

oeslogger*:::dispatch-error
/* @bsdinstruments-predicate */
{
    @oeslogger_dispatch_error[(int)arg0, (int)arg1] = count();
}
