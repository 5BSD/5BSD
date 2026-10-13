/* zsh execution. Scalar diagnostics; no message or command contents.
 * Argument meanings: tools/test/system-tracing/COVERAGE-TWENTIETH.
 */

zsh*:::fork-start
/* @bsdinstruments-predicate */
{
    @zsh_fork_start[0] = count();
}

zsh*:::fork-done
/* @bsdinstruments-predicate */
{
    @zsh_fork_done[(int)arg1] = count();
}

zsh*:::job-limit
/* @bsdinstruments-predicate */
{
    @zsh_job_limit = quantize(arg0);
}

zsh*:::exec-attempt
/* @bsdinstruments-predicate */
{
    @zsh_exec_attempt[(int)arg0] = count();
}

zsh*:::exec-failure
/* @bsdinstruments-predicate */
{
    @zsh_exec_failure[(int)arg1] = count();
}

zsh*:::pipeline-start
/* @bsdinstruments-predicate */
{
    @zsh_pipeline_start[(int)arg1] = count();
}

zsh*:::pipeline-done
/* @bsdinstruments-predicate */
{
    @zsh_pipeline_done[(int)arg1] = count();
}

zsh*:::wait-start
/* @bsdinstruments-predicate */
{
    @zsh_wait_start[(int)arg1] = count();
}

zsh*:::wait-done
/* @bsdinstruments-predicate */
{
    @zsh_wait_done[(int)arg1] = count();
}
