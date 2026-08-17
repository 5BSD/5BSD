/* KINST — trace one instruction inside a kernel function */
/* Usage: bsdinstruments watch kinst --param func=<name> --param offset=<bytes> */

kinst::${func}:${offset}
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: ${func}+${offset}\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
