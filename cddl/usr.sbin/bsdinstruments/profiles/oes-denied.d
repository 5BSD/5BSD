/*
 * OpenEndpointSecurity denied operations — security alert stream.
 *
 * Prints every OES AUTH denial with process and event details.
 * Use for real-time security monitoring and threat detection.
 * Requires oes.ko loaded.
 */

oes:::auth-deny
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: OES DENIED event=%d\n", execname, arg1, arg0);
    @denied[execname, arg0] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

oes:::auth-timeout
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: OES TIMEOUT event=%d default_action=%d\n",
        execname, arg1, arg0, arg2);
    @timeouts[execname, arg0] = count();
}

dtrace:::END
{
    printf("\n--- OES denied operations ---\n");
    printf("%-20s %8s %8s\n", "EXECNAME", "EVENT", "COUNT");
    printa("%-20s %8d %@8d\n", @denied);
    printf("\n--- OES timeouts ---\n");
    printa("%-20s %8d %@8d\n", @timeouts);
}
