/*
 * Kernel cryptographic operation audit via opencrypto.
 *
 * Traces crypto_dispatch to show kernel crypto requests
 * by process. Useful for monitoring IPsec, GELI, ZFS
 * encryption, and TLS offload activity.
 */

fbt::crypto_dispatch:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: crypto_dispatch\n", execname, pid);
    @crypto_ops[execname] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::crypto_done:entry
/* @bsdinstruments-predicate */
{
    @crypto_done[execname] = count();
}

dtrace:::END
{
    printf("\n--- Crypto dispatches by process ---\n");
    printa("%-30s %@d\n", @crypto_ops);
    printf("\n--- Crypto completions by process ---\n");
    printa("%-30s %@d\n", @crypto_done);
}
