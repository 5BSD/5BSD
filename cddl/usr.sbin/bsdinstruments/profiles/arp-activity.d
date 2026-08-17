/*
 * ARP activity — address resolution events.
 *
 * Traces ARP request/reply handling via FBT. High ARP rates
 * indicate network scanning, misconfigured subnets, or
 * ARP spoofing. Useful for network troubleshooting.
 */

fbt::arprequest:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: ARP request\n", execname, pid);
    @arp_ops[execname, "request"] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::in_arpinput:entry
/* @bsdinstruments-predicate */
{
    @arp_ops[execname, "input"] = count();
}

dtrace:::END
{
    printf("\n--- ARP activity by process/type ---\n");
    printf("%-20s %-10s %8s\n", "EXECNAME", "TYPE", "COUNT");
    printa("%-20s %-10s %@8d\n", @arp_ops);
}
