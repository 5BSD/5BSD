/*
 * OpenEndpointSecurity network events — socket operations.
 *
 * Traces OES network-related MAC hooks: socket create, connect,
 * bind, listen, send, receive. Shows which processes trigger
 * network security checks. Requires oes.ko loaded.
 */

fbt::oes_mac_socket_check_create:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: OES socket create check\n", execname, pid);
    @net_ops[execname, "create"] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::oes_mac_socket_check_connect:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: OES socket connect check\n", execname, pid);
    @net_ops[execname, "connect"] = count();
}

fbt::oes_mac_socket_check_bind:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: OES socket bind check\n", execname, pid);
    @net_ops[execname, "bind"] = count();
}

fbt::oes_mac_socket_check_listen:entry
/* @bsdinstruments-predicate */
{
    @net_ops[execname, "listen"] = count();
}

fbt::oes_mac_socket_check_send:entry
/* @bsdinstruments-predicate */
{
    @net_ops[execname, "send"] = count();
}

fbt::oes_mac_socket_check_receive:entry
/* @bsdinstruments-predicate */
{
    @net_ops[execname, "receive"] = count();
}

dtrace:::END
{
    printf("\n--- OES network checks by process/op ---\n");
    printf("%-20s %-10s %8s\n", "EXECNAME", "OP", "COUNT");
    printa("%-20s %-10s %@8d\n", @net_ops);
}
