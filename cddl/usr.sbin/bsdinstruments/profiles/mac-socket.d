/*
 * MAC Framework socket checks — network access control decisions.
 *
 * Traces MAC checks on socket operations: create, connect,
 * bind, listen, send, receive. Non-zero returns indicate
 * a MAC policy denied the network operation.
 */

fbt::mac_socket_check_create:entry
/* @bsdinstruments-predicate */
{
    self->mac_sock_op = "create";
}

fbt::mac_socket_check_connect:entry
/* @bsdinstruments-predicate */
{
    self->mac_sock_op = "connect";
}

fbt::mac_socket_check_bind:entry
/* @bsdinstruments-predicate */
{
    self->mac_sock_op = "bind";
}

fbt::mac_socket_check_listen:entry
/* @bsdinstruments-predicate */
{
    self->mac_sock_op = "listen";
}

fbt::mac_socket_check_send:entry
/* @bsdinstruments-predicate */
{
    self->mac_sock_op = "send";
}

fbt::mac_socket_check_receive:entry
/* @bsdinstruments-predicate */
{
    self->mac_sock_op = "receive";
}

fbt::mac_socket_check_create:return,
fbt::mac_socket_check_connect:return,
fbt::mac_socket_check_bind:return,
fbt::mac_socket_check_listen:return,
fbt::mac_socket_check_send:return,
fbt::mac_socket_check_receive:return
/self->mac_sock_op && arg1 != 0/
{
    printf("%s[%d]: MAC DENIED socket %s err=%d\n",
        execname, pid, self->mac_sock_op, arg1);
    @denied[execname, self->mac_sock_op] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
    self->mac_sock_op = 0;
}

fbt::mac_socket_check_create:return,
fbt::mac_socket_check_connect:return,
fbt::mac_socket_check_bind:return,
fbt::mac_socket_check_listen:return,
fbt::mac_socket_check_send:return,
fbt::mac_socket_check_receive:return
/self->mac_sock_op && arg1 == 0/
{
    @allowed[execname, self->mac_sock_op] = count();
    self->mac_sock_op = 0;
}

dtrace:::END
{
    printf("\n--- MAC socket denials ---\n");
    printf("%-20s %-10s %8s\n", "EXECNAME", "OP", "COUNT");
    printa("%-20s %-10s %@8d\n", @denied);
    printf("\n--- MAC socket allowed ---\n");
    printa("%-20s %-10s %@8d\n", @allowed);
}
