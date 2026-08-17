/*
 * TCP state transitions — aggregate by old/new state and process.
 *
 * Turns raw tcp:::state-change events into a queryable table
 * showing which processes drive the most state transitions
 * and what the transition patterns look like.
 */

tcp:::state-change
/* @bsdinstruments-predicate */
{
    @transitions[execname,
        args[5]->tcps_state == 0 ? "CLOSED" :
        args[5]->tcps_state == 1 ? "LISTEN" :
        args[5]->tcps_state == 2 ? "SYN_SENT" :
        args[5]->tcps_state == 3 ? "SYN_RCVD" :
        args[5]->tcps_state == 4 ? "ESTABLISHED" :
        args[5]->tcps_state == 5 ? "CLOSE_WAIT" :
        args[5]->tcps_state == 6 ? "FIN_WAIT_1" :
        args[5]->tcps_state == 7 ? "CLOSING" :
        args[5]->tcps_state == 8 ? "LAST_ACK" :
        args[5]->tcps_state == 9 ? "FIN_WAIT_2" :
        args[5]->tcps_state == 10 ? "TIME_WAIT" :
        "UNKNOWN",
        args[3]->tcps_state == 0 ? "CLOSED" :
        args[3]->tcps_state == 1 ? "LISTEN" :
        args[3]->tcps_state == 2 ? "SYN_SENT" :
        args[3]->tcps_state == 3 ? "SYN_RCVD" :
        args[3]->tcps_state == 4 ? "ESTABLISHED" :
        args[3]->tcps_state == 5 ? "CLOSE_WAIT" :
        args[3]->tcps_state == 6 ? "FIN_WAIT_1" :
        args[3]->tcps_state == 7 ? "CLOSING" :
        args[3]->tcps_state == 8 ? "LAST_ACK" :
        args[3]->tcps_state == 9 ? "FIN_WAIT_2" :
        args[3]->tcps_state == 10 ? "TIME_WAIT" :
        "UNKNOWN"] = count();
}

dtrace:::END
{
    printf("\n--- TCP state transitions by process ---\n");
    printf("%-20s %-14s %-14s %8s\n", "EXECNAME", "FROM", "TO", "COUNT");
    printa("%-20s %-14s %-14s %@8d\n", @transitions);
}
