/*
 * OpenEndpointSecurity event dispatch — enqueue and drop rates.
 *
 * Traces event delivery to OES clients. Dropped events indicate
 * a client's queue is full — the client is too slow to process
 * events. Requires oes.ko loaded.
 */

oes:::event-enqueue
/* @bsdinstruments-predicate */
{
    @enqueued[arg2, arg0] = count();
}

oes:::event-drop
/* @bsdinstruments-predicate */
{
    printf("OES EVENT DROP: event=%d pid=%d client=%d\n",
        arg0, arg1, arg2);
    @dropped[arg2, arg0] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- Events enqueued by client/type ---\n");
    printf("%8s %8s %8s\n", "CLIENT", "EVENT", "COUNT");
    printa("%8d %8d %@8d\n", @enqueued);
    printf("\n--- Events DROPPED by client/type ---\n");
    printa("%8d %8d %@8d\n", @dropped);
}
