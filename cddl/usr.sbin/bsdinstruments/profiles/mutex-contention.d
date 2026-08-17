/*
 * Quantize kernel adaptive-mutex wait time by execname.
 * Equivalent of Apple Instruments' Mutex Contention.
 */

lockstat:::adaptive-block
/* @bsdinstruments-predicate */
{
    @block[execname] = quantize(arg1);
}

lockstat:::adaptive-spin
/* @bsdinstruments-predicate */
{
    @spin[execname] = quantize(arg1);
}

dtrace:::END
{
    printf("\n--- adaptive mutex block (ns) ---\n");
    printa(@block);
    printf("\n--- adaptive mutex spin (ns) ---\n");
    printa(@spin);
}
