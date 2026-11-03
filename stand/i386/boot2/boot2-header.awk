/([0-9])+ T xread/ {
    x = $1 - ORG1;
    printf("#define XREADORG %#x\n", REL1 + x)
}
