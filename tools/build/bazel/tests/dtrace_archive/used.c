#include <sys/sdt.h>
int selected(int value) { DTRACE_PROBE1(archiveprobe, used, value); return value + 1; }
