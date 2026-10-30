#include <sys/sdt.h>
extern int dependency_not_linked(void);
int unselected(int value) { DTRACE_PROBE1(archiveprobe, unused, value); return dependency_not_linked(); }
