/* Generated automatically */
static int exit_trap_posix;
static volatile int trap_queueing_enabled;
static volatile int trap_queue_front;
static volatile int trap_queue_rear;
static int trap_queue[MAX_QUEUE_SIZE];
static int handletrap(int sig);
static void dotrapargs(int sig,int*sigtr,void*sigfn);
