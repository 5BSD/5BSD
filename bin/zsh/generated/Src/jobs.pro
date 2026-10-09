/* Generated automatically */
#ifdef HAVE_GETRUSAGE
static struct rusage child_usage;
#else
static struct tms shtms;
#endif
static struct timeval*dtime(struct timeval*dt,struct timeval*t1,struct timeval*t2);
static int super_job(int sub);
static int handle_sub(int job,int fg);
static void setprevjob(void);
static void printhhmmss(double secs);
static void dumptime(Job jn);
static int should_report_time(Job j);
static int zwaitjob(int job,int wait_cmd);
static int isanum(char*s);
static void setcurjob(void);
