/* SPDX-License-Identifier: BSD-2-Clause */
/* Disposable VM fixture: inspect authority independently of discovery. */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/cap_authority.h>
#include <sys/ioctl.h>
#include <dev/mac_capability/mac_capability_ioctl.h>
#include <errno.h>
#include <libservice.h>
#include <libservice_session.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <switchboard_ctl.h>
static int
control_operation(struct service_session *session, uint32_t operation)
{
 struct sctl_request request = { .op = operation };
 char response[sizeof(struct sctl_reply) + SWITCHBOARD_CTL_SUMMARY_MAX];
 struct service_message message = { .size = sizeof(message),
     .data = &request, .length = sizeof(request) };
 struct service_reply reply = { .size = sizeof(reply), .data = response,
     .capacity = sizeof(response) };
 struct service_call_options options = SERVICE_CALL_OPTIONS_INITIALIZER;
 struct sctl_reply header;
 options.timeout_ms = 5000;
 if (service_session_call(session, &message, &reply, &options) == -1)
  return -1;
 if (reply.length < sizeof(header)) return errno = EPROTO, -1;
 memcpy(&header, response, sizeof(header));
 if (header.status != 0) return errno = header.status, -1;
 return 0;
}

int main(int argc, char **argv) {
 struct cap_authority_info info;
 int route;
 if (argc == 2 && strcmp(argv[1], "hostile-user-agent") == 0) {
  struct service_session *session;
  gid_t groups[64];
  unsigned mode;
  int count, fd;
  if (getuid() != 2001 || geteuid() != 2001 || getgid() != 2001 || getegid() != 2001)
   errx(1,"user agent escaped owner credentials");
  count = getgroups(64, groups);
  if (count < 0) err(1,"agent groups");
  for (int i = 0; i < count; i++)
   if (groups[i] == 0) errx(1,"agent retained wheel group");
  if (cap_getmode(&mode) == -1 || mode != 1) errx(1,"agent not sandboxed");
  if (service_resource_dir("/root", &fd) == 0)
   errx(1,"agent received root-only directory");
  if (service_resource_dir("/tmp", &fd) == -1) err(1,"agent public directory");
  close(fd);
  if (service_open("system.Trace", &route) == 0)
   errx(1,"agent self-granted trace access");
  if (errno != ENOENT && errno != EPERM) err(1,"unexpected trace denial");
  if (service_open(SWITCHBOARD_CONTROL_NAME, &route) == 0) {
   if (service_session_create(route, &session) == -1) err(1,"agent control session");
   if (control_operation(session, SCTL_OP_RELOAD) != -1 || errno != EPERM)
    errx(1,"agent self-granted administration");
   service_session_close(session);
  } else if (errno != ENOENT && errno != EPERM) err(1,"unexpected control denial");
  puts("SOFTWARE_HOSTILE_USER_AGENT_PROCESS_PASS");
  return 0;
 }
 if (argc == 4 && strcmp(argv[1], "managed-control") == 0) {
  struct service_session *session;
  FILE *result;
  int rc, error;
  if (service_open(SWITCHBOARD_CONTROL_NAME, &route) == -1) err(1,"managed control lookup");
  if (service_session_create(route, &session) == -1) err(1,"managed control session");
  if (control_operation(session, SCTL_OP_STATUS) == -1) err(1,"managed status");
  rc = control_operation(session, SCTL_OP_RELOAD);
  error = errno;
  if (strcmp(argv[2], "allow") == 0) {
   if (rc != 0) errx(1,"attributed managed reload failed: %s",strerror(error));
  } else if (strcmp(argv[2], "deny") == 0) {
   if (rc != -1 || error != EPERM) errx(1,"unprivileged managed reload not denied");
  } else errx(2,"unknown managed test expectation");
  service_session_close(session);
  result = fopen(argv[3], "w");
  if (result == NULL) err(1,"managed result marker");
  if (fprintf(result, "%s\n", argv[2]) < 0 || fclose(result) != 0) err(1,"managed marker write");
  return 0;
 }
 if (argc == 4 && strcmp(argv[1], "hold-control") == 0) {
  struct service_session *session;
  int ready, error;
  unsigned tries;
  if (service_open(SWITCHBOARD_CONTROL_NAME, &route) == -1) err(1,"open control");
  if (service_session_create(route, &session) == -1) err(1,"control session");
  if (control_operation(session, SCTL_OP_STATUS) == -1) err(1,"initial control request");
  ready = open(argv[2], O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (ready == -1) err(1,"ready marker");
  close(ready);
  for (tries = 0; tries < 120 && access(argv[3], F_OK) != 0; tries++) usleep(250000);
  if (tries == 120) errx(1,"revocation trigger timed out");
  if (service_authority_info(&info) == -1 || info.valid)
   errx(1,"live process retained revoked authority");
  if (control_operation(session, SCTL_OP_STATUS) == 0) errx(1,"cached control connection survived revocation");
  error = errno;
  if (error != EPERM && error != ECONNRESET && error != EPIPE && error != EBADF)
   errx(1,"unexpected revocation result: %s", strerror(error));
  service_session_close(session);
  puts("SOFTWARE_CACHED_REVOCATION_PASS");
  return 0;
 }
 if (argc==2 && strcmp(argv[1],"check-application")==0) {
  if (service_authority_info(&info)==-1) err(1,"authority info");
  route=service_ambient_lookup_fd();
  if (route<0) err(1,"discovery route");
  close(route);
  if (!info.valid || info.kind!=CAP_AUTH_MANAGED) errx(1,"missing software authority");
  printf("%ju:%ju\n",(uintmax_t)info.issuer,(uintmax_t)info.identity);
  return 0;
 }
 if (argc==2 && strcmp(argv[1],"route-generation")==0) {
  struct mac_cap_process_info process;
  if (service_process_info(&process)==-1) err(1,"process info");
  if (!process.present) errx(1,"missing discovery route");
  printf("%ju\n",(uintmax_t)process.generation);
  return 0;
 }
 if (argc==3 && strcmp(argv[1],"attach-denied")==0) {
  pid_t target=(pid_t)strtol(argv[2],NULL,10); int status;
  if (target<=1) errx(1,"invalid debugger fixture target");
  if (ptrace(PT_ATTACH,target,NULL,0)==-1) {
   if (errno!=EPERM) err(1,"unexpected attach denial");
   return 0;
  }
  (void)waitpid(target,&status,WUNTRACED);
  (void)ptrace(PT_DETACH,target,(caddr_t)1,0);
  errx(1,"root without authority attached to attributed process");
 }
 if (argc==2 && strcmp(argv[1],"boot-handle")==0) {
  int fd=-1, forbidden=-1; unsigned tries;
  struct mac_capability_sendmsg_args message={0};
  uint32_t operation=1;
  if (service_authority_info(&info)==-1 || !info.valid || info.kind!=CAP_AUTH_MANAGED) errx(1,"missing managed boot authority");
  route=service_ambient_lookup_fd();
  if (route<0 || service_open("system.SystemExtension",&fd)==-1) err(1,"boot extension lookup");
  if (service_open("system.switchboard",&forbidden)==0) errx(1,"boot obtained forbidden control endpoint");
  close(route);
  puts("AUTHORITY_BOOT_SCOPE_PASS"); fflush(stdout);
  for (tries=0; tries<300 && access("/tmp/authority-after-rc",F_OK)!=0; tries++) sleep(1);
  if (tries==300) errx(1,"boot test timed out");
  if (service_authority_info(&info)==-1 || info.valid) errx(1,"boot authority survived rc");
  message.payload=&operation; message.payload_len=sizeof(operation);
  if (ioctl(fd,MAC_CAPABILITY_SENDMSG,&message)!=-1 || errno!=EPERM) errx(1,"cached boot handle survived revocation");
  close(fd); puts("AUTHORITY_BOOT_REVOCATION_PASS"); return 0;
 }
 if (argc == 3 && strcmp(argv[1], "check") == 0) {
  if (service_authority_info(&info) == -1) err(1,"authority info");
  route=service_ambient_lookup_fd();
  if (route<0) err(1,"discovery route");
  close(route);
  printf("AUTHORITY_SESSION uid=%u valid=%u kind=%u principal=%u generation=%ju\n",(unsigned)getuid(),info.valid,info.kind,info.uid,(uintmax_t)info.generation);
  if (strcmp(argv[2],"none")==0) return info.valid ? 1 : 0;
  errx(2,"check accepts only none; use check-application for software authority");
 }
 if (argc>=3 && strcmp(argv[1],"cleanexec")==0) {
  closefrom(3); clearenv(); execv(argv[2],argv+2); err(1,"execv");
 }
 errx(2,"usage: authority-session-check check none | cleanexec /program [args]");
}
