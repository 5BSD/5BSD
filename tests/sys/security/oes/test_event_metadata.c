/*
 * OES event metadata integration test.
 *
 * Exercises live kernel population of process, thread, clock, file, and
 * cached executable metadata.  The child execs a copy of this test under a
 * new pathname and then forks, allowing the test to verify that exec replaces
 * the cached path and execution ID and that the new identity is inherited.
 */
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bsm/audit.h>
#include <security/oes/oes.h>
#include "test_common.h"

#define META_TIMEOUT_MS 5000
#define META_CHILD_ARG "--oes-metadata-child"

static int
timespec_cmp(const struct timespec *a, const struct timespec *b)
{

	if (a->tv_sec != b->tv_sec)
		return (a->tv_sec < b->tv_sec ? -1 : 1);
	if (a->tv_nsec != b->tv_nsec)
		return (a->tv_nsec < b->tv_nsec ? -1 : 1);
	return (0);
}

static int
current_executable(char *path, size_t path_size)
{
	int mib[4];
	size_t len;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PATHNAME;
	mib[3] = -1;
	len = path_size;
	if (sysctl(mib, nitems(mib), path, &len, NULL, 0) != 0)
		return (-1);
	if (len == 0 || path[0] == '\0' || path[len - 1] != '\0') {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

static int
copy_executable(const char *source, char *destination, size_t destination_size,
    struct stat *destination_stat)
{
	char buffer[32768];
	ssize_t nr;
	int input, output, error;

	if (strlcpy(destination, "/tmp/oes-metadata-exec.XXXXXX",
	    destination_size) >= destination_size) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	input = open(source, O_RDONLY | O_CLOEXEC);
	if (input < 0)
		return (-1);
	output = mkstemp(destination);
	if (output < 0) {
		close(input);
		return (-1);
	}
	error = 0;
	while ((nr = read(input, buffer, sizeof(buffer))) > 0) {
		ssize_t off = 0;

		while (off < nr) {
			ssize_t nw = write(output, buffer + off, (size_t)(nr - off));

			if (nw < 0) {
				error = errno;
				break;
			}
			off += nw;
		}
		if (error != 0)
			break;
	}
	if (nr < 0 && error == 0)
		error = errno;
	if (error == 0 && fchmod(output, 0700) != 0)
		error = errno;
	if (error == 0 && fsync(output) != 0)
		error = errno;
	if (error == 0 && fstat(output, destination_stat) != 0)
		error = errno;
	close(input);
	close(output);
	if (error != 0) {
		unlink(destination);
		errno = error;
		return (-1);
	}
	return (0);
}

static int
run_post_exec_child(void)
{
	pid_t child;
	int status;

	(void)pthread_setname_np(pthread_self(), "oes-meta-post");
	child = fork();
	if (child < 0)
		return (122);
	if (child == 0)
		_exit(0);
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		return (123);
	return (0);
}

static int
check_file_metadata(const oes_file_t *file, const struct stat *sb)
{
	int errors = 0;

#define FILE_CHECK(_cond, _name) do { \
	if (!(_cond)) { \
		fprintf(stderr, "  FAIL: file metadata: %s\n", (_name)); \
		errors++; \
	} \
} while (0)

	FILE_CHECK((file->ef_meta_flags & OES_FILE_META_ATTR_UNAVAILABLE) == 0,
	    "attributes reported unavailable");
	FILE_CHECK(file->ef_token.eft_id == (uint64_t)sb->st_ino,
	    "token inode mismatch");
	FILE_CHECK(file->ef_token.eft_dev == (uint64_t)sb->st_dev,
	    "token device mismatch");
	FILE_CHECK(file->ef_ino == (uint64_t)sb->st_ino, "inode mismatch");
	FILE_CHECK(file->ef_dev == (uint64_t)sb->st_dev, "device mismatch");
	FILE_CHECK(file->ef_size == (uint64_t)sb->st_size, "size mismatch");
	FILE_CHECK(file->ef_blocks == (uint64_t)sb->st_blocks,
	    "allocated block count mismatch");
	FILE_CHECK(file->ef_allocated_bytes == (uint64_t)sb->st_blocks * 512,
	    "allocated byte count mismatch");
	FILE_CHECK(file->ef_block_size == (uint64_t)sb->st_blksize,
	    "preferred block size mismatch");
	FILE_CHECK(file->ef_generation == sb->st_gen, "generation mismatch");
	FILE_CHECK(file->ef_rdev == (uint64_t)sb->st_rdev, "rdev mismatch");
	FILE_CHECK(file->ef_filerev == sb->st_filerev, "filerev mismatch");
	FILE_CHECK(file->ef_mode == (sb->st_mode & ~S_IFMT), "mode mismatch");
	FILE_CHECK(file->ef_uid == sb->st_uid, "uid mismatch");
	FILE_CHECK(file->ef_gid == sb->st_gid, "gid mismatch");
	FILE_CHECK(file->ef_flags == sb->st_flags, "flags mismatch");
	FILE_CHECK(file->ef_nlink == sb->st_nlink, "link count mismatch");
	FILE_CHECK(file->ef_type == EF_TYPE_REG, "file type is not regular");
	FILE_CHECK(file->ef_atime == sb->st_atim.tv_sec &&
	    file->ef_atime_nsec == sb->st_atim.tv_nsec,
	    "access timestamp mismatch");
	FILE_CHECK(file->ef_mtime == sb->st_mtim.tv_sec &&
	    file->ef_mtime_nsec == sb->st_mtim.tv_nsec,
	    "modification timestamp mismatch");
	FILE_CHECK(file->ef_ctime == sb->st_ctim.tv_sec &&
	    file->ef_ctime_nsec == sb->st_ctim.tv_nsec,
	    "change timestamp mismatch");
	FILE_CHECK(file->ef_birthtime == sb->st_birthtim.tv_sec &&
	    file->ef_birthtime_nsec == sb->st_birthtim.tv_nsec,
	    "birth timestamp mismatch");
	FILE_CHECK((file->ef_meta_flags & OES_FILE_META_FSTYPE_UNAVAILABLE) == 0,
	    "filesystem type reported unavailable");
	FILE_CHECK((file->ef_meta_flags & OES_FILE_META_PROPOSED_ATTRS) == 0,
	    "existing file reported as proposed attributes");
	FILE_CHECK(file->ef_fstype[0] != '\0', "filesystem type is empty");
	FILE_CHECK(file->ef_reserved == 0, "reserved field is nonzero");

#undef FILE_CHECK
	return (errors);
}

static int
check_process_metadata(const oes_message_t *msg, const oes_process_t *proc,
    pid_t child, pid_t parent, const char *expected_path)
{
	auditinfo_addr_t audit_info;
	char loginclass[MAXLOGNAME];
	const char *path;
	const char *login;
	uid_t ruid, euid, suid;
	gid_t rgid, egid, sgid;
	int errors = 0, nice_value;

#define PROC_CHECK(_cond, _name) do { \
	if (!(_cond)) { \
		fprintf(stderr, "  FAIL: process metadata: %s\n", (_name)); \
		errors++; \
	} \
} while (0)

	path = oes_msg_string(msg, proc->ep_path_off);
	PROC_CHECK(proc->ep_pid == child, "pid mismatch");
	PROC_CHECK(proc->ep_ppid == parent, "parent pid mismatch");
	PROC_CHECK(proc->ep_original_ppid == parent, "real parent pid mismatch");
	if ((proc->ep_meta_flags & OES_PROC_META_SESSION_UNAVAILABLE) == 0) {
		PROC_CHECK(proc->ep_pgid == getpgrp(), "process group mismatch");
		PROC_CHECK(proc->ep_sid == getsid(0), "session id mismatch");
	}
	PROC_CHECK(proc->ep_token.ept_id == (uint64_t)child,
	    "process token pid mismatch");
	PROC_CHECK(proc->ep_token.ept_genid != 0, "process generation is zero");
	PROC_CHECK(proc->ep_exec_id != 0, "execution ID is zero");
	if (getresuid(&ruid, &euid, &suid) == 0) {
		PROC_CHECK(proc->ep_uid == euid, "effective uid mismatch");
		PROC_CHECK(proc->ep_ruid == ruid, "real uid mismatch");
		PROC_CHECK(proc->ep_suid == suid, "saved uid mismatch");
	}
	if (getresgid(&rgid, &egid, &sgid) == 0) {
		PROC_CHECK(proc->ep_gid == egid, "effective gid mismatch");
		PROC_CHECK(proc->ep_rgid == rgid, "real gid mismatch");
		PROC_CHECK(proc->ep_sgid == sgid, "saved gid mismatch");
	}
	PROC_CHECK(proc->ep_ngroups > 0, "group snapshot is empty");
	PROC_CHECK(proc->ep_groups[0] == getegid(),
	    "effective group missing from group snapshot");
	PROC_CHECK(proc->ep_state == OES_PROC_STATE_NORMAL,
	    "process state is not normal");
	PROC_CHECK(proc->ep_num_threads >= 1, "thread count is zero");
	errno = 0;
	nice_value = getpriority(PRIO_PROCESS, 0);
	if (nice_value != -1 || errno == 0)
		PROC_CHECK(proc->ep_nice == nice_value, "nice value mismatch");
	PROC_CHECK(proc->ep_osrel != 0, "binary OS release is zero");
	PROC_CHECK(proc->ep_abi == EP_ABI_FREEBSD, "binary ABI is not FreeBSD");
	PROC_CHECK(proc->ep_start_sec != 0, "process start time is zero");
	PROC_CHECK(proc->ep_comm[0] != '\0', "command name is empty");
	login = getlogin();
	if (login != NULL && (proc->ep_meta_flags &
	    OES_PROC_META_SESSION_UNAVAILABLE) == 0)
		PROC_CHECK(strcmp(proc->ep_login, login) == 0,
		    "session login name mismatch");
	if (getloginclass(loginclass, sizeof(loginclass)) == 0)
		PROC_CHECK(strcmp(proc->ep_loginclass, loginclass) == 0,
		    "login class mismatch");
	if (getaudit_addr(&audit_info, sizeof(audit_info)) == 0) {
		PROC_CHECK(proc->ep_auid == audit_info.ai_auid,
		    "audit user mismatch");
		PROC_CHECK(proc->ep_asid == (uint32_t)audit_info.ai_asid,
		    "audit session mismatch");
		PROC_CHECK(proc->ep_audit_mask_success ==
		    audit_info.ai_mask.am_success, "audit success mask mismatch");
		PROC_CHECK(proc->ep_audit_mask_failure ==
		    audit_info.ai_mask.am_failure, "audit failure mask mismatch");
		PROC_CHECK(proc->ep_audit_term_port == audit_info.ai_termid.at_port,
		    "audit terminal port mismatch");
		PROC_CHECK(proc->ep_audit_term_type == audit_info.ai_termid.at_type,
		    "audit terminal type mismatch");
		PROC_CHECK(memcmp(proc->ep_audit_term_addr,
		    audit_info.ai_termid.at_addr,
		    sizeof(proc->ep_audit_term_addr)) == 0,
		    "audit terminal address mismatch");
		PROC_CHECK(proc->ep_audit_flags == audit_info.ai_flags,
		    "audit flags mismatch");
	}
	PROC_CHECK((proc->ep_meta_flags &
	    OES_PROC_META_CREDENTIALS_UNAVAILABLE) == 0,
	    "credentials reported unavailable");
	PROC_CHECK((proc->ep_meta_flags & OES_PROC_META_CWD_UNAVAILABLE) != 0,
	    "cwd availability is not explicit");
	PROC_CHECK(((proc->ep_meta_flags & OES_PROC_META_GROUPS_TRUNCATED) != 0) ==
	    (proc->ep_ngroups > nitems(proc->ep_groups)),
	    "group truncation flag mismatch");
	if ((proc->ep_meta_flags & (OES_PROC_META_PARENT_UNAVAILABLE |
	    OES_PROC_META_SESSION_UNAVAILABLE)) == 0)
		PROC_CHECK(proc->ep_reaper_pid > 0, "process reaper is missing");
	PROC_CHECK((proc->ep_meta_flags & OES_PROC_META_PATH_UNAVAILABLE) == 0,
	    "executable path reported unavailable");
	PROC_CHECK((proc->ep_meta_flags & OES_PROC_META_PATH_TRUNCATED) == 0,
	    "short executable path reported truncated");
	PROC_CHECK(path[0] != '\0', "executable path is empty");
	PROC_CHECK(strcmp(path, expected_path) == 0, "executable path mismatch");
	PROC_CHECK(proc->ep_pad2 == 0 && proc->ep_reserved == 0,
	    "reserved process fields are nonzero");

#undef PROC_CHECK
	return (errors);
}

static int
check_event_clocks(const oes_message_t *msg, const struct timespec *mono_before,
    const struct timespec *mono_after, const struct timespec *wall_before,
    const struct timespec *wall_after)
{
	struct timespec event_mono, event_wall, wall_floor, wall_ceiling;
	int errors = 0;

	event_mono.tv_sec = msg->em_time.tv_sec;
	event_mono.tv_nsec = msg->em_time.tv_nsec;
	event_wall.tv_sec = msg->em_wall_time.tv_sec;
	event_wall.tv_nsec = msg->em_wall_time.tv_nsec;
	wall_floor = *wall_before;
	wall_ceiling = *wall_after;
	wall_floor.tv_sec -= 2;
	wall_ceiling.tv_sec += 2;

	if (event_mono.tv_nsec < 0 || event_mono.tv_nsec >= 1000000000L ||
	    timespec_cmp(&event_mono, mono_before) < 0 ||
	    timespec_cmp(&event_mono, mono_after) > 0) {
		fprintf(stderr, "  FAIL: monotonic event timestamp is out of range\n");
		errors++;
	}
	if (event_wall.tv_nsec < 0 || event_wall.tv_nsec >= 1000000000L ||
	    timespec_cmp(&event_wall, &wall_floor) < 0 ||
	    timespec_cmp(&event_wall, &wall_ceiling) > 0) {
		fprintf(stderr, "  FAIL: wall event timestamp is out of range\n");
		errors++;
	}
	return (errors);
}

int
main(int argc, char **argv)
{
	struct test_event_reader reader;
	test_msg_buf incoming, open_event, exec_event, fork_event;
	struct oes_mode_args mode;
	struct oes_subscribe_args sub;
	oes_event_type_t events[] = {
		OES_EVENT_NOTIFY_OPEN,
		OES_EVENT_NOTIFY_EXEC,
		OES_EVENT_NOTIFY_FORK,
	};
	struct timespec mono_before, mono_after, wall_before, wall_after, start;
	struct stat temp_stat, exec_stat;
	char test_path[PATH_MAX], exec_path[PATH_MAX];
	char temp_path[] = "/tmp/oes-metadata.XXXXXX";
	const char payload[] = "OES metadata fixture\n";
	pid_t child, parent;
	int fd, temp_fd, status, errors, got_open, got_exec, got_fork;

	if (argc == 2 && strcmp(argv[1], META_CHILD_ARG) == 0)
		return (run_post_exec_child());
	printf("Testing live OES event metadata...\n");
	if (current_executable(test_path, sizeof(test_path)) != 0) {
		fprintf(stderr, "resolve current executable: %s\n",
		    strerror(errno));
		return (1);
	}
	if (copy_executable(test_path, exec_path, sizeof(exec_path),
	    &exec_stat) != 0) {
		perror("copy metadata test executable");
		return (1);
	}
	temp_fd = mkstemp(temp_path);
	if (temp_fd < 0) {
		perror("mkstemp");
		unlink(exec_path);
		return (1);
	}
	if (write(temp_fd, payload, sizeof(payload) - 1) !=
	    (ssize_t)(sizeof(payload) - 1) || fsync(temp_fd) != 0 ||
	    fstat(temp_fd, &temp_stat) != 0) {
		perror("prepare metadata fixture");
		close(temp_fd);
		unlink(temp_path);
		unlink(exec_path);
		return (1);
	}
	close(temp_fd);

	fd = open(OES_DEVICE_PATH, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open " OES_DEVICE_PATH);
		unlink(temp_path);
		unlink(exec_path);
		return (1);
	}
	memset(&mode, 0, sizeof(mode));
	mode.ema_mode = OES_MODE_NOTIFY;
	if (ioctl(fd, OES_IOC_SET_MODE, &mode) != 0) {
		perror("OES_IOC_SET_MODE");
		close(fd);
		unlink(temp_path);
		unlink(exec_path);
		return (1);
	}
	memset(&sub, 0, sizeof(sub));
	sub.esa_events = events;
	sub.esa_count = nitems(events);
	sub.esa_flags = OES_SUB_REPLACE;
	if (ioctl(fd, OES_IOC_SUBSCRIBE, &sub) != 0) {
		perror("OES_IOC_SUBSCRIBE");
		close(fd);
		unlink(temp_path);
		unlink(exec_path);
		return (1);
	}
	/* Suppress the observer's reads while retaining events from its child. */
	(void)test_mute_self(fd);
	test_event_reader_init(&reader);
	parent = getpid();
	clock_gettime(CLOCK_MONOTONIC, &mono_before);
	clock_gettime(CLOCK_REALTIME, &wall_before);

	child = fork();
	if (child < 0) {
		perror("fork");
		close(fd);
		unlink(temp_path);
		unlink(exec_path);
		return (1);
	}
	if (child == 0) {
		int child_fd;

		close(fd);
		(void)pthread_setname_np(pthread_self(), "oes-meta-open");
		child_fd = open(temp_path, O_RDONLY | O_CLOEXEC);
		if (child_fd < 0)
			_exit(120);
		close(child_fd);
		execl(exec_path, exec_path, META_CHILD_ARG, (char *)NULL);
		_exit(121);
	}

	got_open = got_exec = got_fork = 0;
	clock_gettime(CLOCK_MONOTONIC, &start);
	while (!got_open || !got_exec || !got_fork) {
		struct timespec now;
		long elapsed_ms;
		oes_message_t *msg;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (now.tv_sec - start.tv_sec) * 1000L +
		    (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms >= META_TIMEOUT_MS)
			break;
		if (test_event_reader_next(&reader, fd, &incoming.msg, 100) != 0)
			continue;
		msg = &incoming.msg;
		if (!oes_message_is_compatible(msg) ||
		    msg->em_process.ep_pid != child)
			continue;
		if (!got_open && msg->em_event == OES_EVENT_NOTIFY_OPEN &&
		    msg->em_event_data.open.file.ef_token.eft_id ==
		    (uint64_t)temp_stat.st_ino &&
		    msg->em_event_data.open.file.ef_token.eft_dev ==
		    (uint64_t)temp_stat.st_dev) {
			memcpy(open_event.raw, incoming.raw, msg->em_size);
			got_open = 1;
		} else if (!got_exec && msg->em_event == OES_EVENT_NOTIFY_EXEC &&
		    strcmp(oes_msg_string(msg,
		    msg->em_event_data.exec.target.ep_path_off), exec_path) == 0) {
			memcpy(exec_event.raw, incoming.raw, msg->em_size);
			got_exec = 1;
		} else if (!got_fork && msg->em_event == OES_EVENT_NOTIFY_FORK) {
			memcpy(fork_event.raw, incoming.raw, msg->em_size);
			got_fork = 1;
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &mono_after);
	clock_gettime(CLOCK_REALTIME, &wall_after);
	(void)waitpid(child, &status, 0);
	close(fd);
	unlink(temp_path);
	unlink(exec_path);

	errors = 0;
	if (!got_open) {
		fprintf(stderr, "  FAIL: matching NOTIFY_OPEN was not received\n");
		errors++;
	}
	if (!got_exec) {
		fprintf(stderr, "  FAIL: matching NOTIFY_EXEC was not received\n");
		errors++;
	}
	if (!got_fork) {
		fprintf(stderr, "  FAIL: post-exec NOTIFY_FORK was not received\n");
		errors++;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "  FAIL: metadata child exited abnormally\n");
		errors++;
	}
	if (!got_open || !got_exec || !got_fork)
		return (1);

	errors += check_file_metadata(&open_event.msg.em_event_data.open.file,
	    &temp_stat);
	errors += check_file_metadata(
	    &exec_event.msg.em_event_data.exec.executable, &exec_stat);
	errors += check_process_metadata(&open_event.msg,
	    &open_event.msg.em_process, child, parent, test_path);
	errors += check_event_clocks(&open_event.msg, &mono_before, &mono_after,
	    &wall_before, &wall_after);
	if (open_event.msg.em_version != OES_MESSAGE_VERSION ||
	    open_event.msg.em_struct_size != sizeof(oes_message_t) ||
	    open_event.msg.em_size < sizeof(oes_message_t) ||
	    open_event.msg.em_seq_num == 0 ||
	    open_event.msg.em_global_seq_num == 0 ||
	    !oes_message_has_auth_result(&open_event.msg) ||
	    open_event.msg.em_result != OES_AUTH_ALLOW) {
		fprintf(stderr, "  FAIL: message envelope metadata mismatch\n");
		errors++;
	}
	if ((open_event.msg.em_thread.et_flags & OES_THREAD_META_PRESENT) == 0 ||
	    open_event.msg.em_thread.et_id == 0 ||
	    strcmp(open_event.msg.em_thread.et_name, "oes-meta-open") != 0 ||
	    open_event.msg.em_thread.et_reserved != 0) {
		fprintf(stderr, "  FAIL: triggering thread metadata mismatch\n");
		errors++;
	}
	if (open_event.msg.em_event_data.open.file.ef_path_off == 0) {
		if ((open_event.msg.em_event_data.open.file.ef_meta_flags &
		    OES_FILE_META_PATH_UNAVAILABLE) == 0) {
			fprintf(stderr, "  FAIL: missing file path lacks availability flag\n");
			errors++;
		}
	} else if (strcmp(oes_msg_string(&open_event.msg,
	    open_event.msg.em_event_data.open.file.ef_path_off), temp_path) != 0) {
		fprintf(stderr, "  FAIL: available file path does not match fixture\n");
		errors++;
	}

	/* The exec event identifies the requested image, then the later fork
	 * proves the successful exec installed and inherited the new identity. */
	if (strcmp(oes_msg_string(&exec_event.msg,
	    exec_event.msg.em_process.ep_path_off), test_path) != 0) {
		fprintf(stderr,
		    "  FAIL: exec source process path was replaced by target path\n");
		errors++;
	}
	if (strcmp(oes_msg_string(&exec_event.msg,
	    exec_event.msg.em_event_data.exec.target.ep_path_off), exec_path) != 0 ||
	    strcmp(oes_msg_string(&exec_event.msg,
	    exec_event.msg.em_event_data.exec.executable.ef_path_off),
	    exec_path) != 0) {
		fprintf(stderr, "  FAIL: exec target/executable paths are incorrect\n");
		errors++;
	}
	if (strcmp(oes_msg_string(&fork_event.msg,
	    fork_event.msg.em_process.ep_path_off), exec_path) != 0 ||
	    strcmp(oes_msg_string(&fork_event.msg,
	    fork_event.msg.em_event_data.fork.child.ep_path_off), exec_path) != 0) {
		fprintf(stderr, "  FAIL: cached exec path was not inherited by fork\n");
		errors++;
	}
	if (fork_event.msg.em_process.ep_exec_id == 0 ||
	    fork_event.msg.em_event_data.fork.child.ep_exec_id !=
	    fork_event.msg.em_process.ep_exec_id ||
	    fork_event.msg.em_process.ep_exec_id ==
	    exec_event.msg.em_process.ep_exec_id) {
		fprintf(stderr, "  FAIL: execution ID replacement/inheritance mismatch\n");
		errors++;
	}

	if (errors == 0)
		printf("  PASS: process, thread, clock, file, and exec metadata\n");
	return (errors != 0);
}
