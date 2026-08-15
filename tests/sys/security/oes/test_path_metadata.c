/*
 * OES path metadata flags test.
 *
 * Verifies that helpers mark the correct object and aggregate message flags
 * for unavailable paths, and keep requested-path provenance distinct.
 */
#include <stdio.h>
#include <string.h>

#include <security/oes/oes.h>

static int
check_exec_flags(void)
{
	oes_message_t msg;

	memset(&msg, 0, sizeof(msg));
	oes_process_mark_path_unavailable(&msg, &msg.em_process);
	oes_process_mark_path_unavailable(&msg, &msg.em_event_data.exec.target);
	oes_file_mark_path_unavailable(&msg, &msg.em_event_data.exec.executable);

	if ((msg.em_flags & OES_MSG_FLAG_PATH_UNAVAILABLE) == 0) {
		printf("    FAIL: exec did not set message flag\n");
		return (1);
	}
	if ((msg.em_process.ep_meta_flags & OES_PROC_META_PATH_UNAVAILABLE) == 0) {
		printf("    FAIL: exec did not set process metadata flag\n");
		return (1);
	}
	if ((msg.em_event_data.exec.target.ep_meta_flags &
	    OES_PROC_META_PATH_UNAVAILABLE) == 0) {
		printf("    FAIL: exec target did not set process metadata flag\n");
		return (1);
	}
	if ((msg.em_event_data.exec.executable.ef_meta_flags &
	    OES_FILE_META_PATH_UNAVAILABLE) == 0) {
		printf("    FAIL: exec executable did not set file metadata flag\n");
		return (1);
	}

	return (0);
}

static int
check_requested_path_flag(void)
{
	oes_message_t msg;

	memset(&msg, 0, sizeof(msg));
	oes_file_mark_path_requested(&msg.em_event_data.create.file);

	if ((msg.em_event_data.create.file.ef_meta_flags &
	    OES_FILE_META_PATH_REQUESTED) == 0) {
		printf("    FAIL: requested path did not set file metadata flag\n");
		return (1);
	}
	if ((msg.em_event_data.create.file.ef_meta_flags &
	    OES_FILE_META_PATH_UNAVAILABLE) != 0) {
		printf("    FAIL: requested path incorrectly marked unavailable\n");
		return (1);
	}
	if ((msg.em_flags & OES_MSG_FLAG_PATH_UNAVAILABLE) != 0) {
		printf("    FAIL: requested path incorrectly set message flag\n");
		return (1);
	}

	oes_file_mark_path_unavailable(&msg, &msg.em_event_data.create.file);
	if ((msg.em_event_data.create.file.ef_meta_flags &
	    OES_FILE_META_PATH_REQUESTED) == 0) {
		printf("    FAIL: unavailable path cleared requested provenance\n");
		return (1);
	}
	if ((msg.em_event_data.create.file.ef_meta_flags &
	    OES_FILE_META_PATH_UNAVAILABLE) == 0) {
		printf("    FAIL: requested unavailable path did not set unavailable\n");
		return (1);
	}

	return (0);
}

static int
check_file_event_flags(void)
{
	oes_message_t msg;

	memset(&msg, 0, sizeof(msg));
	oes_file_mark_path_unavailable(&msg, &msg.em_event_data.create.file);
	oes_file_mark_path_unavailable(&msg, &msg.em_event_data.unlink.file);
	oes_file_mark_path_unavailable(&msg, &msg.em_event_data.rename.src_dir);
	oes_file_mark_path_unavailable(&msg, &msg.em_event_data.rename.src_file);

	if ((msg.em_event_data.create.file.ef_meta_flags &
	    OES_FILE_META_PATH_UNAVAILABLE) == 0) {
		printf("    FAIL: create file did not set file metadata flag\n");
		return (1);
	}
	if ((msg.em_event_data.unlink.file.ef_meta_flags &
	    OES_FILE_META_PATH_UNAVAILABLE) == 0) {
		printf("    FAIL: unlink file did not set file metadata flag\n");
		return (1);
	}
	if ((msg.em_event_data.rename.src_dir.ef_meta_flags &
	    OES_FILE_META_PATH_UNAVAILABLE) == 0) {
		printf("    FAIL: rename src_dir did not set file metadata flag\n");
		return (1);
	}
	if ((msg.em_event_data.rename.src_file.ef_meta_flags &
	    OES_FILE_META_PATH_UNAVAILABLE) == 0) {
		printf("    FAIL: rename src_file did not set file metadata flag\n");
		return (1);
	}
	if ((msg.em_flags & OES_MSG_FLAG_PATH_UNAVAILABLE) == 0) {
		printf("    FAIL: file events did not set message flag\n");
		return (1);
	}

	return (0);
}

int
main(void)
{
	int errors = 0;

	printf("Testing path metadata flags...\n");
	errors += check_exec_flags();
	errors += check_requested_path_flag();
	errors += check_file_event_flags();
	if (errors == 0)
		printf("    PASS: path metadata flags match helpers\n");
	return (errors != 0);
}
