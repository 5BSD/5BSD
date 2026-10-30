/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef STORAGE_TEST_H
#define STORAGE_TEST_H
#include <stdint.h>
#define STORAGE_TEST_VERSION 10
#define STORAGE_TEST_CRASH 1u
#define STORAGE_TEST_SCOPES 4
#define STORAGE_RELEASE_OPERATIONS 3
#define STORAGE_TEST_CHALLENGE_SIZE 32
#define STORAGE_TEST_CREATED 1
#define STORAGE_TEST_RECOVERED 2
struct storage_test_request {
	uint32_t version;
	uint32_t flags;
	char challenge[STORAGE_TEST_CHALLENGE_SIZE];
};
#define STORAGE_NAMESPACE_OPERATIONS 4
struct storage_operation_result {
	int32_t result;
	int32_t error;
};
struct storage_test_result {
	int32_t line;
	int32_t error;
	uint32_t phase;
	uint32_t worker_management;
	struct storage_operation_result channel_fork;
	int32_t fork_read_result;
	int32_t fork_read_errno;
	int32_t fork_write_result;
	int32_t fork_write_errno;
	int32_t retained_read_result;
	int32_t retained_read_errno;
	int32_t retained_write_result;
	int32_t retained_write_errno;
	struct storage_operation_result fork_namespace[STORAGE_NAMESPACE_OPERATIONS];
	struct storage_operation_result clear_namespace[STORAGE_NAMESPACE_OPERATIONS];
	struct storage_operation_result release[STORAGE_TEST_SCOPES][STORAGE_RELEASE_OPERATIONS];
	uint32_t restart_recovered;
	struct storage_operation_result restart_read, restart_write;
};
#endif
