// Copyright (c) 2023-2026, Nubificus LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <assert.h>
#include <string.h>

#define main urunit_program_main
#include "../src/main.c"
#undef main

int setup_console(void) { return 0; }
int remount_root_rw(void) { return 0; }
char *get_boot_var(const char *name) { (void)name; return NULL; }
char *read_raw_device(int fd, size_t *size) { (void)fd; (void)size; return NULL; }
int configure_network(struct net_config *net) { (void)net; return 0; }
int mount_special_fs(void) { return 0; }
int mount_block_vols(struct block_config **vols) { (void)vols; return 0; }
int set_default_route(void) { return 0; }
void unmount_external(void) { }
int set_subreaper(void) { return 0; }
void request_reboot(void) { }

static void test_nul_separated_config(void) {
	char config[] =
		"UES\0"
		"FOO=line1\nUEE\nstill-data\0"
		"UEE\nstill-an-env\0"
		"PATH=/bin:/usr/bin\0"
		"UEE\0"
		"UCS\0"
		"UID:1000\0"
		"GID:1001\0"
		"WD:/work\nUCE\nstill-data\0"
		"ARC:2\0"
		"ARV:/bin/echo\0"
		"ARV:hello\nARV:still-data\0"
		"UCE\0"
		"UBS\0"
		"ID:vol0\0"
		"MP:/data\nUBE\nstill-data\0"
		"UBE\0"
		"UNS\0"
		"IP:192.0.2.2\0"
		"GW:192.0.2.1\0"
		"MSK:255.255.255.0\0"
		"UNE\0";
	char *cursor = config;
	char *path_env = NULL;
	char **envs = NULL;
	struct process_config *process = NULL;
	struct block_config **blocks = NULL;
	struct net_config *net = NULL;
	size_t remaining = sizeof(config) - 1;
	char *section = cursor;

	envs = parse_envs(&cursor, remaining, &path_env);
	assert(envs != NULL);
	assert(strcmp(envs[0], "FOO=line1\nUEE\nstill-data") == 0);
	assert(strcmp(envs[1], "UEE\nstill-an-env") == 0);
	assert(strcmp(envs[2], "PATH=/bin:/usr/bin") == 0);
	assert(envs[3] == NULL);
	assert(path_env == envs[2]);
	remaining -= (size_t)(cursor - section);

	section = cursor;
	process = parse_process_config(&cursor, remaining);
	assert(process != NULL);
	assert(process->uid == 1000);
	assert(process->gid == 1001);
	assert(strcmp(process->wdir, "/work\nUCE\nstill-data") == 0);
	assert(process->argc == 2);
	assert(strcmp(process->argv[1], "hello\nARV:still-data") == 0);
	remaining -= (size_t)(cursor - section);

	section = cursor;
	blocks = parse_block_config(&cursor, remaining);
	assert(blocks != NULL);
	assert(strcmp(blocks[0]->id, "vol0") == 0);
	assert(strcmp(blocks[0]->mountpoint, "/data\nUBE\nstill-data") == 0);
	assert(blocks[1] == NULL);
	remaining -= (size_t)(cursor - section);

	net = parse_net_config(&cursor, remaining);
	assert(net != NULL);
	assert(strcmp(net->ip, "192.0.2.2") == 0);
	assert(strcmp(net->gateway, "192.0.2.1") == 0);
	assert(strcmp(net->mask, "255.255.255.0") == 0);

	free(envs);
	free(process->argv);
	free(process);
	free(blocks[0]);
	free(blocks);
	free(net);
}

static void test_missing_nul_is_rejected(void) {
	char config[] = "UES\0FOO=bar\nUEE\0";
	char *cursor = config;
	char *path_env = NULL;

	assert(parse_envs(&cursor, sizeof(config) - 1, &path_env) == NULL);
	assert(cursor == config);
}

static void test_malformed_blocks_are_rejected(void) {
	char missing_id[] = "UBS\0MP:/data\0ID:vol0\0UBE\0";
	char empty_id[] = "UBS\0ID:\0MP:/data\0UBE\0";
	char unknown_field[] = "UBS\0XX:vol0\0MP:/data\0UBE\0";
	char *cursor = missing_id;

	assert(parse_block_config(&cursor, sizeof(missing_id) - 1) == NULL);
	cursor = empty_id;
	assert(parse_block_config(&cursor, sizeof(empty_id) - 1) == NULL);
	cursor = unknown_field;
	assert(parse_block_config(&cursor, sizeof(unknown_field) - 1) == NULL);
}

static void test_malformed_process_config_is_rejected(void) {
	char oversized_argc[] = "UCS\0UID:0\0GID:0\0WD:/\0ARC:4294967295\0UCE\0";
	char invalid_field[] = "UCS\0UID:0\0GIDevil:0\0WD:/\0UCE\0";
	char utf8_workdir[] = "UCS\0UID:0\0GID:0\0WD:/tmp/\xc3\xa9\0UCE\0";
	char *cursor = oversized_argc;
	struct process_config *process = NULL;

	assert(parse_process_config(&cursor, sizeof(oversized_argc) - 1) == NULL);
	cursor = invalid_field;
	assert(parse_process_config(&cursor, sizeof(invalid_field) - 1) == NULL);
	cursor = utf8_workdir;
	process = parse_process_config(&cursor, sizeof(utf8_workdir) - 1);
	assert(process != NULL);
	assert(strcmp(process->wdir, "/tmp/\xc3\xa9") == 0);
	free(process);
}

int main(void) {
	test_nul_separated_config();
	test_missing_nul_is_rejected();
	test_malformed_blocks_are_rejected();
	test_malformed_process_config_is_rejected();
	return 0;
}
