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

#ifndef COMMON_H 
#define COMMON_H 

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define SERIAL_MAX_SZ 10

#ifdef DEBUG
#define SHOW_DEBUG 1
#else
#define SHOW_DEBUG 0
#endif

#define DEBUG_PRINTF(fmt, ...) \
	do { if (SHOW_DEBUG) fprintf(stderr, "[DEBUG] " fmt, __VA_ARGS__); } while (0)

#define DEBUG_PRINT(fmt, ...) \
	do { if (SHOW_DEBUG) fprintf(stderr, "[DEBUG] " fmt); } while (0)

struct block_config {
	char *id;
	char *mountpoint;
};

int ensure_dir(const char *path);
int mkdir_all(const char *path, mode_t mode, char *first_dir);
int rm_empty_dirs(const char *dir, const char *top_dir);
char *skip_n_words(const char *str, size_t n);
int is_block_fs(const char *fs_type);
int is_network_fs(const char *fs_type);
int is_cloud_storage_fs(const char *fs_type);

int read_block_dev_serial(const char *device_name, char *serial, const size_t size);
int find_vblock_device_by_order(const uint32_t n, char *device_path);
int find_vblock_device_by_serial(const char *target_serial, char *device_path);
int mount_special_fs();
int mount_block_vols(struct block_config **vols);
int set_default_route();
void unmount_external();
int set_subreaper();
void request_reboot();
int open_power_button(void);

#endif // COMMON_H
