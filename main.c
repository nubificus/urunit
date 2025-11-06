// Copyright (c) 2023-2025, Nubificus LTD
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

// Parts of the following code are taken from
// https://github.com/krallin/tini/tree/master
// which comes with the The MIT License (MIT)
// In particular:
// The MIT License (MIT)
//
// Copyright (c) 2015 Thomas Orozco <thomas@orozco.fr>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// For more information, please check https://github.com/krallin/tini/blob/master/LICENSE

#include <linux/reboot.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <linux/route.h>
#include <netinet/in.h>

#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

#define STATUS_MAX 255
#define STATUS_MIN 0
#define ETH0_IF "eth0"
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

struct process_config {
	uint32_t uid;
	uint32_t gid;
	char     *wdir;
};

struct block_config {
	char *id;
	char *mountpoint;
};

struct app_exec_config {
	char	 **envs;
	char	 *path_env;
	struct process_config *pr_conf;
	struct block_config **blk_conf;
};

extern char **environ;

int isolate_child(void) {
	int ret = 0;
	sigset_t set;

	ret = sigemptyset(&set);
	if (ret) {
		perror("sigemptyset");
		return 1;
	}
	ret = sigaddset(&set, SIGTTOU);
	if (ret) {
		perror("sigaddset");
		return 1;
	}
	ret = sigaddset(&set, SIGTTIN);
	if (ret) {
		perror("sigaddset");
		return 1;
	}
	ret = sigprocmask(SIG_BLOCK, &set, NULL);
	if (ret) {
		perror("sigprocmask");
		return 1;
	}

	// Put the child into a new process group.
	if (setpgid(0, 0) < 0) {
		perror("setpgid");
		return 1;
	}

	// If there is a tty, allocate it to this new process group. We
	// can do this in the child process because we're blocking
	// SIGTTIN / SIGTTOU.
	// Doing it in the child process avoids a race condition scenario
	// if urunit is calling urunit (in which case the grandparent may make the
	// parent the foreground process group, and the actual child ends up...
	// in the background!)
	if (tcsetpgrp(STDIN_FILENO, getpgrp())) {
		if (errno != ENOTTY && errno != ENXIO) {
			perror("tcsetpgrp");
			return 1;
		}
	}

	return 0;
}

// ensure_dir: Makes sure a directory exists and if not it creates it.
//
// Arguments:
// 1. path:	The directory to check and create if does not exist
//
// Return value:
// It returns 0 in success. Otherwise it returns 1.
int ensure_dir(const char *path) {
	struct stat st;
	int ret = 0;

	// Check if the path exists
	ret = stat(path, &st);
	if (ret == 0) {
		if (S_ISDIR(st.st_mode)) {
			DEBUG_PRINTF("Directory %s already exists.\n", path);
			return 0;
		}
		fprintf(stderr, "'%s' exists but is not a directory.\n", path);
		return -1;
	}

	// Since it does not exist create it.
	ret = mkdir(path, 0555);
	if (ret != 0) {
		perror("mkdir");
		return -1;
	}
	DEBUG_PRINTF("Created directory %s\n", path);

	return 0;
}

// mount_special_fs: Mounts the special filesystems procfs and sysfs in /proc and
// /sys respectively.
//
// Arguments:
// No arguments.
//
// Return value:
// It returns 0 in success. Otherwise it returns 1.
int mount_special_fs() {
	int ret = 0;

	ret = ensure_dir("/proc");
	if (ret < 0) {
		return 1;
	}
	ret = mount("proc", "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
	if (ret < 0) {
		perror("mount /proc");
		return 1;
	}

	ret = ensure_dir("/sys");
	if (ret < 0) {
		return 1;
	}
	ret = mount("sysfs", "/sys", "sysfs", 0, NULL);
	if (ret < 0) {
		perror("mount /sys");
		return 1;
	}

	return 0;
}

// read_exact_size: Reads exactly sz bytes from a file. It returns a
// dynamically allocated memory and the caller is responsible to free it.
//
// Arguments:
// 1. f:	The pointer to a FILE
// 2. sz:	The amount of bytes to read
//
// Return value:
// On success it returns a buffer of sz size with all bytes read.
// On failure, it returns NULL.
char *read_exact_size(FILE *f, size_t sz) {
	size_t total_read = 0;
	size_t bytes_read = 0;
	char *buffer = NULL;

	buffer = malloc(sz);
	if (!buffer) {
		fprintf(stderr, "Failed to allocate memory for file contents\n");
		return NULL;
	}

	while (total_read < sz) {
		bytes_read = fread(buffer + total_read, 1, sz - total_read, f);
		// the retrun value of fread does not distinguish between EOF and
		// an error. Therefore, we have to use feof and ferror.
		if (bytes_read == 0) {
			if (feof(f)) {
				// No more bytes to read.
				break;
			} else if (ferror(f)) {
				fprintf(stderr, "Failed to read file data at offset %zu\n", total_read);
				goto read_exact_error;
			}
		}
		total_read += bytes_read;
	}

	// We are out of the loop so we read as much bytes the caller asked
	// or we reached the EOF. Check which of the two happened.
	if (total_read != sz) {
		fprintf(stderr, "Read %zu bytes, expected %zu bytes\n", total_read, sz);
		goto read_exact_error;
	}

	return buffer;

read_exact_error:
	free(buffer);
	return NULL;
}

// read_file_and_size: Reads the file <file> from arguments and returns buffer
// with all the contents of the file. Furthermore, it stores in the size argument
// the total size of the file.
//
// Arguments:
// 1. file:	The file to read
// 2. size:	The total size of the file
//
// Return value:
// On success it returns a buffer with all the contents of the file and updates the
// size argument to contain the total size of the file.
// On failure, it returns NULL.
char *read_file_and_size(char *file, size_t *size) {
	FILE *fp = NULL;
	struct stat st = { 0 };
	int ret = 0;
	char *buf = NULL;

	DEBUG_PRINTF("Read configuration file %s\n", file);
	fp = fopen(file, "rb");
	if (!fp) {
		perror("Read configuration file");
		return NULL;
	}

	// Find the total size of the file in order to read the whole file
	// and have a limit to search in the buffer.
	ret = fstat(fileno(fp), &st);
	if (ret != 0) {
		perror("Getting configuration file size");
		goto exit_read_file;
	}
	DEBUG_PRINTF("Total size of configuration file %ld\n", st.st_size);

	// Make sure to read the whole file in one buffer.
	buf = read_exact_size(fp, st.st_size);
	if (!buf) {
		fprintf(stderr, "Could not read whole configuration file\n");
		goto exit_read_file;
	}
	DEBUG_PRINTF("Contents of configuration file\n%s\n", buf);
	*size = st.st_size;

exit_read_file:
	fclose(fp);
	return buf;
}

// measure_tokens: Measures how many tokens found in a string, searching at most
// max_size bytes.
//
// Arguments:
// 1. str_buf:	The string to search at
// 2. max_size:	The max size of bytes to llok at the string
// 3. tok:	The character to search for.
//
// Return value:
// It returns the number of times the character was found.
size_t measure_tokens(char *str_buf, size_t max_size, char tok) {
	size_t i = 0;
	size_t cnt = 0;

	// Keep searching till we reach the max_size or
	// the end of string '\0'
	while (i < max_size && str_buf[i] != 0) {
		if (str_buf[i] == tok) {
			cnt++;
		}
		i++;
	}

	return cnt;
}

// parse_envs: Parses a list with one string in every line. The list should begin
// with the special string "UES" and each line should contain an environment
// variable. The last line in the list should be the special string "UEE"
// Given such a list, it constructs an array of pointers to strings where each
// pointer points to a single environment variable. The array is properly
// formatted to be passed as the environment variables table at execve and friends.
// It is important to note, that this function will alter the given list,
// replacing the new line characters with the end of string '\0' character.
// The funtion returns a dynamically allocated memory for storing the environment
// variables array and the caller is responsible to free that memory.
//
// Arguments:
// 1. string_area:	The list with in the aformentioned format. If this function
//			returns successfully, then this pointer will move after the end
//			of the environment variable list, passed the end of The
//			"UEE" string.
// 2. max_sz:		The max possible size of the list.
// 3. path_env:		A pointer to a string where a pointer to the PATH environment
//			variable will get stored (if it is found).
//
// Return value:
// It returns an array of strings, where each row points
// to a single environment variable inside the initial list.
// Also, if the environment variable PATH was found, then path_env
// will point to the beginning of that string inside the list.
char **parse_envs(char **string_area, size_t max_sz, char **path_env) {
	size_t total_envs = 0;
	// TODO: We might need to retrun a list here with the first
	// element being NULL instead of returning NULL
	char **env_vars = NULL;
	uint8_t path_found = 0;
	char *tmp_env = NULL;
	size_t i = 0;

	// Search how many new line characters we have in the list.
	total_envs = measure_tokens(*string_area, max_sz, '\n');
	DEBUG_PRINTF("Found %ld total lines in the environment variables list\n", total_envs);

	// The list starts with "UES"
	// which will not be stored and therefore, we can use this extra
	// pointer for the end of the table (NULL), as execve and friends require.
	// NOTE: If the list contains "UEE", we allocate one more pointer that
	// is never used.
	env_vars = malloc(total_envs * sizeof(char *));
	if (!env_vars) {
		fprintf(stderr, "Failed to allocate memory for environment variables\n");
		return NULL;
	}

	tmp_env = strtok(*string_area, "\n");
	// Discard the first string since it is the special string "UES"
	// Also, it is safe to call strtok, even if there was no '\n', since it will
	// return NULL again.
	tmp_env = strtok(NULL, "\n");
	while (tmp_env && i < total_envs) {
		// Check if we reached the end of the environment variable list
		if (memcmp(tmp_env, "UEE", 3) == 0) {
			*string_area = tmp_env + 4; // 4 bytes for the "UEE" string
			break;
		}
		// Store the environment variable
		DEBUG_PRINTF("Found env %s\n", tmp_env);
		env_vars[i] = tmp_env;
		// If we have not found PATH yet,
		// check if the current environment variable is PATH.
		if (!path_found) {
			if (memcmp(tmp_env, "PATH=", 5) == 0) {
				DEBUG_PRINTF("Found PATH env %s\n", tmp_env);
				*path_env = tmp_env;
				path_found = 1;
			}
		}
		i++;
		tmp_env = strtok(NULL, "\n");
	}
	// Special case where malloc did not return NULL with 0 size,
	// or no strings with '\n' found after the first occurance of '\n'.
	// Both cases mean that we have no environment variables and hence
	// we should return NULL.
	if (i == 0) {
		// free is safe here, since env_vars come from malloc and
		// contains either NULL or address. Both cases are fine for free.
		free(env_vars);
		return NULL;
	}
	// Add NULL to indicate the end of the table with environment variables.
	env_vars[i] = NULL;

	return env_vars;
}

// get_uint_val: Converst the value of "KEY: VALUE" string  to uint32_t
//
// Arguments:
// 1. str:	The string to convert in the form "KEY: VAL"
// 2. value:	A pointer to uint32_t where the converted value will get stored.
//
// Return value:
// On success 0 is returned and value contains the coverted value.
// On failure, -1 is returned and value stays intact.
int get_uint_val(char *str, uint32_t *value) {
	size_t str_sz = strlen(str);
	char *val_str = strchr(str, ':');
	unsigned long val = 0;
	char *end = NULL;

	if (val_str == NULL) {
		// We could not find the beginning of the value string.
		fprintf(stderr, "Failed to find ':' character in %s\n", str);
		return -1;
	}

	// strchr will return a pointer to ':', but we need to move passed
	// ':', hence +1 character.
	if (val_str + 1 >= str + str_sz) {
		// We can not go over the string. Something is wrong
		fprintf(stderr, "Failed to find value after ':' in %s\n", str);
		return -1;
	}
	val_str ++;

	// strtoul can take care of spaces.
	val = strtoul(val_str, &end, 10);
	if (errno == ERANGE || val > UINT32_MAX) {
		perror("Convert string to uint32_t");
		return -1;
	}
	if (*end != '\0') {
		fprintf(stderr, "Failed to convert %s to unit32_t. Got trailing character %c\n", val_str, *end);
		return -1;
	}

	*value = (uint32_t)val;

	return 0;
}

// get_string_val: Returns the string value of "KEY: VALUE" strings.
//
// Arguments:
// 1. str:	The whole string in the form "KEY: VALUE"
// 2. value:	A pointer which will point to the beginning of the VALUE
//
// Return value:
// On success 0 is returned and value points to the beginning of VALUE
// On failure, -1 is returned and value stays intact.
int get_string_val(char *str, char **value) {
	size_t str_sz = strlen(str);
	char *val_str = strchr(str, ':');

	if (val_str == NULL) {
		// We could not find the beginning of the value string.
		fprintf(stderr, "Failed to find ':' character in %s\n", str);
		return -1;
	}

	// strchr will return a pointer to ':', but we need to move pass this character
	// and until we find a non-space value.
	val_str++;
	while ((val_str < str + str_sz) && *val_str != '\0') {
		if (!isspace(*val_str)) {
			*value = val_str;

			return 0;
		}
		val_str++;
	}

	// We can not go over the string. Something is wrong
	fprintf(stderr, "Failed to find value after ':' in %s\n", str);

	return -1;
}

// parse_process_config: Parses a list with the following format:
// UCS
// UID:<uid>
// GID:<gid>
// WD:<working directory>
// UCE
// It is important to note, that this function will alter the given list,
// replacing the new line characters with the end of string '\0' character.
// The funtion returns a dynamically allocated memory and the caller is
// responsible to free that memory.
//
// Arguments:
// 1. string_area:	The list with in the aformentioned format.
// 2. max_sz:		The max possible size of the list.
//
// Return value:
// On success it returns a pointer to a dynamically allocated memory that
// contains a process_config struct filled with the information
// from the configuration.
// Otherwise, NULL is returned
struct process_config *parse_process_config(char **string_area, size_t max_sz) {
	struct process_config *conf = NULL;
	char *tmp_field = NULL;

	conf = malloc(sizeof(struct process_config));
	if (!conf) {
		fprintf(stderr, "Failed to allocate memory for app execution environment config\n");
		return NULL;
	}
	memset(conf, 0, sizeof(struct process_config));
	conf->wdir = NULL; // Sanity

	tmp_field = strtok(*string_area, "\n");
	// Discard the first string since it is the special string "UCS"
	// Also, it is safe to call strtok, even if there was no '\n', since it will
	// return NULL again.
	tmp_field = strtok(NULL, "\n");
	while (tmp_field && ((size_t)(tmp_field - *string_area) < max_sz)) {
		int ret = 0;

		if (memcmp(tmp_field, "UID", 3) == 0) {
			ret = get_uint_val(tmp_field, &(conf->uid));
			if (ret != 0) {
				fprintf(stderr, "Failed to retreive UID information from %s\n", tmp_field);
				break;
			}
		} else 	if (memcmp(tmp_field, "GID", 3) == 0) {
			ret = get_uint_val(tmp_field, &(conf->gid));
			if (ret != 0) {
				fprintf(stderr, "Failed to retreive GID information from %s\n", tmp_field);
				break;
			}
		} else 	if (memcmp(tmp_field, "WD", 2) == 0) {
			ret = get_string_val(tmp_field, &(conf->wdir));
			if (ret != 0) {
				fprintf(stderr, "Failed to retreive WD information from %s\n", tmp_field);
				break;
			}
		} else 	if (memcmp(tmp_field, "UCE", 3) == 0) {
			*string_area = tmp_field + 4; // 4 bytes for the "UCE" string
			return conf;
		}

		tmp_field = strtok(NULL, "\n");
	}

	free(conf);
	return NULL;
}

// parse_block_config Parses a list with the following format:
// UBS
// ID: <serial_id>
// MP: <mount_point>
// ...
// UBE
// It is important to note, that this function will alter the given list,
// replacing the new line characters with the end of string '\0' character.
// The funtion returns a dynamically allocated memory and the caller is
// responsible to free that memory.
//
// Arguments:
// 1. string_area:	The list with the aformentioned format.
// 2. max_sz:		The maximum size of the area to look for block config
//
// Return value:
// On success it returns an array of block_config structs filled with the information
// from the list.
// Otherwise, NULL is returned
struct block_config **parse_block_config(char **string_area, size_t max_sz) {
	// TODO: We might need to retrun a list here with the first
	// element being NULL instead of returning NULL
	struct block_config **bentries = NULL;
	char *tmp_field = NULL;
	size_t i = 0;
	size_t total_entries = 0;

	// Count the new line characters we have in the list.
	// Since every block entry consist of 2 fields, the total number
	// of entries derives from diving the number of new lines by 2.
	total_entries = measure_tokens(*string_area, max_sz, '\n') / 2;
	// If the list is correctly formatted it will start with "UBS"
	// and end with "UBE". These special strings will not be stored,
	// but they add up in the overall size, since they occupy one line each.
	// However, we can use this extra entry in the array to mark the end of
	// the array with NULL.
	bentries = malloc(total_entries * sizeof(struct block_config *));
	if (!bentries) {
		fprintf(stderr, "Failed to allocate memory for block entries\n");
		return NULL;
	}
	if (total_entries > 0)
		bentries[0] = NULL;
	DEBUG_PRINTF("Found %ld block entries\n", total_entries);

	tmp_field = strtok(*string_area, "\n");
	// Discard the first string since it is the special string "UBS"
	// Also, it is safe to call strtok, even if there was no '\n', since it will
	// return NULL again.
	tmp_field = strtok(NULL, "\n");
	while (tmp_field && i < total_entries) {
		int ret = 0;

		// The first string should be "ID:"
		if (memcmp(tmp_field, "ID:", 3) == 0) {
			// If bentries[i] is not NULL then we never reached found
			// MP entry in the config for this ID.
			if (bentries[i]) {
				fprintf(stderr, "Multiple ID entries without MP\n");
				goto parse_block_config_free;
			}
			bentries[i] = malloc(sizeof(struct block_config));
			if (!bentries[i]) {
				fprintf(stderr, "Failed to allocate memory for a block entry\n");
				goto parse_block_config_free;
			}
			bentries[i]->id = NULL;
			bentries[i]->mountpoint = NULL;

			ret = get_string_val(tmp_field, &(bentries[i]->id));
			if (ret != 0) {
				fprintf(stderr, "Failed to retrieve block ID from %s\n", tmp_field);
				free(bentries[i]);
				goto parse_block_config_free;
			}
			DEBUG_PRINTF("Found block entry with ID %s\n", bentries[i]->id);
		} else if (memcmp(tmp_field, "MP:", 3) == 0) {
			ret = get_string_val(tmp_field, &(bentries[i]->mountpoint));
			if (ret != 0) {
				fprintf(stderr, "Failed to retrieve block mountpoint from %s\n", tmp_field);
				// Remove the current entry
				// because it was not properly formatted.
				free(bentries[i]);
				goto parse_block_config_free;
			}
			DEBUG_PRINTF("Found block entry with MP %s\n", bentries[i]->mountpoint);
			i++;
			bentries[i] = NULL;
		} else 	if (memcmp(tmp_field, "UBE", 3) == 0) {
			// 4 bytes for the "UBE" string
			*string_area = tmp_field + 4;
			break;
		}
		tmp_field = strtok(NULL, "\n");
	}

	// Special case where malloc did not return NULL with 0 size,
	// or none properly formatted block entries were found
	// Both cases mean that we have no block entries and hence
	// we should return NULL.
	if (i == 0) {
		// free is safe here, since bentries come from malloc and
		// contains either NULL or an address. Both cases are fine for free.
		free(bentries);
		return NULL;
	}
	// In case of a malformed block config where we had an ID but no MP,
	// then mountpoint will be NULL and we should free the allocated entry.
	if (bentries[i] && !(bentries[i]->mountpoint)) {
		free(bentries[i]);
	}
	// Add NULL to indicate the end of the table with block entries
	bentries[i] = NULL;

	return bentries;

parse_block_config_free:
	for (size_t j = 0; j < i; j++) {
		free(bentries[j]);
	}
	free(bentries);

	return NULL;
}

// get_config_from_file: Reads the contents of <file> argumen and it parses the 
// app execution configuration and environment variables list.
// The app execution configuration list starts with the line "UCS" and ends with the
// line "UCE". Respectively, the environment variable list, starts with the "UES" line
// and ends with the line "UES".
//
// Arguments:
// 1. file:	The name of the file that contains the configuration.
// 2. sbuf:	The variable that will hold the address of the allocated memory
//		that was used to read the configuration file. The caller is
//		responsible to free it.
//
// Return value:
// On success it returns a pointer to an instance of a struct app_exec_config
// ehich contains all the respective information for setting app the execution
// environment of the application.
struct app_exec_config *get_config_from_file(char *file, char **sbuf) {
	char **env_vars = NULL;
	size_t size = 0;
	char *buf = NULL;
	char *path_env = NULL;
	struct app_exec_config *econf = NULL;
	struct process_config *pconf = NULL;
	struct block_config **bconf = NULL;
	char *conf_area = NULL;

	buf = read_file_and_size(file, &size);
	if (!buf) {
		fprintf(stderr, "Could not read file %s\n", file);
		return NULL;
	}
	conf_area = buf;

	DEBUG_PRINT("Checking for environment variables list\n");
	// Check if the special string "UES" is present
	// which means that now starts the environment variable
	// list.
	if (memcmp(conf_area, "UES", 3) == 0) {
		char *init_conf_area = conf_area;
		// Extract the environment variables from the list
		env_vars = parse_envs(&conf_area, size, &path_env);
		if (!env_vars ) {
			fprintf(stderr, "Warning: No environment variables found in the configuration\n");
		}
		// If the list was properly formatted, ending with "UEE"
		// then string_area should differ from init_string_area
		// Otherwise, the list was not properly formatted and
		// we abort the parsing.
		if (conf_area == init_conf_area) {
			fprintf(stderr, "Invalid format of environment variable list. \"UEE\" was not found\n");
			goto get_env_vars_error_free;
		}
		// Reduce the size of the config by the bytes parsed
		// for the environment variables list.
		size -= conf_area - init_conf_area;
	}

	DEBUG_PRINT("Checking for execution environment configuration\n");
	// Check if the special string "UCS" is present
	// which means that now starts the configuration for the application
	// execution environment
	if (memcmp(conf_area, "UCS", 3) == 0) {
		char *init_conf_area = conf_area;
		// Extract the environment variables from the list
		pconf = parse_process_config(&conf_area, size);
		if (!pconf ) {
			fprintf(stderr, "Warning: No configuration for the application execution environment was found\n");
		}
		// If the list was properly formatted, ending with "UCE"
		// then string_area should differ from init_string_area
		// Otherwise, the list was not properly formatted and
		// we abort the parsing.
		if (conf_area == init_conf_area) {
			fprintf(stderr, "Invalid format of application execution environment configuration\n");
			goto get_env_vars_error_free;
		}
		// Reduce the size of the config by the bytes parsed
		// for the environment variables list.
		size -= conf_area - init_conf_area;
	}

	DEBUG_PRINT("Checking for block volumes mount configuration\n");
	// Check if the special string "UBS" is present
	// which means that now starts the configuration for the block mounts
	if (memcmp(conf_area, "UBS", 3) == 0) {
		char *init_conf_area = conf_area;
		// Extract the block configuration
		bconf = parse_block_config(&conf_area, size);
		if (!bconf ) {
			fprintf(stderr, "Warning: No configuration for block mounts\n");
		}
		// If the list was properly formatted, ending with "UBE"
		// then conf_area should differ from init_conf_area
		// Otherwise, the list was not properly formatted and
		// we abort the parsing.
		if (conf_area == init_conf_area) {
			fprintf(stderr, "Invalid format of block volume mounts\n");
			goto get_env_vars_error_free;
		}
		size -= conf_area - init_conf_area;
	}

	econf = malloc(sizeof(struct app_exec_config));
	if (!econf) {
		fprintf(stderr, "Could not allocate memory for app exec config struct\n");
		goto get_env_vars_error_free;
	}

	*sbuf = buf;
	econf->envs = env_vars;
	econf->path_env = path_env;
	econf->pr_conf = pconf;
	econf->blk_conf = bconf;
	return econf;

get_env_vars_error_free:
	free(buf);
	return NULL;
}

// manual_execvpe: Tries to implement in a simple way execvpe, since execvpe is
// only supported by glibc. The rational is to combine every path in env_path
// (which is the PATH) with the file_bin (the executable) and try to execve.
// If a combination does not succeed then we move to the next path in env_path
//
// Arguments:
// 1. env_path:	A string containing the PATH environment variable with all possible
//		directories to search for the executable.
// 2. file_bin:	The basename of the executable.
// 3. argv:	The arguments for the application.
// 4. env:	The environment variables for the application.
//
// Return value:
// On success it will never return. Otherwise, a non-zero return value
// will get returned and errno will be set appropriately.
int manual_execvpe(const char *env_path, const char *file_bin, char *const argv[], char *const env[]) {
	int status = 1;
	char *path_buf = NULL;
	const char *cur_path_end = NULL;
	const char *cur_path_start = NULL;
	char *tmp_bin_path = NULL;
	size_t env_path_len = 0;
	size_t file_bin_len = 0;

	if (!env) {
		DEBUG_PRINT("No environment variables were set, just execvp and use the current ones\n");
		// No environment variables were given. So, we can just
		// use execvp.
		execvp(file_bin, argv);
		goto manual_exec_exit;
	}

	if (*file_bin == '/' || env_path == NULL) {
		DEBUG_PRINT("Binary has full path, therefore just execvp it\n");
		// The file to execute is an absolute path.
		// Or there is no custom PATH to search for.
		// Therefore, just try to execve the given file
		execve(file_bin, argv, env);
		goto manual_exec_exit;
	}

	file_bin_len = strlen(file_bin);
	env_path_len = strlen(env_path);
	if (env_path_len <= 5) {
		fprintf(stderr, "Invalid format of custom PATH environment variable");
		goto manual_exec_exit;
	}
	// Move past "PATH+" and get to its values
	env_path += 5;
	env_path_len -= 5;

	// Allocate memory for the temporary buffer where we will construct
	// all combinations. The size should be:
	// env_path_len + '/' +file_bin_len + '\0'
	path_buf = malloc((env_path_len + file_bin_len + 2) * sizeof(char));
	if (!path_buf) {
		fprintf(stderr, "Failed to allocate memory to search binary\n");
		return 1;
	}

	// Store the basename of the executable in the end of the buffer
	// and prepend the '/' character to prepare a concatination of a
	// path from custom PATH and the basename of the executable
	// This will reduce the copies, since we only change the directory
	// that we try out each time.
	tmp_bin_path = path_buf + env_path_len;
	*(tmp_bin_path) = '/';
	memcpy(tmp_bin_path + 1, file_bin, file_bin_len);
	*(tmp_bin_path + 1 + file_bin_len) = '\0';

	// cur_path_start stores the beginning of the current path we try from custom PATH
	cur_path_start = env_path;

	do {
		char *path_attempt = NULL;
		size_t tmp_path_size = 0;

		// cur_path_end stores the end of the current path we try from custom PATH
		cur_path_end = strchr(cur_path_start, ':');
		if (!cur_path_end) {
			// We reached the last path, but strchr return NULL,
			// since the character was not found. Therefore,
			// manually set the pointer to the end of the string.
			cur_path_end = env_path + env_path_len;
		}
		tmp_path_size = cur_path_end - cur_path_start;

		// We copy right before the '/' character the current directory
		// from custom PATH
		path_attempt = (char *)memcpy(tmp_bin_path - tmp_path_size,
						cur_path_start,
						tmp_path_size);

		DEBUG_PRINTF("Trying %s\n", path_attempt);
		execve(path_attempt, argv, env);

		// Execve failed, but check the reason
		switch (errno) {
		case EACCES:
			// Permission denied and therefore, we can not execute
			// the file we found. Try the next possible path.
			//
			// TODO: However, we might want to keep this error
			// and report it if everything else fails, because the
			// error will get overwritten from the last failure.
		case ENOENT:
		case ENOTDIR:
			// The file or a directory in the path does not exist.
			// Just move to the next possible path.
			break;
		default:
			// For any other reason, just abort.
			goto manual_exec_exit_free;
		}

		// Discard the ':' character
		cur_path_start = cur_path_end + 1;

	} while (cur_path_start < (env_path + env_path_len));

	// We could not execute the binary.
manual_exec_exit_free:
	free(path_buf);
manual_exec_exit:
	// execvp/execve will only return on an error so make sure that we check
	// the errno and exit with the correct return status for the error 
	// that we encountered.
	// See: http://www.tldp.org/LDP/abs/html/exitcodes.html#EXITCODESREF
	switch (errno) {
	case ENOENT:
		status = 127;
		break;
	case EACCES:
		status = 126;
		break;
	}
	// Just a trick to print the filename in the error.
	fprintf(stderr, "exec %s ", file_bin);
	perror("failed");

	return status;
}

// setup_exec_env: Sets up the process execution environment as defined by
// the process_conf argument.
//
// Arguments:
// 1. process_conf:	The config to apply with uid/gid and CWD.
//
// Return value:
// On success 0 is returned.
// Otherwise 1 is returned.
int setup_exec_env(struct process_config *process_conf) {
	int ret = 0;

	if (!process_conf) {
		DEBUG_PRINT("Empty config, nothing to be done\n");
		return 0;
	}

	DEBUG_PRINTF("Setting gid to %d\n", process_conf->gid);
	ret = setgid(process_conf->gid);
	if (ret < 0) {
		perror("set GID");
		return 1;
	}

	DEBUG_PRINTF("Setting uid to %d\n", process_conf->uid);
	ret = setuid(process_conf->uid);
	if (ret < 0) {
		// No need for reverting gid, since we will exit.
		perror("set UID");
		return 1;
	}

	DEBUG_PRINTF("Switching to directory %s\n", process_conf->wdir);
	ret = chdir(process_conf->wdir);
	if (ret < 0) {
		// No need for reverting gid/uid, since we will exit.
		perror("set CWD");
		return 1;
	}

	return 0;
}

// rm_empty_dirs: Removes the directory dir given as argument and all empty parent
// directories up to and including top_dir.
//
// Arguments:
// 1. dir:	The directory to remove. 
// 2. top_dir:	The top-most directory to remove. It should not end in '/'
//
// Return value:
// On success 0 is returned.
// Otherwise -1 is returned.
int rm_empty_dirs(const char *dir, const char *top_dir) {
	char current[PATH_MAX] = { 0 };
	int ret = 0;

	ret = snprintf(current, sizeof(current), "%s", dir);
	if (ret <= 0 || (size_t)ret > sizeof(current)) {
		fprintf(stderr, "Could not copy %s\n", dir);
		return -1;
	}
	// Make sure the path does not end in '/'
	if (current[ret - 1] == '/') {
		current[ret - 1] = '\0';
	}

	DEBUG_PRINTF("Top most directory to remove: %s\n", top_dir);
	while (strcmp(current, top_dir) != 0) {
		char *last_slash = NULL;

		// Stop at root or common mount points
		if (strcmp(current, "/") == 0 ||
		    strcmp(current, "/mnt") == 0 ||
		    strcmp(current, "/var") == 0 ||
		    strcmp(current, "/home") == 0 ||
		    strcmp(current, "/tmp") == 0) {
			break;
		}

		DEBUG_PRINTF("Trying to remove directory: %s\n", current);
		ret = rmdir(current);
		if (ret != 0) {
			perror("rmdir");
			return -1;
		}
		DEBUG_PRINTF("Removed empty directory: %s\n", current);

		// Get parent directory
		last_slash = strrchr(current, '/');
		if (!last_slash || last_slash == current) {
			fprintf(stderr, "Could not get parent directory of %s\n", current);
			return -1;
		}
		*last_slash = '\0';
	}

	DEBUG_PRINTF("Trying to remove directory: %s\n", current);
	// Remove also top most directory
	ret = rmdir(current);
	if (ret != 0) {
		perror("rmdir");
		return -1;
	}
	DEBUG_PRINTF("Removed empty directory: %s\n", current);

	return 0;
}

// mkdir_all: Creates a directory path including all non-existing parent directories.
// Similar to MkdirAll in Go and "mkdir -p" command.
//
// Arguments:
// 1. path:	The full path of the directory to create
// 2. mode:	The permissions mode for the new directories
//
// Return value:
// On success 0 is returned.
// Otherwise -1 is returned.
int mkdir_all(const char *path, mode_t mode, char *first_dir) {
	char tmp_path[PATH_MAX] = { 0 };
	char *next_slash = NULL;
	int ret = 0;
	struct stat st;
	uint8_t is_first = 1;
	size_t or_path_len = 0;
	size_t tmp_len = 0;

	if (path == NULL || *path == '\0') {
		fprintf(stderr, "Invalid path value\n");
		return -1;
	}

	if (strcmp(path, "/") == 0) {
		fprintf(stderr, "Invalid path value: %s\n", path);
		return -1;
	}

	// Check if path already exists
	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode)) {
			return 0;
		} else {
			fprintf(stderr, "%s exists and is not a directory\n", path);
			return -1;
		}
	}

	ret = snprintf(tmp_path, sizeof(tmp_path), "%s", path);
	if (ret <= 0 || (size_t)ret > sizeof(tmp_path)) {
		fprintf(stderr, "Could not create a copy of %s\n", path);
		return -1;
	}

	or_path_len = strlen(tmp_path);
	tmp_len = or_path_len;
	// Remove trailing slashes
	while (tmp_len > 1 && tmp_path[tmp_len - 1] == '/') {
		tmp_path[tmp_len - 1] = '\0';
		tmp_len--;
	}
	// We will need to copy tmp_path later so we need to include
	// the end of string character.
	or_path_len++;

	// Iterate through the path and create directories
	next_slash = strchr(tmp_path + 1, '/');
	while(next_slash) {
		*next_slash = '\0'; // Temporarily truncate

		// Try to create the directory
		DEBUG_PRINTF("Trying to create dir %s\n", tmp_path);
		ret = mkdir(tmp_path, mode);
		if (ret != 0 && errno != EEXIST) {
			fprintf(stderr, "Could not create directory %s\n", tmp_path);
			perror("mkdir");
			ret = -1;
			goto mkdir_all_cleanup;
		}
		if (ret == 0 && is_first) {
			ret = snprintf(first_dir, or_path_len, "%s", tmp_path);
			if (ret < 0 || (size_t)ret > or_path_len) {
				fprintf(stderr, "Could not copy first created path %s", tmp_path);
				return -1;
			}
			is_first = 0;
		}
		*next_slash = '/'; // Restore the slash
		next_slash = strchr(next_slash + 1, '/');
	}

	// Create the final directory
	DEBUG_PRINTF("Trying to create dir %s\n", tmp_path);
	ret = mkdir(tmp_path, mode);
	if (ret != 0 && errno != EEXIST) {
		fprintf(stderr, "Could not create directory %s\n", tmp_path);
		perror("mkdir");
		ret = -1;
		goto mkdir_all_cleanup;
	}
	if (ret == 0 && is_first) {
		ret = snprintf(first_dir, or_path_len, "%s", tmp_path);
		if (ret < 0 || (size_t)ret > or_path_len) {
			fprintf(stderr, "Could not copy first created directory %s\n", tmp_path);
			return -1;
		}
	}
	DEBUG_PRINTF("Top most created dir %s\n", first_dir);
	return 0;

mkdir_all_cleanup:
	// If we have not created any directory yet then is_first will be 1
	// and hence we do not have to remove any directory.
	if (!is_first) {
		int ret = 0;
		// However, the fail took place for the tmp_path directory
		// which was not created and hence we do not have to remove it.
		// Therefore, move to the parent directory.
		char *last_slash = strrchr(tmp_path, '/');
		if (!last_slash || last_slash == tmp_path) {
			fprintf(stderr, "Could not get parent directory of %s\n", tmp_path);
			return ret;
		}
		*last_slash = '\0';
		ret = rm_empty_dirs(tmp_path, first_dir);
		if (ret != 0) {
			fprintf(stderr, "Could not remove directories between %s and %s",first_dir, tmp_path );
		}
	}
	// creation of subdir failed
	return ret;
}

// read_block_dev_serial: Read the serial ID of a block device from the respective sysfs
// entry.
//
// Arguments:
// 1. device_name:	The device name
// 2. serial:		The buffer to hold the serial ID that was found
// 2. size:		The max size of the buffer
//
// Return value:
// If the device exists, then 0 is returned.
// If the deivce doe snot exist 1 is returned.
// In all other cases or errors -1 is returned.
int read_block_dev_serial(const char *device_name, char *serial, const size_t size) {
	char path[PATH_MAX];
	FILE *fp;
	int ret = 0;

	ret = snprintf(path, sizeof(path), "/sys/block/%s/serial", device_name);
	if (ret < 0 || (size_t)ret > sizeof(path)) {
		fprintf(stderr, "Could not create sysfs path for %s\n", device_name);
		return -1;
	}

	fp = fopen(path, "r");
	if (!fp) {
		if (errno == ENOENT) {
			return 1;
		}
		perror("fopen");
		return -1;
	}

	if (fgets(serial, size, fp) == NULL) {
		fclose(fp);
		return -1;
	}

	// Remove trailing whitespace
	serial[strcspn(serial, "\n\r \t")] = '\0';
	fclose(fp);
	return 0;
}

// find_vblock_device_by_order: Returns the nth virtio block device (vd*) if it
// exists. The order is based on the conventional naming of virtio block devices
// in Linux where usually the first attached is vda, second vdb etc.
//
// Arguments:
// 1. n:		The order of the virtio blockd evice to retrun.
// 2. device_path:	The buffer that will store the path to the block device.
//
// Return value:
// On success 0 is returned and device_path parameter will hold the path
// the the device with the specific ID.
// Otherwise -1 is returned.
int find_vblock_device_by_order(const uint32_t n, char *device_path) {
	// TODO: Add support for more than 26 devices.
	char suffix = 'a' + (n % 26);
	char device_name[] = "/dev/vda";
	int ret = 0;

	device_name[7] = suffix;
	ret = access(device_name, F_OK);
	if (ret)
		return -1;

	snprintf(device_path, PATH_MAX, "%s", device_name);
	return 0;
}

// find_vblock_device_by_serial: Search all virtio block devices (vd[a-z]) to find the
// one with a specific serial ID.
//
// Arguments:
// 1. target_serial:	The serial ID to search for in the devices
// 2. device_path:	The buffer that will store the path to the block device
//
// Return value:
// On success 0 is returned and device_path parameter will hold the path
// the the device with the specific ID.
// Otherwise -1 is returned.
int find_vblock_device_by_serial(const char *target_serial, char *device_path) {
	char suffix = 0;
	char serial[SERIAL_MAX_SZ];
	char device_name[] = "vda";

	for (suffix = 'a'; suffix <= 'z'; suffix++) {
		int ret = 0;

		device_name[2] = suffix;
		ret = read_block_dev_serial(device_name, serial, sizeof(serial));
		if (ret < 0) {
			fprintf(stderr, "Error getting serial id of %s\n", device_name);
			continue;
		} else if (ret > 0) {
			// The device does not exist. Move to the next one.
			continue;
		}
		if (strcmp(serial, target_serial) == 0) {
			snprintf(device_path, PATH_MAX, "/dev/%s", device_name);
			return 0;
		}
	}

	return -1;
}

// mount_block_vols:	Mounts all block devices using their info from the
// block_config parameter.
//
// Arguments:
// 1. vols:	An array of struct block_config with information to mount
//		block volumes
//
// Return value:
// On success 0 is returned.
// Otherwise 1 is returned.
int mount_block_vols(struct block_config **vols) {
	struct block_config **iter_bc = NULL;
	char first_new_dir[PATH_MAX] = { 0 };
	uint32_t blk_count = 0;

	if (vols == NULL) {
		DEBUG_PRINT("No block volumes to mount, nothing to do\n");
		return 0;
	}

	for (iter_bc = vols; *iter_bc != NULL; iter_bc++) {
		struct block_config *tmp_bc = *iter_bc;
		char block_dev[PATH_MAX] = { 0 };
		int ret = 0;

		blk_count++;
		first_new_dir[0] = '\0';
		DEBUG_PRINTF("Searching block device with serial ID %s\n", tmp_bc->id);
		if (strlen(tmp_bc->id) > 2 && tmp_bc->id[0] == 'F' && tmp_bc->id[1] == 'C') {
			ret = find_vblock_device_by_order(blk_count, block_dev);
		} else {
			ret = find_vblock_device_by_serial(tmp_bc->id, block_dev);
		}
		if (ret) {
			fprintf(stderr, "Could not find any virtio block device with serial ID %s\n", tmp_bc->id);
			continue;
		}
		DEBUG_PRINTF("Found device %s\n", block_dev);
		DEBUG_PRINTF("Setup the mountpoint %s\n", tmp_bc->mountpoint);
		ret = mkdir_all(tmp_bc->mountpoint, 0755, first_new_dir);
		if (ret != 0 ) {
			fprintf(stderr, "Failed to create %s\n",tmp_bc->mountpoint);
			continue;
		}
		DEBUG_PRINT("Mount device as ext4\n");
		// TODO: SUpport more filesystem types
		ret = mount(block_dev, tmp_bc->mountpoint, "ext4", 0, "");
		if (ret != 0) {
			perror("mount");
			// Remove previously created directories.
			// NOTE: In case of an error we just print a warning
			// We might want to revisit this in the future.
			ret = rm_empty_dirs(tmp_bc->mountpoint, first_new_dir);
			if (ret < 0) {
				fprintf(stderr, "WARNING: Could not remove %s and its subdirs\n", tmp_bc->mountpoint);
			}
		}
	}

	return 0;
}

int child_func(char *argv[]) {
	char *config_file = NULL;
	char *config_buf = NULL;
	struct app_exec_config *app_config = NULL;
	int ret = 0;

	DEBUG_PRINT("Isolating child\n");
	// Put the child in a process group and
	// make it the foreground process if there is a tty.
	if (isolate_child()) {
		return 1;
	}

	// Check if we need to read any configuration for the app execution
	config_file = getenv("URUNIT_CONFIG");
	if (config_file) {
		// We need to mount sysfs to read the data from retained initrd
		ret = mount_special_fs();
		if (ret != 0) {
			fprintf(stderr, "Failed to mount special filesystems\n");
			return 1;
		}
		app_config = get_config_from_file(config_file, &config_buf);
	}
	if (app_config) {
		ret = mount_block_vols(app_config->blk_conf);
		if (ret != 0) {
			fprintf(stderr, "Failed to mount block volumes\n");
			goto child_func_free;
		}
		ret = setup_exec_env(app_config->pr_conf);
		if (ret != 0) {
			fprintf(stderr, "Failed to set up the process execution environment\n");
			goto child_func_free;
		}
		ret = manual_execvpe(app_config->path_env, argv[0], argv, app_config->envs);
	} else {
		DEBUG_PRINT("No configuration, simply execvp\n");
		ret = manual_execvpe(NULL, argv[0], argv, NULL);
	}
	// If we returned something went wrong
child_func_free:
	free(config_buf);
	free(app_config->envs);
	free(app_config->pr_conf);
	free(app_config);

	return ret;
}

int spawn_app(int argc, char *argv[], pid_t *child_pid) {
	int i = 0;
	pid_t pid;
	char *new_argv[128];
	// The arguments of the app are the same as the ones for urunit, but
	// removing the urunit argv[0]. Therefore:
	int new_argc = 0;

	for (i = 1; i < argc; i++) {
		char *tmp_arg = argv[i];

		if (tmp_arg[0] == '\'') {
			// The below is safe since the tmp_arg has at least one char
			uint32_t last_char = strlen(tmp_arg) - 1;
			if (tmp_arg[last_char] == '\'') {
				new_argv[new_argc++] = argv[i];
				continue;
			}
			// This arg (and everything until we encounter a ')
			// is part of the same argument
			int j = 0;
			char buffer[1024] = {0};

			strcat(buffer, tmp_arg + 1); // skip '
			for (j = i + 1; j < argc; j++) {
				char *next_arg = argv[j];
				size_t arg_len = strlen(next_arg);
				uint32_t last_char = 0;
				uint8_t should_break = 0;
				if (arg_len == 0) {
					continue;
				}
				last_char = arg_len - 1;
				if (last_char == 0) {
					if (next_arg[last_char] == '\'') {
						should_break = 1;
						// Remove '
						next_arg[last_char] = '\0';
					}
				} else {
					if (next_arg[last_char] == '\'' && next_arg[last_char - 1] != '\'' ) {
						should_break = 1;
						// Remove '
						next_arg[last_char] = '\0';
					}
				}
				strcat(buffer, " ");
				strcat(buffer, next_arg);
				if (should_break) {
					break;
				}
			}
			new_argv[new_argc++] = strdup(buffer);
			break;
		} else if (tmp_arg[0] == '"') {
			// The below is safe since the tmp_arg has at least one char
			uint32_t last_char = strlen(tmp_arg) - 1;
			if (tmp_arg[last_char] == '"') {
				new_argv[new_argc++] = argv[i];
				continue;
			}
			// This arg (and everything until we encounter a ")
			// is part of the same argument
			int j = 0;
			char buffer[1024] = {0};

			strcat(buffer, tmp_arg + 1); // skip "
			for (j = i + 1; j < argc; j++) {
				char *next_arg = argv[j];
				size_t arg_len = strlen(next_arg);
				uint32_t last_char = 0;
				uint8_t should_break = 0;
				if (arg_len == 0) {
					continue;
				}
				last_char = arg_len - 1;
				if (last_char == 0) {
					if (next_arg[last_char] == '"') {
						should_break = 1;
						// Remove '
						next_arg[last_char] = '\0';
					}
				} else {
					if (next_arg[last_char] == '"' && next_arg[last_char - 1] != '"' ) {
						should_break = 1;
						// Remove '
						next_arg[last_char] = '\0';
					}
				}
				strcat(buffer, " ");
				strcat(buffer, next_arg);
				if (should_break) {
					break;
				}
			}
			new_argv[new_argc++] = strdup(buffer);
			break;
		} else {
			new_argv[new_argc++] = argv[i];
		}
	}
	new_argv[new_argc] = NULL;

	if (new_argc <= 0 || new_argv[0] == NULL) {
		fprintf(stderr, "No application execute\n");
		return 1;
	}
#ifdef DEBUG
	printf("Starting app %s with the following arguments\n", new_argv[0]);
	for (int i = 1; i < new_argc; i++) {
		printf("%s\n", new_argv[i]);
	}
	printf("Environment variables\n");
	for (char **env = environ; *env != NULL; env++) {
		printf("%s\n", *env);
	}
#endif
	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	} else if (pid == 0) {
		return child_func(new_argv);
	} else {
		*child_pid = pid;
		return 0;
	}

	return 1;
}

int reap(const pid_t child_pid, int *child_exitcode_ptr) {
	pid_t reaped_pid = 0;
	int reaped_status = 0;

	while (1) {
		reaped_pid = waitpid(-1, &reaped_status, 0);
		switch (reaped_pid) {
		case -1:
			if (errno == ECHILD) {
				break;
			}
			perror("reaping");
			return 1;

		case 0:
			break;
		default:
			DEBUG_PRINTF("Reaped process %d ", reaped_pid);
			// A child was reaped. Check whether it's the app.
			// If it is, then set the exit_code,
			if (reaped_pid == child_pid) {
				if (WIFEXITED(reaped_status)) {
					DEBUG_PRINTF("with exit status %d\n", WEXITSTATUS(reaped_status));
					// The app exited normally
					*child_exitcode_ptr = WEXITSTATUS(reaped_status);
				} else if (WIFSIGNALED(reaped_status)) {
					DEBUG_PRINTF("with exit status %d\n", WTERMSIG(reaped_status));
					/* The app was terminated. Emulate what sh / bash
					 * would do, which is to return
					 * 128 + signal number.
					 */
					*child_exitcode_ptr = 128 + WTERMSIG(reaped_status);
				} else {
					DEBUG_PRINT("with unknown exit status\n");
					return 1;
				}

				// Be safe, ensure the status code is indeed between 0 and 255.
				*child_exitcode_ptr = *child_exitcode_ptr % (STATUS_MAX - STATUS_MIN + 1);

			}
			continue;
		}
		/* If we make it here, that's because we did not continue in the switch case. */
		break;
	}

	return 0;
}

int set_default_route() {
	int sockfd;
	struct rtentry rt;
	struct sockaddr_in addr;
	int ret = 0;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		perror("socket creation failed");
		return 1;
	}

	memset(&rt, 0, sizeof(rt));

	// Set default route for any IP address
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	memcpy(&rt.rt_dst, &addr, sizeof(addr));

	memcpy(&rt.rt_genmask, &addr, sizeof(addr));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = 0;
	memcpy(&rt.rt_gateway, &addr, sizeof(addr));

	DEBUG_PRINT("Setting default route to eth0\n");
	rt.rt_flags = RTF_UP;
	// TODO: We might want to doscover or somehow
	// get the interface as a parameter.
	rt.rt_dev = ETH0_IF;

	ret = ioctl(sockfd, SIOCADDRT, &rt);
	if(ret < 0) {
		perror("ioctl SIOCADDRT");
	}

	close(sockfd);
	return ret;
}

// is_block_fs: Checks if the parameter belongs to a list of known block-based
// filesystems.
//
// Arguments:
// 1. fs_type:	The filesystem type to check
//
// Return value:
// If the filesystem type is a known block-based filesystem type then 1 is returned.
// Otherwise 0 is returned.
int is_block_fs(const char *fs_type) {
	const char *block_types[] = {
		"ext2", "ext3", "ext4",	"xfs", "btrfs", "f2fs",
		"jfs", "reiserfs", "nilfs2", "vfat", "ntfs", "exfat",
		"hfs", "hfsplus", "ufs", "minix", "iso9660", "udf",
		NULL
	};
	int i = 0;

	for (i = 0; block_types[i] != NULL; i++) {
		if (strcmp(fs_type, block_types[i]) == 0) {
			return 1;
		}
	}
	return 0;
}

// is_network_fs: Checks if the parameter belongs to a list of known network-based
// filesystems.
//
// Arguments:
// 1. fs_type:	The filesystem type to check
//
// Return value:
// If the filesystem type is a known network-based filesystem type then 1 is returned.
// Otherwise 0 is returned.
int is_network_fs(const char *fs_type) {
	const char *network_types[] = {
		"nfs", "nfs4", "cifs", "smb", "smbfs",
		"ncpfs", "coda", "afs", "9p",
		"glusterfs", "lustre", "ceph", "ocfs2",
		NULL
	};

	for (int i = 0; network_types[i] != NULL; i++) {
		if (strcmp(fs_type, network_types[i]) == 0) {
			return 1;
		}
	}
	return 0;
}

// is_cloud_storage_fs: Checks if the parameter belongs to a list of known cloud-based
// filesystems.
//
// Arguments:
// 1. fs_type:	The filesystem type to check
//
// Return value:
// If the filesystem type is a known cloud-based filesystem type then 1 is returned.
// Otherwise 0 is returned.
int is_cloud_storage_fs(const char *fs_type) {
	const char *cloud_types[] = {
		"fuse.s3fs", "fuse.goofys", "fuse.s3backer", "fuse.gcsfuse",
		"fuse.blobfuse", "fuse.rclone", "fuse.juicefs", "fuse.sshfs",
		"fuse.curlftpfs", "fuse.davfs2", "fuse.httpfs", "fuse.s3ql",
		"fuse.ossfs", "fuse.cosfs", "fuse.obsfs", "iscsi", "seaweedfs",
		"minio",
		NULL
	};

	for (int i = 0; cloud_types[i] != NULL; i++) {
		if (strcmp(fs_type, cloud_types[i]) == 0) {
			return 1;
		}
	}

	return 0;
}

// skip_n_words: Returns a pointer after the first n words of a string
//
// Arguments:
// 1. str:	The string
// 2. n:	The number fo words to skip
//
// Return value:
// On success it returns a pointer right after the first n words inside the string str
// Otherwise str is returned.
char *skip_n_words(const char *str, size_t n) {
	const char *c = str;
	while (n > 0 && *c) {
		// Skip multiple spaces
		while (isspace((unsigned char)*c))
			c++;
		// Walk the word till space or end of string
		while (*c && !isspace((unsigned char)*c))
			c++;
		n--;
	}

	// Move to the beginning of the next word
	while (isspace((unsigned char)*c))
			c++;
	if (*c == 0) {
		return (char *)str;
	}

	return (char *)c;
}

// unmount_external: Unmounts all the external filesstem mounts found in
// /proc/self/mountinfo. External means all the known block, network and cloud storage
// based filesystems.
//
// Arguments:
//
// Return value:
void unmount_external() {
	FILE *mount_info_f = NULL;
	char line[1024] = { 0 };

	mount_info_f = fopen("/proc/self/mountinfo", "r");
	if (!mount_info_f) {
		perror("Error opening /proc/self/mountinfo");
		return;
	}

	while (fgets(line, sizeof(line), mount_info_f)) {
		char *tmp = NULL;
		char *mount_point = NULL;
		char *mount_type = NULL;

		mount_point = skip_n_words(line, 4);
		if (mount_point == line) {
			fprintf(stderr, "Malformed line in mountinfo. Could not reach mountpoint: %s\n", line);
			continue;
		}
		tmp = strchr(mount_point, ' ');
		if (!tmp) {
			fprintf(stderr, "Malformed line in mountinfo. Could not get mountpoint: %s\n", line);
			continue;
		}
		*tmp = '\0';
		tmp++;
		DEBUG_PRINTF("Found mountpoint %s\n", mount_point);
		// SKip rootfs because we can not unmount it easily.
		// Also, the rootfs will be be based on the container's image
		// and hence even if somehting goes wrong, a new instance of it
		// will get created for another container. Therefore, it will not
		// get reused.
		if (strcmp(mount_point, "/") == 0)
			continue;
		mount_type = strstr(tmp, " - ");
		if (!mount_type) {
			fprintf(stderr, "Malformed line in mountinfo. Could not reach mount type: %s%s\n", line, tmp);
			continue;
		}
		mount_type += 3;
		tmp = strchr(mount_type, ' ');
		if (!tmp) {
			fprintf(stderr, "Malformed line in mountinfo. Could not get mount type: %s%s\n", line, mount_type - 3);
			continue;
		}
		*tmp = '\0';
		DEBUG_PRINTF("Found mount type %s\n", mount_type);
		if (is_block_fs(mount_type) ||
		    is_network_fs(mount_type) ||
		    is_cloud_storage_fs(mount_type)) {
			int ret = 0;
			DEBUG_PRINTF("Trying to unmount %s\n", mount_point);
			ret = umount2(mount_point, MNT_FORCE);
			if (ret) {
				perror("umount");
			} else {
				DEBUG_PRINTF("Successful unmount of %s\n", mount_point);
			}
		}
	}
}

int main(int argc, char *argv[]) {
	pid_t app_pid;
	int ret = 0;
	int app_exitcode = -1;
	char *should_set_def_route = NULL;

	should_set_def_route = getenv("URUNIT_DEFROUTE");
	if (should_set_def_route) {
		DEBUG_PRINT("URUNIT_DEFROUTE was set\n");
		ret = set_default_route();
		if (ret != 0) {
			fprintf(stderr, "Failed to set default route\n");
		}
	}

	DEBUG_PRINT("Setting subreaper\n");
	ret = prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
	if (ret < 0) {
		perror("Become subreaper");
		return 1;
	}

	DEBUG_PRINT("Spawn the app\n");
	ret = spawn_app(argc, argv, &app_pid);
	if (ret) {
		fprintf(stderr, "Could not spawn app\n");
		return ret;
	}

	DEBUG_PRINT("Starting reaping loop\n");
	while (1) {
		ret = reap(app_pid, &app_exitcode);
		if (ret) {
			fprintf(stderr, "Error while reaping %d", ret);
			break;
		}

		if (app_exitcode != -1) {
			break;
		}
	}

	DEBUG_PRINT("Exiting, will reboot in order to shutdown\n");
	sync();
	unmount_external();
	syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
		LINUX_REBOOT_CMD_RESTART, NULL);
}
