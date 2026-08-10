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

#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <poll.h>
#include <sys/signalfd.h>
#include <linux/input.h>
#include <sys/mount.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "common.h"

#define STATUS_MAX 255
#define STATUS_MIN 0

struct process_config {
	uint32_t uid;
	uint32_t gid;
	char     *wdir;
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

	// The parent blocked SIGCHLD/SIGINT/SIGTERM before forking so they reach
	// its signalfd. Reset the mask here so the app runs normally (execve keeps
	// the signal mask but not the dispositions).
	{
		sigset_t mask;

		sigemptyset(&mask);
		sigaddset(&mask, SIGCHLD);
		sigaddset(&mask, SIGINT);
		sigaddset(&mask, SIGTERM);
		if (sigprocmask(SIG_UNBLOCK, &mask, NULL) < 0)
			perror("sigprocmask unblock");
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

// reap_children: Reap every exited child without blocking. If the app process
// (app_pid) is among them, store its normalized exit code in *app_exitcode.
//
// Return value:
// 1 if the app was reaped, 0 otherwise.
static int reap_children(pid_t app_pid, int *app_exitcode) {
	int app_reaped = 0;
	pid_t pid = 0;
	int status = 0;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (pid != app_pid)
			continue;
		if (WIFEXITED(status)) {
			*app_exitcode = WEXITSTATUS(status);
		} else if (WIFSIGNALED(status)) {
			*app_exitcode = 128 + WTERMSIG(status);
		} else {
			continue;
		}
		*app_exitcode = *app_exitcode % (STATUS_MAX - STATUS_MIN + 1);
		app_reaped = 1;
	}
	return app_reaped;
}

// request_app_shutdown: Send SIGTERM to the app's process group once. The app
// is its own process-group leader (isolate_child called setpgid(0,0)), so the
// whole workload receives it. Repeated calls are a no-op via *triggered.
static void request_app_shutdown(pid_t app_pid, int *triggered) {
	if (*triggered)
		return;
	*triggered = 1;
	DEBUG_PRINT("Shutdown event received, sending SIGTERM to the app\n");
	if (kill(-app_pid, SIGTERM) < 0)
		perror("kill app SIGTERM");
}

// wait_for_app: Wait until the app exits, reacting to shutdown events on the
// way. Multiplex the signalfd (child exits, SIGINT, SIGTERM) and the optional
// power-button device (btn_fd, -1 if none) with poll. On a shutdown event, ask
// the app to terminate, then keep waiting for it to exit. No timeout: the
// container manager's SIGKILL is the outer bound.
//
// Return value:
// The app's exit code, or -1 if the loop broke on an unrecoverable error.
static int wait_for_app(int sfd, int btn_fd, pid_t app_pid) {
	int app_exitcode = -1;
	int triggered = 0;

	for (;;) {
		struct pollfd fds[2];
		int nfds = 0;

		fds[nfds].fd = sfd;
		fds[nfds].events = POLLIN;
		fds[nfds].revents = 0;
		nfds++;
		if (btn_fd >= 0) {
			fds[nfds].fd = btn_fd;
			fds[nfds].events = POLLIN;
			fds[nfds].revents = 0;
			nfds++;
		}

		if (poll(fds, nfds, -1) < 0) {
			if (errno == EINTR)
				continue;
			perror("poll");
			break;
		}

		// Signalfd is always fds[0]. Drain it (non-blocking, until EAGAIN).
		if (fds[0].revents & POLLIN) {
			struct signalfd_siginfo si;

			while (read(sfd, &si, sizeof(si)) == (ssize_t)sizeof(si)) {
				if (si.ssi_signo == SIGCHLD) {
					if (reap_children(app_pid, &app_exitcode))
						return app_exitcode;
				} else {
					// SIGINT (Firecracker C-A-D) or SIGTERM.
					request_app_shutdown(app_pid, &triggered);
				}
			}
		}

		// Power-button device is fds[1] when present. Drain it.
		if (btn_fd >= 0 && (fds[1].revents & POLLIN)) {
			struct input_event ev;

			while (read(btn_fd, &ev, sizeof(ev)) == (ssize_t)sizeof(ev)) {
				if (ev.type == EV_KEY && ev.code == KEY_POWER &&
				    ev.value == 1)
					request_app_shutdown(app_pid, &triggered);
			}
		}
	}

	return app_exitcode;
}

int main(int argc, char *argv[]) {
	pid_t app_pid;
	int ret = 0;
	int app_exitcode = -1;
	int sfd = -1;
	int btn_fd = -1;
	char *should_set_def_route = NULL;

	should_set_def_route = getenv("URUNIT_DEFROUTE");
	if (should_set_def_route) {
		DEBUG_PRINT("URUNIT_DEFROUTE was set\n");
		ret = set_default_route();
		if (ret != 0) {
			fprintf(stderr, "Failed to set default route\n");
		}
	}

	// Route a guest Ctrl+Alt+Del (Firecracker x86) to PID 1 as SIGINT.
	disable_cad();

	DEBUG_PRINT("Setting subreaper\n");
	ret = set_subreaper();
	if (ret < 0) {
		perror("Become subreaper");
		return 1;
	}

	// Block the shutdown-related signals and read them through a signalfd.
	// Must happen before spawn_app so that no SIGCHLD is missed.
	sfd = setup_signalfd();
	if (sfd < 0) {
		fprintf(stderr, "Failed to set up signalfd\n");
		return 1;
	}

	// The bare initrd has no /dev, so create it and mount devtmpfs before the
	// app starts and before we look for the power-button device node.
	if (mkdir("/dev", 0755) < 0 && errno != EEXIST)
		perror("mkdir /dev");
	if (mount("dev", "/dev", "devtmpfs", MS_NOSUID, "mode=0755") < 0 &&
	    errno != EBUSY)
		perror("mount /dev devtmpfs");

	DEBUG_PRINT("Spawn the app\n");
	ret = spawn_app(argc, argv, &app_pid);
	if (ret) {
		fprintf(stderr, "Could not spawn app\n");
		return ret;
	}

	// Open the power-button input device (may be -1 if the kernel exposes none;
	// the SIGINT path still works in that case).
	btn_fd = open_power_button();

	DEBUG_PRINT("Waiting for the app\n");
	app_exitcode = wait_for_app(sfd, btn_fd, app_pid);
	DEBUG_PRINTF("App exited with code %d\n", app_exitcode);

	if (btn_fd >= 0)
		close(btn_fd);
	close(sfd);

	DEBUG_PRINT("Exiting, will reboot in order to shutdown\n");
	sync();
	unmount_external();
	request_reboot();
}
