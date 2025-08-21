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

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#define STATUS_MAX 255
#define STATUS_MIN 0
#define ETH0_IF "eth0"
#define SMBIOS_TABLE_PATH "/sys/firmware/dmi/tables/DMI"
#define DMI_TYPE_OEM_STRINGS 11

#ifdef DEBUG
#define SHOW_DEBUG 1
#else
#define SHOW_DEBUG 0
#endif


#define DEBUG_PRINT(fmt, ...) \
	do { if (SHOW_DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

struct smbios_header {
	uint8_t type;
	uint8_t length;
	uint16_t handle;
}__attribute__((packed));

struct smbios_type11 {
	struct smbios_header shdr;
	uint8_t count;
}__attribute__((packed));

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
		// No environment variables were given. So, we can just
		// use execvp.
		execvp(file_bin, argv);
		goto manual_exec_exit;
	}

	if (*file_bin == '/' || env_path == NULL) {
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

// mount_special_fs: Mounts the special filesystems procfs and sysfs in /proc and
// /sys respectively.
//
// Arguments:
// No arguments.
//
// Return value:
// It returns 0 in success. Otherwise it returns 1.
int mount_special_fs() {
	if (mount("proc", "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL) < 0) {
		perror("mount /proc");
		return 1;
	}

	if (mount("sysfs", "/sys", "sysfs", 0, NULL) < 0) {
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

// measure_tokens: Measures how many tokens found in string, searching at most
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
// The funtion retruns a dynamically allocated memory and the caller is
// responsible to free that memory.
//
// Arguments:
// 1. string_area:	The list with in the aformentioned format.
// 2. max_sz:		The max possible size of the list.
// 3. path_env:		A pointer to a string where a pointer to the PATH environment
//			variable will get stored (if it is found).
//
// Return value:
// On success it returns an array of strings, where each row points
// to a single environment variable inside the initial list.
// Also, if the environment variable PATH was found, then path_env
// will point to the beginning of that string inside the list.
// Otherwise, NULL is returned.
char **parse_envs(char *string_area, size_t max_sz, char **path_env) {
	size_t total_envs = 0;
	char **env_vars = NULL;
	uint8_t path_found = 0;
	char *tmp_env = NULL;
	size_t i = 0;

	// Search how many new line characters we have in the list.
	total_envs = measure_tokens(string_area, max_sz, '\n');
	// If the list is correctly formatted it will start with "UES"
	// which will not be stored and therefore, we can use this extra
	// pointer for the end of the table (NULL), as execve and friends require.
	// NOTE: If the list contains "UEE", we allocate one more pointer that
	// is never used.
	env_vars = malloc(total_envs * sizeof(char *));
	if (!env_vars) {
		fprintf(stderr, "Failed to allocate memory for environment variables\n");
		return NULL;
	}

	tmp_env = strtok(string_area, "\n");
	// Discard the first string since it is the special string "UES"
	// Also, it is safe to call strtok, even if there was no '\n', since it will
	// return NULL again.
	tmp_env = strtok(NULL, "\n");
	while (tmp_env && i < total_envs) {
		// Check if we reached the end of the environment variable list
		if (memcmp(tmp_env, "UEE", 3) == 0)
			break;
		// Store the environment variable
		env_vars[i] = tmp_env;
		// If we have not found PATH yet,
		// check if the current environment variable is PATH.
		if (!path_found) {
			if (memcmp(tmp_env, "PATH=", 5) == 0) {
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
	// Add nULL to indicate the end of the table with environment variables.
	env_vars[i] = NULL;

	return env_vars;
}

// get_env_vars_from_smbios: Reads the smbios information from SMBIOS_TABLE_PATH and
// searches the area that holds the Type 11 (OEM strings) information. In this area,
// searches for the special string "UES" which denotes the beginning of the environment
// variables list and calls parse_envs to parse the found list.
//
// Arguments:
// 1. path_env:	A pointer to store the location of PATH environment variables
//		inside the list, if the environment variable is found.
//
// Return value:
// On success it returns a a table with environment variables formatted correctly
// and able to be used for execve and friends. Furthermore, if PATH environment
// variable is found, the path_env will point to the respective location.
// On failure, it return NULL.
char **get_env_vars_from_smbios(char **path_env, char **sbuf) {
	char **env_vars = NULL;
	FILE *fp = NULL;
	struct stat st = { 0 };
	int ret = 0;
	char *buf = NULL;
	size_t pos = 0;

	fp = fopen(SMBIOS_TABLE_PATH, "rb");
	if (!fp) {
		perror("Open smbios file");
		return NULL;
	}

	// FInd the total size of the file in order to read the whole file
	// and have a limit to search in the buffer.
	ret = fstat(fileno(fp), &st);
	if (ret != 0) {
		perror("Getting smbios file size");
		goto get_env_vars_error;
	}

	// Make sure to read the whole file in one buffer.
	buf = read_exact_size(fp, st.st_size);
	if (!buf) {
		goto get_env_vars_error;
	}

	// Start searching for the Type 11 (OEM strings) area.
	while (pos < st.st_size - sizeof(struct smbios_header)) {
		// Get the smbios header of the current area.
		struct smbios_header *header = (struct smbios_header *)(buf + pos);

		// Make sure the structural info of the area is not bigger than
		// the smbios header.This check is also importnat for iteration later.
		if (header->length < sizeof(struct smbios_header))
			break;

		if (header->type == DMI_TYPE_OEM_STRINGS) {
			struct smbios_type11 *type11 = (struct smbios_type11 *)(buf + pos);
			char *string_area = buf + pos + header->length;

			DEBUG_PRINT("Found DMI Type 11 structure with %d OEM strings:\n",
					type11->count);
			DEBUG_PRINT("%s\n", string_area);
			// Check if the special string "UES" is present
			if (memcmp(string_area, "UES", 3) == 0) {
				// Extract the environment variables from the list
				env_vars = parse_envs(string_area, st.st_size, path_env);
				if (!env_vars) {
					fprintf(stderr, "Warning: No environment variables found in smbios\n");
					goto get_env_vars_error_free;
				}
				// We found our list no reason to check further.
				break;
			}
			// TODO: There is the possibility that QEMU prepends
			// various data before our list and we might need to search
			// deeper in the Type 11 area to find "UES".
		}
		// Move to the next area.
		pos += header->length;
		// We do not have the information to know the size of each area.
		// Therefore, check every byte till we find the sequence
		// "\0\0"
		while (pos < (size_t)(st.st_size - 1)) {
			if (buf[pos] == 0 && buf[pos + 1] == 0) {
				// Move past the "\0\0" sequence.
				pos += 2;
				break;
			}
			pos++;
		}
	}

	fclose(fp);
	*sbuf = buf;
	return env_vars;

get_env_vars_error_free:
	free(buf);
get_env_vars_error:
	fclose(fp);
	return NULL;
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

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	} else if (pid == 0) {
		const char *config_from_smbios = NULL;
		char *path_env = NULL;
		char *smbios_buf = NULL;
		char **smbios_envs = NULL;
		int ret = 0;

		// Put the child in a process group and
		// make it the foreground process if there is a tty.
		if (isolate_child()) {
			return 1;
		}

		// Check if we need to read any config from smbios.
		config_from_smbios = getenv("URUNIT_ENVS");
		if (config_from_smbios) {
			// We need to mount sysfs to read the data from smbios.
			if (mount_special_fs() != 0) {
				fprintf(stderr, "Failed to mount special filesystems\n");
				return 1;
			} else {
				smbios_envs = get_env_vars_from_smbios(&path_env, &smbios_buf);
			}
		}

		DEBUG_PRINT("Executing %s\n", new_argv[0]);
		ret = manual_execvpe(path_env, new_argv[0], new_argv, smbios_envs);
		free(smbios_buf);
		free(smbios_envs);
		return ret;
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
			// A child was reaped. Check whether it's the app.
			// If it is, then set the exit_code,
			if (reaped_pid == child_pid) {
				if (WIFEXITED(reaped_status)) {
					// The app exited normally
					*child_exitcode_ptr = WEXITSTATUS(reaped_status);
				} else if (WIFSIGNALED(reaped_status)) {
					/* The app was terminated. Emulate what sh / bash
					 * would do, which is to return
					 * 128 + signal number.
					 */
					*child_exitcode_ptr = 128 + WTERMSIG(reaped_status);
				} else {
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

int main(int argc, char *argv[]) {
	pid_t app_pid;
	int ret = 0;
	int app_exitcode = -1;

	ret = set_default_route();
	if (ret != 0) {
		fprintf(stderr, "Failed to set default route\n");
	}

	ret = prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
	if (ret < 0) {
		perror("Become subreaper");
		return 1;
	}

	ret = spawn_app(argc, argv, &app_pid);
	if (ret) {
		fprintf(stderr, "Could not spawn app\n");
		return ret;
	}

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

	sync();
	syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
		LINUX_REBOOT_CMD_RESTART, NULL);
}
