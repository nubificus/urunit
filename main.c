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


#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <linux/reboot.h>
#include <linux/route.h>

#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

#define SMBIOS_TABLE_PATH "/sys/firmware/dmi/tables/DMI"

#define STATUS_MAX 255
#define STATUS_MIN 0
#define ETH0_IF "eth0"

// SMBIOS table header
struct smbios_header {
    uint8_t type;
    uint8_t length;
    uint16_t handle;
};

static unsigned char b64_table[256];

void base64_init_table() {
    memset(b64_table, 0x80, 256);
    const char *alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; alphabet[i]; i++) {
        b64_table[(unsigned char)alphabet[i]] = i;
    }
    b64_table[(unsigned char)'='] = 0;
}

char *base64_decode_str(const char *src) {
    size_t len = strlen(src);
    unsigned char *out = malloc((len * 3) / 4 + 1);
    if (!out) return NULL;

    size_t out_len = 0;
    uint32_t buffer = 0;
    int bits = 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)src[i];
        if (isspace(c)) continue;
        unsigned char val = b64_table[c];
        if (val & 0x80) continue;

        buffer = (buffer << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[out_len++] = (buffer >> bits) & 0xFF;
        }
    }
    out[out_len] = '\0';
    return (char*)out;
}

const char *get_smbios_string(const char *start, size_t struct_len, uint8_t str_index) {
    if (str_index == 0)
        return NULL;
    const char *str_ptr = start + struct_len;
    int current_index = 1;
    while (current_index < str_index && *str_ptr) {
        str_ptr += strlen(str_ptr) + 1;
        current_index++;
    }
    if (*str_ptr == 0)
        return NULL;
    return str_ptr;
}

void parse_smbios_type11_and_setenv(const char *struct_start, uint8_t length) {
    uint8_t count = (uint8_t)struct_start[4];

    for (int i = 1; i <= count; i++) {
        const char *s = get_smbios_string(struct_start, length, i);
        if (!s) continue;

        char *tmp = strdup(s);
        if (!tmp) continue;

        char *eq = strchr(tmp, '=');
        if (eq) {
            *eq = '\0';
            const char *key = tmp;
            const char *encoded = eq + 1;

            char *decoded = base64_decode_str(encoded);
            if (decoded) {
                setenv(key, decoded, 1);
                free(decoded);
            }
        }
        free(tmp);
    }
}

void import_smbios_type11_envvars() {
    FILE *f = fopen(SMBIOS_TABLE_PATH, "rb");
    if (!f) {
        perror("Failed to open SMBIOS table");
        return;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);
    if (size <= 0) {
        fclose(f);
        return;
    }

    char *buffer = malloc(size);
    if (!buffer) {
        fclose(f);
        return;
    }
    fread(buffer, 1, size, f);
    fclose(f);

    size_t pos = 0;
    while (pos + sizeof(struct smbios_header) <= (size_t)size) {
        struct smbios_header *hdr = (struct smbios_header *)(buffer + pos);

        if (hdr->length < sizeof(struct smbios_header)) break;

        size_t struct_start = pos;
        size_t formatted_len = hdr->length;
        size_t str_area = struct_start + formatted_len;
        size_t str_len = 0;
        while (str_area + str_len + 1 < (size_t)size) {
            if (buffer[str_area + str_len] == 0 &&
                buffer[str_area + str_len + 1] == 0) {
                str_len += 2;
                break;
            }
            str_len++;
        }

        size_t total_len = formatted_len + str_len;

        if (hdr->type == 11) {
            parse_smbios_type11_and_setenv(buffer + struct_start, hdr->length);
        }

        pos += total_len;
        if (hdr->type == 127) break;
    }
    free(buffer);
}

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

extern char **environ;

#if 0
void append_nameserver() {
    FILE *f = fopen("/etc/resolv.conf", "a");  // open for appending
    if (!f) {
        perror("Failed to open /etc/resolv.conf");
        return;
    }

    // Append the nameserver line
    fprintf(f, "\nnameserver 8.8.8.8\n");

    fclose(f);
}
#endif

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
		int status = 1;


		// After clone or unshare(CLONE_NEWNS), do:
		if (mount("proc", "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL) < 0) {
		    perror("mount /proc");
		    return 1;
		}

		if (mount("sysfs", "/sys", "sysfs", 0, NULL) < 0) {
		    perror("mount /sys");
		    return 1;
		}

		if (mount("tmpfs", "/tmp", "tmpfs", 0, "mode=1777") < 0) {
		    perror("mount /tmp");
		    return 1;
		}


		mkdir("/dev/pts", 0755);
		if (mount("devpts", "/dev/pts", "devpts", 0, "gid=5,mode=620") < 0) {
		    perror("mount /dev/pts");
		    return 1;
		}

		//FIXME
		struct rlimit rl;
		rl.rlim_cur = 65535;
		rl.rlim_max = 65535;

		if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
		    perror("setrlimit RLIMIT_NOFILE");
		}

		FILE *f = fopen("/proc/sys/vm/max_map_count", "w");
		if (f) {
		    fprintf(f, "262144\n");
		    fclose(f);
		} else {
		    perror("fopen max_map_count");
		}

		// Put the child in a process group and
		// make it the foreground process if there is a tty.
		if (isolate_child()) {
			return 1;
		}

		base64_init_table();
    		import_smbios_type11_envvars();

		// Print current environment
		printf("== Environment passed to execvp() ==\n");
		for (char **env = environ; *env != NULL; env++) {
			printf("%s\n", *env);
		}
		printf("====================================\n");

		//FIXME set UID/GID
		setenv("USER", "elasticsearch", 1);
#define TARGET_UID 1000
#define TARGET_GID 1000

		if (setgid(TARGET_GID) < 0) {
		    perror("setgid");
		    exit(1);
		}

		if (setuid(TARGET_UID) < 0) {
		    perror("setuid");
		    exit(1);
		}

		//FIXME
		printf("Chdir to home, and launch!\n");

		const char *home = getenv("HOME");
		if (!home) {
			fprintf(stderr, "HOME environment variable not set, non Fatal\n");
		}

		if (chdir(home) != 0) {
			perror("chdir to HOME failed, non Fatal");
		}

		execvp(new_argv[0], new_argv);

		// execvp will only return on an error so make sure that we check the errno
		// and exit with the correct return status for the error that we encountered
		// See: http://www.tldp.org/LDP/abs/html/exitcodes.html#EXITCODESREF
		switch (errno) {
		case ENOENT:
			status = 127;
			break;
		case EACCES:
			status = 126;
			break;
		}
		perror("execv failed");
		return status;
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
		reaped_pid = waitpid(-1, &reaped_status, WNOHANG);

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

int set_mtu(const char *ifname, int mtu) {
    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ifr.ifr_mtu = mtu;

    if (ioctl(sockfd, SIOCSIFMTU, &ifr) < 0) {
        perror("ioctl SIOCSIFMTU");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}


int main(int argc, char *argv[]) {
	pid_t app_pid;
	int ret = 0;
	int app_exitcode = -1;

	ret = set_default_route();
	if (ret != 0) {
		fprintf(stderr, "Failed to set default route\n");
	}

	//FIXME
	ret = set_mtu("eth0", 1400);
	if (ret != 0) {
		fprintf(stderr, "Failed to set mtu\n");
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
