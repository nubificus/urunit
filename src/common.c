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

#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>

#include "common.h"

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
