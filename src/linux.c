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

#include <stdio.h> 
#include <limits.h>
#include <errno.h>
#include <string.h>

#include <linux/reboot.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/route.h>
#include <netinet/in.h>

#include "common.h"

#define ETH0_IF "eth0"

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
// If the device does not exist, 1 is returned.
// In all other cases or errors -1 is returned.
int read_block_dev_serial(const char *device_name, char *serial, const size_t size) {
	char path[PATH_MAX];
	FILE *fp;
	int ret = 0;

	ret = snprintf(path, sizeof(path), "/sys/block/%s/serial", device_name);
	if (ret < 0 || (size_t)ret >= sizeof(path)) {
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

// find_vblock_device_by_order: Returns the nth (zero-based) virtio block device
// (vd*) if it exists. The order is based on the conventional naming of virtio
// block devices in Linux where usually the first attached is vda, second vdb,
// etc. In this function, n == 0 maps to /dev/vda, n == 1 to /dev/vdb, and so on.
//
// Arguments:
// 1. n:		Zero-based index of the virtio block device to return.
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

	// It is safe here to doa quick memcpy, since device_name has
	// a specific size and only its last character (of the string,
	// not NULL temrination byte) can change
	memcpy(device_path, device_name, sizeof(device_name));
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
			int ret = snprintf(device_path, PATH_MAX, "/dev/%s", device_name);
			if (ret < 0 || (size_t)ret >= PATH_MAX) {
				fprintf(stderr, "Could not copy the found device: %s", device_name);
				return -1;
			}
			return 0;
		}
	}

	return -1;
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
		// TODO: Support more filesystem types
		ret = mount(block_dev, tmp_bc->mountpoint, "ext4", 0, "");
		if (ret != 0) {
			perror("mount");
			// Remove previously created directories.
			// NOTE: In case of an error we just print a warning
			// We might want to revisit this in the future.
			if (first_new_dir[0] != '\0') {
				ret = rm_empty_dirs(tmp_bc->mountpoint, first_new_dir);
				if (ret < 0) {
					fprintf(stderr, "WARNING: Could not remove %s and its subdirs\n", tmp_bc->mountpoint);
				}
			}
		}
	}

	return 0;
}

// set_default_route: Sets the default network route to eth0.
//
// Arguments:
// No arguments.
//
// Return value:
// On success 0 is returned. Otherwise a non-zero value is returned.
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
	// TODO: We might want to discover or somehow
	// get the interface as a parameter.
	rt.rt_dev = ETH0_IF;

	ret = ioctl(sockfd, SIOCADDRT, &rt);
	if(ret < 0) {
		perror("ioctl SIOCADDRT");
	}

	close(sockfd);
	return ret;
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
		// Skip rootfs because we can not unmount it easily.
		// Also, the rootfs will be based on the container's image
		// and hence even if something goes wrong, a new instance of it
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

	fclose(mount_info_f);
}

int set_subreaper() {
	return prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);
}

void request_reboot() {
	syscall(SYS_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
		LINUX_REBOOT_CMD_RESTART, NULL);
}
