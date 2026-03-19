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
#include <stdlib.h>

#include <sys/types.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/procctl.h>
#include <sys/reboot.h>
#include <sys/disk.h>

#include <net/route.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <unistd.h>

#include "common.h"

#define ETH0_IF "vtnet0"

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
	char ident[DISK_IDENT_SIZE];
	int fd = 0;
	int ret = 0;

	ret = snprintf(path, sizeof(path), "/dev/%s", device_name);
	if (ret < 0 || (size_t)ret >= sizeof(path)) {
		fprintf(stderr, "Could not create device path for %s\n", device_name);
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT) {
			return 1;
		}
		perror("open");
		return -1;
	}

	memset(ident, 0, sizeof(ident));
	ret = ioctl(fd, DIOCGIDENT, ident);
	close(fd);
	if (ret < 0) {
		perror("ioctl DIOCGIDENT");
		return -1;
	}

	if (ident[0] == '\0') {
		fprintf(stderr, "Serial value is empty");
		return 1;
	}

	ret = snprintf(serial, size, "%s", ident);
	if (ret < 0 || (size_t)ret >= size) {
		fprintf(stderr, "Serial too long for buffer\n");
		return -1;
	}

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
	// TODO: Add support for more than 10 devices.
	char suffix = '0' + (n % 10);
	char device_name[] = "/dev/vtbd0";
	int ret = 0;

	device_name[9] = suffix;
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
	char device_name[] = "vtbd0";

	for (suffix = '0'; suffix <= '9'; suffix++) {
		int ret = 0;

		device_name[4] = suffix;
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
int mount_special_fs(void) {
	int ret = 0;
	struct iovec iov[4];

	ret = ensure_dir("/proc");
	if (ret < 0) {
		return 1;
	}

	memset(iov, 0, sizeof(iov));
	iov[0].iov_base = "fstype";
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = "procfs";
	iov[1].iov_len = sizeof("procfs");
	iov[2].iov_base = "fspath";
	iov[2].iov_len = sizeof("fspath");
	iov[3].iov_base = "/proc";
	iov[3].iov_len = sizeof("/proc");

	ret = nmount(iov, 4, 0);
	if (ret < 0) {
		perror("mount /proc (procfs)");
		return 1;
	}

	ret = ensure_dir("/dev");
	if (ret < 0) {
		return 1;
	}

	memset(iov, 0, sizeof(iov));
	iov[0].iov_base = "fstype";
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = "devfs";
	iov[1].iov_len = sizeof("devfs");
	iov[2].iov_base = "fspath";
	iov[2].iov_len = sizeof("fspath");
	iov[3].iov_base = "/dev";
	iov[3].iov_len = sizeof("/dev");

	ret = nmount(iov, 4, 0);
	if (ret < 0) {
		perror("mount /dev (devfs)");
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
		struct iovec iov[6];

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
		DEBUG_PRINT("Mount device as ext2\n");
		// TODO: Support more filesystem types
		memset(iov, 0, sizeof(iov));
		iov[0].iov_base = "fstype";
		iov[0].iov_len = sizeof("fstype");
		iov[1].iov_base = "ext2fs";
		iov[1].iov_len = sizeof("ext2fs");
		iov[2].iov_base = "fspath";
		iov[2].iov_len = sizeof("fspath");
		iov[3].iov_base = tmp_bc->mountpoint;
		iov[3].iov_len = strlen(tmp_bc->mountpoint) + 1;
		iov[4].iov_base = "from";
		iov[4].iov_len = sizeof("from");
		iov[5].iov_base = block_dev;
		iov[5].iov_len = strlen(block_dev) + 1;

		ret = nmount(iov, 6, 0);
		if (ret != 0) {
			perror("nmount");
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
int set_default_route(const char *gateway_ip) {
	int sockfd;
	int ret = 0;

	struct {
		struct rt_msghdr rtm;
		struct sockaddr_in dst;
		struct sockaddr_in gw;
		struct sockaddr_in netmask;
		struct sockaddr_dl ifp;
	} msg;

	unsigned int ifindex = 0;

	ifindex = if_nametoindex(ETH0_IF);
	if (ifindex == 0) {
		perror("if_nametoindex");
		return 1;
	}

	sockfd = socket(PF_ROUTE, SOCK_RAW, AF_INET);
	if (sockfd < 0) {
		perror("socket PF_ROUTE");
		return 1;
	}

	memset(&msg, 0, sizeof(msg));

	msg.rtm.rtm_msglen = sizeof(msg);
	msg.rtm.rtm_version = RTM_VERSION;
	msg.rtm.rtm_type = RTM_ADD;
	msg.rtm.rtm_flags = RTF_UP | RTF_GATEWAY;
	msg.rtm.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK | RTA_IFP;
	msg.rtm.rtm_seq = 1;
	msg.rtm.rtm_pid = getpid();

	// Destination: 0.0.0.0 (default route)
	msg.dst.sin_len = sizeof(struct sockaddr_in);
	msg.dst.sin_family = AF_INET;
	msg.dst.sin_addr.s_addr = INADDR_ANY;

	// Gateway
	msg.gw.sin_len = sizeof(struct sockaddr_in);
	msg.gw.sin_family = AF_INET;
	if (gateway_ip && gateway_ip[0] != '\0') {
		ret = inet_pton(AF_INET, gateway_ip, &msg.gw.sin_addr);
		if (ret != 1) {
			fprintf(stderr, "Invalid gateway IP address: %s\n", gateway_ip);
			close(sockfd);
			return 1;
		}
		DEBUG_PRINTF("Setting default route via gateway %s on vtnet0\n", gateway_ip);
	} else {
		msg.gw.sin_addr.s_addr = INADDR_ANY;
		DEBUG_PRINT("Setting default route (on-link) on vtnet0\n");
	}

	// Netmask: 0.0.0.0
	msg.netmask.sin_len = sizeof(struct sockaddr_in);
	msg.netmask.sin_family = AF_INET;
	msg.netmask.sin_addr.s_addr = INADDR_ANY;

	// Interface
	msg.ifp.sdl_len = sizeof(struct sockaddr_dl);
	msg.ifp.sdl_family = AF_LINK;
	msg.ifp.sdl_index = (unsigned short)ifindex;

	DEBUG_PRINT("Setting default route to vtnet0\n");
	ret = write(sockfd, &msg, sizeof(msg));
	if (ret < 0) {
		perror("write to routing socket");
		close(sockfd);
		return 1;
	}

	close(sockfd);
	return 0;
}

// unmount_external: Unmounts all the external filesstem mounts found in
// /proc/self/mountinfo. External means all the known block, network and cloud storage
// based filesystems.
//
// Arguments:
//
// Return value:
void unmount_external(void) {
	struct statfs *mntbuf = NULL;
	int mntcount = 0;
	int i = 0;

	mntcount = getmntinfo(&mntbuf, MNT_NOWAIT);
	if (mntcount == 0) {
		perror("getmntinfo");
		return;
	}

	for (i = 0; i < mntcount; i++) {
		const char *mount_point = mntbuf[i].f_mntonname;
		const char *mount_type = mntbuf[i].f_fstypename;

		DEBUG_PRINTF("Found mountpoint %s (type %s)\n", mount_point, mount_type);

		// Skip rootfs
		if (strcmp(mount_point, "/") == 0)
			continue;

		if (is_block_fs(mount_type) ||
		    is_network_fs(mount_type) ||
		    is_cloud_storage_fs(mount_type)) {
			int ret = 0;
			DEBUG_PRINTF("Trying to unmount %s\n", mount_point);
			ret = unmount(mount_point, MNT_FORCE);
			if (ret) {
				perror("unmount");
			} else {
				DEBUG_PRINTF("Successful unmount of %s\n", mount_point);
			}
		}
	}
}

int set_subreaper(void) {
	return procctl(P_PID, 0, PROC_REAP_ACQUIRE, NULL);
}

void request_reboot(void) {
	reboot(RB_AUTOBOOT);
}

// set_iface_addr: Sets the IP address and netmask on the default network
// interface
//
// Arguments:
// 1. ip:      The IPv4 address as a string (e.g. "10.0.2.15")
// 2. netmask: The netmask as a string (e.g. "255.255.255.0")
//
// Return value:
// On success 0 is returned. Otherwise a non-zero value is returned.
int set_iface_addr(const char *ip, const char *netmask) {
	int sockfd;
	struct ifreq ifr;
	struct in_aliasreq ifra;
	int ret = 0;

	if (!ip || !netmask) {
		fprintf(stderr, "set_iface_addr: NULL argument\n");
		return 1;
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("socket");
		return 1;
	}

	memset(&ifra, 0, sizeof(ifra));
	snprintf(ifra.ifra_name, IFNAMSIZ, "%s", ETH0_IF);

	// Set IP address
	ifra.ifra_addr.sin_len = sizeof(struct sockaddr_in);
	ifra.ifra_addr.sin_family = AF_INET;
	ret = inet_pton(AF_INET, ip, &ifra.ifra_addr.sin_addr);
	if (ret != 1) {
		fprintf(stderr, "Invalid IP address: %s\n", ip);
		close(sockfd);
		return 1;
	}

	// Set netmask
	ifra.ifra_mask.sin_len = sizeof(struct sockaddr_in);
	ifra.ifra_mask.sin_family = AF_INET;
	ret = inet_pton(AF_INET, netmask, &ifra.ifra_mask.sin_addr);
	if (ret != 1) {
		fprintf(stderr, "Invalid netmask: %s\n", netmask);
		close(sockfd);
		return 1;
	}

	// Leave broadcast as zero — the kernel will compute it
	ifra.ifra_broadaddr.sin_len = sizeof(struct sockaddr_in);
	ifra.ifra_broadaddr.sin_family = AF_INET;

	DEBUG_PRINTF("Setting IP %s/%s on %s\n", ip, netmask, ETH0_IF);
	ret = ioctl(sockfd, SIOCAIFADDR, &ifra);
	if (ret < 0) {
		perror("ioctl SIOCAIFADDR");
		close(sockfd);
		return 1;
	}

	// Bring the interface up
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ETH0_IF);
	ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		perror("ioctl SIOCGIFFLAGS");
		close(sockfd);
		return 1;
	}

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
	if (ret < 0) {
		perror("ioctl SIOCSIFFLAGS");
		close(sockfd);
		return 1;
	}

	DEBUG_PRINTF("Interface %s is up with %s/%s\n", iface, ip, netmask);
	close(sockfd);
	return 0;
}
