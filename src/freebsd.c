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

// FreeBSD implementation of the platform specific parts of urunit.
//
// Differences from Linux that shape this file:
// - The kernel starts init (us) without arguments and without open file
//   descriptors. The application and its arguments come from the urunit
//   configuration and the console has to be opened by hand.
// - Boot arguments are kernel environment variables (kenv(2)), not process
//   environment variables. URUNIT_CONFIG and URUNIT_DEFROUTE are read from
//   there when they are not in the environment.
// - There is no ip= boot parameter, so the network configuration is part of
//   the urunit configuration (UNS/UNE section) and applied here.
// - The urunit configuration is handed over as a raw virtio block device
//   (disks are character devices with st_size == 0, so their size comes
//   from DIOCGMEDIASIZE).
// - Virtio block devices are /dev/vtbdN and, when the device has a serial,
//   /dev/diskid/DISK-<serial> (GEOM_LABEL).

#include <sys/param.h>
#include <sys/types.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/procctl.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/ucred.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <kenv.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

#define VTNET_IF	"vtnet0"
#define CONSOLE_DEV	"/dev/console"
#define CONFIG_MAX_SZ	(1024 * 1024)
#define DEFAULT_MASK	"255.255.255.0"

// setup_console: PID 1 started by the FreeBSD kernel has no open file
// descriptors and no controlling terminal. Become a session leader, open the
// console and use it for stdin/stdout/stderr. When we already have a stdin
// (e.g. started from a shell) nothing is done.
//
// Return value:
// On success 0 is returned. Otherwise 1 is returned.
int setup_console(void) {
	struct stat st;
	int fd;
	int ret;

	ret = fstat(STDIN_FILENO, &st);
	if (ret == 0) {
		DEBUG_PRINT("stdin is open, keeping the current console\n");
		return 0;
	}

	// PID 1 is not a session leader; ignore EPERM if we already are one.
	ret = setsid();
	if (ret < 0 && errno != EPERM) {
		perror("setsid");
	}

	fd = open(CONSOLE_DEV, O_RDWR);
	if (fd < 0) {
		// Nothing we can print to. Try to continue silently.
		return 1;
	}
	// Make the console our controlling terminal so that the application
	// gets job control and signals (^C) from the serial console.
	ret = ioctl(fd, TIOCSCTTY, 0);
	if (ret < 0) {
		perror("TIOCSCTTY");
	}
	ret = dup2(fd, STDIN_FILENO) < 0 || dup2(fd, STDOUT_FILENO) < 0 ||
	      dup2(fd, STDERR_FILENO) < 0;
	if (ret) {
		perror("dup2 console");
		close(fd);
		return 1;
	}
	if (fd > STDERR_FILENO) {
		close(fd);
	}

	return 0;
}

// get_boot_var: Returns the value of a kernel environment variable, which is
// how boot arguments (name=value) reach the guest on the PVH boot path.
//
// Arguments:
// 1. name:	The name of the variable
//
// Return value:
// On success a dynamically allocated string with the value is returned.
// If the variable does not exist, NULL is returned.
char *get_boot_var(const char *name) {
	char buf[KENV_MVALLEN + 1];
	int ret;

	ret = kenv(KENV_GET, name, buf, sizeof(buf) - 1);
	if (ret < 0) {
		return NULL;
	}
	buf[sizeof(buf) - 1] = '\0';
	DEBUG_PRINTF("kenv %s=%s\n", name, buf);

	return strdup(buf);
}

// read_raw_device: Reads the contents of a raw disk device (the urunit
// configuration is attached as a tiny virtio block device). The device is read
// in sector-sized chunks and the buffer is NUL terminated. The caller is
// responsible to free the returned buffer.
//
// Arguments:
// 1. fd:	An open file descriptor of the device
// 2. size:	Will hold the amount of bytes read
//
// Return value:
// On success a buffer with the contents of the device is returned.
// On failure, NULL is returned.
char *read_raw_device(int fd, size_t *size) {
	off_t media_size = 0;
	u_int sector_size = DEV_BSIZE;
	char *buffer = NULL;
	off_t off = 0;
	int ret = 0;

	ret = ioctl(fd, DIOCGMEDIASIZE, &media_size);
	if (ret < 0) {
		perror("DIOCGMEDIASIZE");
		return NULL;
	}
	ret = ioctl(fd, DIOCGSECTORSIZE, &sector_size);
	if (ret < 0 || sector_size == 0) {
		sector_size = DEV_BSIZE;
	}
	if (media_size <= 0) {
		fprintf(stderr, "Configuration device is empty\n");
		return NULL;
	}
	if (media_size > CONFIG_MAX_SZ) {
		media_size = CONFIG_MAX_SZ;
	}
	// Raw device I/O has to be a multiple of the sector size.
	media_size -= media_size % sector_size;
	DEBUG_PRINTF("Reading %jd bytes from configuration device (sector %u)\n",
		     (intmax_t)media_size, sector_size);

	buffer = malloc(media_size + 1);
	if (!buffer) {
		fprintf(stderr, "Failed to allocate memory for the configuration device\n");
		return NULL;
	}

	while (off < media_size) {
		ssize_t n = pread(fd, buffer + off, media_size - off, off);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			perror("read configuration device");
			free(buffer);
			return NULL;
		}
		if (n == 0) {
			break;
		}
		off += n;
	}
	buffer[off] = '\0';
	*size = (size_t)off;

	return buffer;
}

// remount_root_rw: The kernel always mounts the root filesystem read-only
// (vfs.root.mountfrom.options=rw is ignored by mountroot); rc(8) normally
// remounts it read-write. Do the same for the application.
//
// Return value:
// On success 0 is returned. Otherwise a non-zero value is returned.
int remount_root_rw(void) {
	struct statfs sfs;
	struct iovec iov[10];
	int ret = 0;

	ret = statfs("/", &sfs);
	if (ret != 0) {
		perror("statfs /");
		return 1;
	}
	if ((sfs.f_flags & MNT_RDONLY) == 0) {
		return 0;
	}
	DEBUG_PRINTF("Remounting / (%s from %s) read-write\n", sfs.f_fstypename, sfs.f_mntfromname);
	iov[0].iov_base = (void *)"fstype";
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = sfs.f_fstypename;
	iov[1].iov_len = strlen(sfs.f_fstypename) + 1;
	iov[2].iov_base = (void *)"fspath";
	iov[2].iov_len = sizeof("fspath");
	iov[3].iov_base = (void *)"/";
	iov[3].iov_len = sizeof("/");
	iov[4].iov_base = (void *)"from";
	iov[4].iov_len = sizeof("from");
	iov[5].iov_base = sfs.f_mntfromname;
	iov[5].iov_len = strlen(sfs.f_mntfromname) + 1;
	// Flag options are name/value pairs with an empty value.
	iov[6].iov_base = (void *)"update";
	iov[6].iov_len = sizeof("update");
	iov[7].iov_base = NULL;
	iov[7].iov_len = 0;
	iov[8].iov_base = (void *)"rw";
	iov[8].iov_len = sizeof("rw");
	iov[9].iov_base = NULL;
	iov[9].iov_len = 0;
	ret = nmount(iov, 10, MNT_UPDATE);
	if (ret != 0) {
		perror("remount / read-write");
		return 1;
	}

	return 0;
}

// mount_special_fs: devfs is mounted on /dev by the kernel. Mount a tmpfs on
// /tmp, and procfs on /proc if the directory exists. Neither failure is fatal.
//
// Return value:
// It always returns 0.
int mount_special_fs(void) {
	struct iovec iov[6];
	struct stat st;
	int ret = 0;

	// A writable /tmp is expected by most applications. urunit does not
	// itself depend on it, so a failure here is not fatal.
	ret = ensure_dir("/tmp");
	if (ret == 0) {
		iov[0].iov_base = (void *)"fstype";
		iov[0].iov_len = sizeof("fstype");
		iov[1].iov_base = (void *)"tmpfs";
		iov[1].iov_len = sizeof("tmpfs");
		iov[2].iov_base = (void *)"fspath";
		iov[2].iov_len = sizeof("fspath");
		iov[3].iov_base = (void *)"/tmp";
		iov[3].iov_len = sizeof("/tmp");
		iov[4].iov_base = (void *)"from";
		iov[4].iov_len = sizeof("from");
		iov[5].iov_base = (void *)"tmpfs";
		iov[5].iov_len = sizeof("tmpfs");
		ret = nmount(iov, 6, 0);
		if (ret < 0) {
			DEBUG_PRINTF("mount /tmp: %s\n", strerror(errno));
		} else {
			// tmpfs takes the mode of the covered directory; make /tmp
			// world-writable with the sticky bit like a normal /tmp.
			ret = chmod("/tmp", 01777);
			if (ret < 0) {
				perror("chmod /tmp");
			}
		}
	}

	// procfs is optional and only mounted when /proc exists.
	ret = stat("/proc", &st);
	if (ret != 0) {
		return 0;
	}
	iov[0].iov_base = (void *)"fstype";
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = (void *)"procfs";
	iov[1].iov_len = sizeof("procfs");
	iov[2].iov_base = (void *)"fspath";
	iov[2].iov_len = sizeof("fspath");
	iov[3].iov_base = (void *)"/proc";
	iov[3].iov_len = sizeof("/proc");
	iov[4].iov_base = (void *)"from";
	iov[4].iov_len = sizeof("from");
	iov[5].iov_base = (void *)"procfs";
	iov[5].iov_len = sizeof("procfs");
	ret = nmount(iov, 6, 0);
	if (ret < 0 && errno != EBUSY) {
		DEBUG_PRINTF("mount /proc: %s\n", strerror(errno));
	}

	return 0;
}

// find_vblock_device_by_order: Returns the nth (zero-based) virtio block
// device (/dev/vtbdN) if it exists.
//
// Arguments:
// 1. n:		Zero-based index of the virtio block device to return.
// 2. device_path:	The buffer that will store the path to the block device.
//
// Return value:
// On success 0 is returned and device_path holds the device path.
// Otherwise -1 is returned.
int find_vblock_device_by_order(const uint32_t n, char *device_path) {
	char device_name[PATH_MAX];
	int len = 0;
	int ret = 0;

	len = snprintf(device_name, sizeof(device_name), "/dev/vtbd%u", n);
	if (len < 0 || (size_t)len >= sizeof(device_name)) {
		return -1;
	}
	ret = access(device_name, F_OK);
	if (ret != 0) {
		return -1;
	}
	memcpy(device_path, device_name, (size_t)len + 1);

	return 0;
}

// find_vblock_device_by_serial: Finds a disk by its serial id through the
// GEOM_LABEL diskid provider (/dev/diskid/DISK-<serial>).
//
// Arguments:
// 1. target_serial:	The serial ID to search for
// 2. device_path:	The buffer that will store the path to the block device
//
// Return value:
// On success 0 is returned and device_path holds the device path.
// Otherwise -1 is returned.
int find_vblock_device_by_serial(const char *target_serial, char *device_path) {
	char device_name[PATH_MAX];
	int len = 0;
	int ret = 0;

	len = snprintf(device_name, sizeof(device_name), "/dev/diskid/DISK-%s", target_serial);
	if (len < 0 || (size_t)len >= sizeof(device_name)) {
		return -1;
	}
	ret = access(device_name, F_OK);
	if (ret != 0) {
		return -1;
	}
	memcpy(device_path, device_name, (size_t)len + 1);

	return 0;
}

// do_mount: Mounts a filesystem with nmount(2).
static int do_mount(const char *fstype, const char *from, const char *fspath, int flags) {
	struct iovec iov[6];

	iov[0].iov_base = (void *)"fstype";
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = (void *)fstype;
	iov[1].iov_len = strlen(fstype) + 1;
	iov[2].iov_base = (void *)"fspath";
	iov[2].iov_len = sizeof("fspath");
	iov[3].iov_base = (void *)fspath;
	iov[3].iov_len = strlen(fspath) + 1;
	iov[4].iov_base = (void *)"from";
	iov[4].iov_len = sizeof("from");
	iov[5].iov_base = (void *)from;
	iov[5].iov_len = strlen(from) + 1;

	return nmount(iov, 6, flags);
}

// mount_block_vols: Mounts all block devices using their info from the
// block_config parameter. Volumes are tried as ext2fs first (urunc creates
// ext2/ext4 block volumes on the host) and as ufs afterwards.
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
		// Firecracker has no drive serials: the volumes follow the rootfs
		// in the order they were attached.
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
		DEBUG_PRINT("Mount device as ext2fs\n");
		ret = do_mount("ext2fs", block_dev, tmp_bc->mountpoint, 0);
		if (ret != 0) {
			DEBUG_PRINT("Mount device as ufs\n");
			ret = do_mount("ufs", block_dev, tmp_bc->mountpoint, 0);
		}
		if (ret != 0) {
			perror("mount");
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

#define RT_ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

// rt_add: Adds a route through the routing socket.
//
// Arguments:
// 1. dst:	The destination
// 2. gw:	The gateway (an IPv4 address or the link address of an interface)
// 3. mask:	The netmask, or NULL for a host route
// 4. flags:	RTF_* flags
//
// Return value:
// On success 0 is returned. Otherwise -1 is returned.
static int rt_add(struct sockaddr *dst, struct sockaddr *gw, struct sockaddr *mask, int flags) {
	struct {
		struct rt_msghdr hdr;
		char space[512];
	} msg;
	char *cp = msg.space;
	int sock;
	ssize_t n;

	memset(&msg, 0, sizeof(msg));
	msg.hdr.rtm_type = RTM_ADD;
	msg.hdr.rtm_version = RTM_VERSION;
	msg.hdr.rtm_flags = flags;
	msg.hdr.rtm_seq = 1;
	msg.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY;

	memcpy(cp, dst, dst->sa_len);
	cp += RT_ROUNDUP(dst->sa_len);
	memcpy(cp, gw, gw->sa_len);
	cp += RT_ROUNDUP(gw->sa_len);
	if (mask) {
		msg.hdr.rtm_addrs |= RTA_NETMASK;
		memcpy(cp, mask, mask->sa_len);
		cp += RT_ROUNDUP(mask->sa_len);
	}
	msg.hdr.rtm_msglen = (u_short)(cp - (char *)&msg);

	sock = socket(PF_ROUTE, SOCK_RAW, AF_INET);
	if (sock < 0) {
		perror("routing socket");
		return -1;
	}
	n = write(sock, &msg, msg.hdr.rtm_msglen);
	close(sock);
	if (n < 0) {
		if (errno == EEXIST) {
			return 0;
		}
		perror("RTM_ADD");
		return -1;
	}

	return 0;
}

// get_link_addr: Returns the AF_LINK address of an interface.
static int get_link_addr(const char *ifname, struct sockaddr_dl *sdl) {
	struct ifaddrs *ifap = NULL, *ifa = NULL;
	int found = 0;
	int ret = 0;

	ret = getifaddrs(&ifap);
	if (ret != 0) {
		perror("getifaddrs");
		return -1;
	}
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		size_t len = 0;

		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_LINK) {
			continue;
		}
		if (strcmp(ifa->ifa_name, ifname) != 0) {
			continue;
		}
		// The kernel-supplied AF_LINK sockaddr can be larger than our
		// fixed struct (56 vs 54 bytes on 64-bit FreeBSD). Clamp the copy
		// to sizeof(*sdl) so we do not overflow it, and cap sdl_len to the
		// bytes we actually hold so rt_add does not later over-read it.
		len = ifa->ifa_addr->sa_len;
		if (len > sizeof(*sdl)) {
			len = sizeof(*sdl);
		}
		memcpy(sdl, ifa->ifa_addr, len);
		sdl->sdl_len = (u_char)len;
		found = 1;
		break;
	}
	freeifaddrs(ifap);

	return found ? 0 : -1;
}

static void sin_init(struct sockaddr_in *sin, in_addr_t addr) {
	memset(sin, 0, sizeof(*sin));
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = addr;
}

// configure_network: Configures vtnet0 with the address from the urunit
// configuration and installs the default route. If the gateway is not in the
// interface subnet (e.g. Kubernetes CNI setups), a host route to the gateway
// through the interface is added first.
//
// Arguments:
// 1. net:	The network configuration (IP, gateway, mask)
//
// Return value:
// On success 0 is returned. Otherwise a non-zero value is returned.
int configure_network(struct net_config *net) {
	struct in_aliasreq ifra;
	struct ifreq ifr;
	struct in_addr ip, mask, gw;
	int sock;
	int ret = 0;

	if (net == NULL || net->ip == NULL || net->ip[0] == '\0') {
		DEBUG_PRINT("No network configuration\n");
		return 0;
	}

	ret = inet_pton(AF_INET, net->ip, &ip);
	if (ret != 1) {
		fprintf(stderr, "Invalid IP address %s\n", net->ip);
		return 1;
	}
	if (net->mask == NULL || net->mask[0] == '\0' ||
	    inet_pton(AF_INET, net->mask, &mask) != 1) {
		DEBUG_PRINTF("Invalid or empty netmask, using %s\n", DEFAULT_MASK);
		inet_pton(AF_INET, DEFAULT_MASK, &mask);
	}

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		return 1;
	}

	memset(&ifra, 0, sizeof(ifra));
	strlcpy(ifra.ifra_name, VTNET_IF, sizeof(ifra.ifra_name));
	sin_init(&ifra.ifra_addr, ip.s_addr);
	sin_init(&ifra.ifra_mask, mask.s_addr);
	sin_init(&ifra.ifra_broadaddr, (ip.s_addr & mask.s_addr) | ~mask.s_addr);
	DEBUG_PRINTF("Setting %s address %s mask %s\n", VTNET_IF, net->ip, inet_ntoa(mask));
	ret = ioctl(sock, SIOCAIFADDR, &ifra);
	if (ret < 0) {
		perror("SIOCAIFADDR");
		close(sock);
		return 1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, VTNET_IF, sizeof(ifr.ifr_name));
	ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
	if (ret == 0) {
		ifr.ifr_flags |= IFF_UP;
		ret = ioctl(sock, SIOCSIFFLAGS, &ifr);
		if (ret < 0) {
			perror("SIOCSIFFLAGS");
			ret = 1;
		}
	} else {
		perror("SIOCGIFFLAGS");
		ret = 1;
	}
	close(sock);

	if (net->gateway == NULL || net->gateway[0] == '\0') {
		DEBUG_PRINT("No gateway, skipping default route\n");
		return ret;
	}
	if (inet_pton(AF_INET, net->gateway, &gw) != 1) {
		fprintf(stderr, "Invalid gateway address %s\n", net->gateway);
		return 1;
	}

	if ((gw.s_addr & mask.s_addr) != (ip.s_addr & mask.s_addr)) {
		// The gateway is not directly reachable through the subnet:
		// add a host route to it through the interface (link address).
		struct sockaddr_in dst;
		struct sockaddr_dl sdl;

		DEBUG_PRINTF("Gateway %s is outside the subnet, adding a host route\n", net->gateway);
		if (get_link_addr(VTNET_IF, &sdl) != 0) {
			fprintf(stderr, "Could not find the link address of %s\n", VTNET_IF);
			return 1;
		}
		sin_init(&dst, gw.s_addr);
		if (rt_add((struct sockaddr *)&dst, (struct sockaddr *)&sdl, NULL,
			   RTF_UP | RTF_HOST | RTF_STATIC) != 0) {
			return 1;
		}
	}

	{
		struct sockaddr_in dst, gateway, netmask;

		DEBUG_PRINTF("Setting default route via %s\n", net->gateway);
		sin_init(&dst, INADDR_ANY);
		sin_init(&gateway, gw.s_addr);
		sin_init(&netmask, INADDR_ANY);
		if (rt_add((struct sockaddr *)&dst, (struct sockaddr *)&gateway,
			   (struct sockaddr *)&netmask,
			   RTF_UP | RTF_GATEWAY | RTF_STATIC) != 0) {
			return 1;
		}
	}

	return ret;
}

// set_default_route: On FreeBSD the default route is installed by
// configure_network (the gateway is part of the urunit configuration).
//
// Return value:
// It always returns 0.
int set_default_route(void) {
	return 0;
}

// unmount_external: Unmounts all block based filesystems except the root.
void unmount_external(void) {
	struct statfs *mntbuf = NULL;
	int count = 0;
	int i = 0;
	int ret = 0;

	count = getmntinfo(&mntbuf, MNT_NOWAIT);
	if (count <= 0) {
		perror("getmntinfo");
		return;
	}
	// Walk backwards so that nested mounts go first.
	for (i = count - 1; i >= 0; i--) {
		const char *type = mntbuf[i].f_fstypename;
		const char *path = mntbuf[i].f_mntonname;

		if (strcmp(path, "/") == 0) {
			continue;
		}
		if (strcmp(type, "ufs") == 0 || strcmp(type, "ext2fs") == 0 ||
		    strcmp(type, "msdosfs") == 0 || strcmp(type, "cd9660") == 0 ||
		    is_block_fs(type) || is_network_fs(type) || is_cloud_storage_fs(type)) {
			DEBUG_PRINTF("Trying to unmount %s (%s)\n", path, type);
			ret = unmount(path, MNT_FORCE);
			if (ret != 0) {
				perror("unmount");
			}
		}
	}
}

// set_subreaper: PID 1 is the reaper of the system by default; for any other
// PID acquire the reaper role of our subtree.
int set_subreaper(void) {
	int ret;

	ret = procctl(P_PID, getpid(), PROC_REAP_ACQUIRE, NULL);
	if (ret < 0) {
		if (errno == EBUSY) {
			return 0;
		}
		return -1;
	}

	return 0;
}

// request_reboot: Resets the VM. Firecracker terminates when the guest
// resets; QEMU does the same when started with -no-reboot.
void request_reboot(void) {
	sync();
	reboot(RB_AUTOBOOT);
}
