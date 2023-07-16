
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <teavpn2/common.h>
#include <teavpn2/helpers.h>

#include "net.h"

static const char *net_tun_path[] = {
	"/dev/net/tun",
	"/dev/tun",
	NULL,
};

static int open_dev_tun(void)
{
	size_t i;
	int ret;

	for (i = 0; net_tun_path[i] != NULL; i++) {
		ret = __sys_open(net_tun_path[i], O_RDWR, 0);
		if (ret >= 0)
			return ret;
	}

	pr_err("open_dev_tun(): %s", strerror(-ret));
	return ret;
}


/*
 * https://www.kernel.org/doc/Documentation/networking/tuntap.txt
 *
 * Flags: IFF_TUN   - TUN device (no Ethernet headers)
 *        IFF_TAP   - TAP device
 *
 *        IFF_NO_PI - Do not provide packet information
 *        IFF_MULTI_QUEUE - Create a queue of multiqueue device
 */
__cold int tun_alloc(const char *dev, short flags)
{
	struct ifreq ifr;
	int fd, err;

	if (dev == NULL || dev[0] == '\0') {
		pr_err("tun_alloc(): dev cannot be empty");
		return -EINVAL;
	}

	fd = open_dev_tun();
	if (fd < 0)
		return fd;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	ifr.ifr_flags = flags;

	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		err = errno;
		__sys_close(fd);
		pr_err("ioctl(%d, TUNSETIFF, &ifr): %s", fd, strerror(err));
		return -err;
	}

	return fd;
}
