
#include <teavpn2/ap/linux/net.h>
#include <teavpn2/common.h>
#include <linux/if_tun.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>

static const char *net_tun_path[] = {
	"/dev/net/tun",
	"/dev/tun",
	NULL,
};

static int open_net_tun(void)
{
	size_t i;
	int ret;

	for (i = 0; net_tun_path[i] != NULL; i++) {
		ret = open(net_tun_path[i], O_RDWR);
		if (ret >= 0)
			return ret;
	}

	ret = errno;
	pr_err("open_net_tun(): " PRERF, PREAR(ret));
	return -ret;
}

/*
 * https://www.kernel.org/doc/Documentation/networking/tuntap.txt
 *
 * Flags: IFF_TUN   - TUN device (no Ethernet headers)
 *        IFF_TAP   - TAP device
 *
 *        IFF_NO_PI - Do not provide packet information
 *        IFF_MULTI_QUEUE - Create a queue of multiqueue device
 *
 */
int tun_alloc(const char *dev, short flags)
{
	struct ifreq ifr;
	int ret, fd;

	if (!dev || *dev == '\0') {
		pr_err("tun_alloc(): dev cannot be empty");
		return -EINVAL;
	}

	fd = open_net_tun();
	if (unlikely(fd < 0))
		return fd;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	ifr.ifr_flags = flags;

	ret = ioctl(fd, TUNSETIFF, &ifr);
	if (ret < 0) {
		ret = errno;
		pr_err("ioctl(%d, TUNSETIFF, &ifr): " PRERF, fd, PREAR(ret));
		close(fd);
		return -ret;
	}

	return fd;
}
