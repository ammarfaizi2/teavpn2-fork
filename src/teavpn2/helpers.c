// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include <teavpn2/helpers.h>
#include <string.h>
#include <errno.h>

int str_to_sockaddr(const char *addr_str, uint16_t port,
		    struct sockaddr_storage *addr)
{
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
	struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
	int ret;

	memset(addr, 0, sizeof(*addr));
	ret = inet_pton(AF_INET6, addr_str, &addr6->sin6_addr);
	if (ret == 1) {
		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = htons(port);
		return 0;
	}

	ret = inet_pton(AF_INET, addr_str, &addr4->sin_addr);
	if (ret == 1) {
		addr4->sin_family = AF_INET;
		addr4->sin_port = htons(port);
		return 0;
	}

	return -EINVAL;
}
