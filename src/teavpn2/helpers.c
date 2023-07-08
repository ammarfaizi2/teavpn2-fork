// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include <string.h>
#include <teavpn2/common.h>
#include <teavpn2/helpers.h>

int str_to_sockaddr(struct sockaddr_storage *ss, const char *addr,
		    uint16_t port)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
	struct sockaddr_in *sin = (struct sockaddr_in *)ss;
	int ret;

	ret = inet_pton(AF_INET6, addr, &sin6->sin6_addr);
	if (ret == 1) {
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(port);
		return 0;
	}

	ret = inet_pton(AF_INET, addr, &sin->sin_addr);
	if (ret == 1) {
		sin->sin_family = AF_INET;
		sin->sin_port = htons(port);
		return 0;
	}

	return -EINVAL;
}

int sockaddr_to_str(char *addr, const struct sockaddr_storage *ss)
{
	int family = ss->ss_family;
	const void *raw_addr;
	uint16_t port;

	if (family != AF_INET && family != AF_INET6)
		return -EINVAL;

	if (family == AF_INET6) {
		struct sockaddr_in6 *in6 = (void *)ss;
		*addr++ = '[';
		port = in6->sin6_port;
		raw_addr = &in6->sin6_addr;
	} else {
		struct sockaddr_in *in = (void *)ss;
		port = in->sin_port;
		raw_addr = &in->sin_addr;
	}

	if (!inet_ntop(family, raw_addr, addr, INET6_ADDRSTRLEN))
		return -errno;

	addr += strlen(addr);
	if (family == AF_INET6)
		*addr++ = ']';

	*addr++ = ':';
	sprintf(addr, "%hu", ntohs(port));
	return 0;
}

bool teavpn_check_uname(const char *u)
{
	size_t len = 0;

	while (1) {
		if (u[len] == '\0')
			break;

		if (!(isalnum(u[len]) || u[len] == '_' || u[len] == '-'))
			return false;

		if (++len > 255)
			return false;
	}

	return (len >= 3);
}

__cold int parse_socket_type(const char *str, uint8_t *type)
{
	char tmp[4];
	size_t i;

	/*
	 * Convert to lower case. Don't use tolower() to avoid
	 * function call. Keep it small.
	 */
	for (i = 0; i < (sizeof(tmp) - 1); i++) {
		if (!str[i])
			break;
		tmp[i] = str[i] | 0x20;
	}
	tmp[i] = '\0';

	if (!strcmp(tmp, "tcp")) {
		*type = SOCK_TYPE_TCP;
		return 0;
	} else if (!strcmp(tmp, "udp")) {
		*type = SOCK_TYPE_UDP;
		return 0;
	}

	fprintf(stderr, "Invalid socket type: %s (valid: tcp, udp)\n", str);
	return -EINVAL;
}
