// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef TEAVPN2__HELPERS_H
#define TEAVPN2__HELPERS_H

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/*
 * Convert string to sockaddr.
 *
 * @param ss	Pointer to sockaddr_storage.
 * @param addr	IP address (can be IPv4 or IPv6).
 * @param port	Port number.
 * @return	Return 0 on success, otherwise return -EINVAL.
 */
extern int str_to_sockaddr(struct sockaddr_storage *ss, const char *addr,
			   uint16_t port);

/*
 * Validate username. Username must be between 3 to 255 characters, and
 * only alphanumeric, underscore, and dash are allowed.
 *
 * @param u	Username.
 * @return	Return true if the username is valid, otherwise return false.
 */
extern bool teavpn_check_uname(const char *u);


enum {
	SOCK_TYPE_TCP,
	SOCK_TYPE_UDP,
};

/*
 * Parse socket type. Parse the socket type from string to integer.
 * The string must be either "tcp" or "udp" (case insensitive).
 *
 * If the string is "tcp", then the integer will be set to SOCK_TYPE_TCP.
 * If the string is "udp", then the integer will be set to SOCK_TYPE_UDP.
 *
 * @param str	String to be parsed.
 * @param type	Pointer to uint8_t.
 * @return	Return 0 on success, otherwise return -EINVAL.
 */
int parse_socket_type(const char *str, uint8_t *type);

/*
 * Just a wrapper to sane strncpy() call.
 *
 * @param dst	Pointer to destination buffer.
 * @param src	Pointer to source buffer.
 * @param len	Length of destination buffer.
 * @return	Return pointer to destination buffer.
 * @note	This function will always null-terminate the destination buffer.
 */
static inline char *strecpy(char *__restrict__ dst,
			    const char *__restrict__ src, size_t len)
{
	char *ret;

	ret = strncpy(dst, src, len - 1);
	dst[len - 1] = '\0';
	return ret;
}

#endif /* #ifndef TEAVPN2__HELPERS_H */
