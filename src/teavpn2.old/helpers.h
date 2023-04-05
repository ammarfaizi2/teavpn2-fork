// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef TEAVPN2__HELPERS_H
#define TEAVPN2__HELPERS_H

#include <arpa/inet.h>
#include <errno.h>

int str_to_sockaddr(const char *addr_str, uint16_t port,
		    struct sockaddr_storage *addr);

#endif /* #ifndef TEAVPN2__HELPERS_H */
