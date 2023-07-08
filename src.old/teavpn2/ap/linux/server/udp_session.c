// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#include <teavpn2/common.h>
#include <teavpn2/server.h>
#include <teavpn2/helpers.h>
#include <teavpn2/ap/linux/server.h>

__cold int init_server_udp_sessions(struct udp_sess **sessions_p, uint16_t n)
{
	struct udp_sess *sessions;
	size_t size;

	size = sizeof(*sessions) * n;
	sessions = malloc(size);
	if (!sessions)
		return -ENOMEM;

	memset(sessions, 0, size);
	*sessions_p = sessions;
	return 0;
}

__cold void destroy_server_udp_sessions(struct udp_sess *sessions)
{
	free(sessions);
}
