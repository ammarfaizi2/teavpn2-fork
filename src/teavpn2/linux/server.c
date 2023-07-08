// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include <teavpn2/server.h>

__cold int select_server_event_loop(struct srv_cfg *cfg)
{
	const char *ev = cfg->sock.event_loop;

	if (!strcmp(ev, "epoll")) {
		pr_info("Using epoll as event loop");
		return EVT_EPOLL;
	} else if (!strcmp(ev, "io_uring")) {
		pr_err("event_loop=io_uring is currently not supported");
		return -EOPNOTSUPP;
	}

	pr_err("Invalid event loop: %s (valid values: epoll, io_uring)", ev);
	return -EINVAL;
}

int run_server_app(struct srv_cfg *cfg)
{
	switch (cfg->sock.type) {
	case SOCK_TYPE_UDP:
		return run_server_udp(cfg);
		break;
	case SOCK_TYPE_TCP:
		pr_err("TCP socket is currently not supported!");
		return -EPROTONOSUPPORT;
	default:
		pr_err("Invalid socket type: %hhu", cfg->sock.type);
		return -EINVAL;
	}
}
