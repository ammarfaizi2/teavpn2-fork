// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#include <stdio.h>
#include <signal.h>
#include <teavpn2/server.h>

static volatile bool *p_stop;

__cold static void handle_signal(int sig)
{
	if (*p_stop)
		return;

	*p_stop = true;
	putchar('\n');
	(void)sig;
}

__cold int install_signal_stop_handler(volatile bool *stop)
{
	struct sigaction act = { .sa_handler = handle_signal };
	int ret;

	pr_debug("Installing signal handler...");

	p_stop = stop;
	ret = sigaction(SIGINT, &act, NULL);
	if (ret < 0)
		goto err;
	ret = sigaction(SIGTERM, &act, NULL);
	if (ret < 0)
		goto err;
	ret = sigaction(SIGHUP, &act, NULL);
	if (ret < 0)
		goto err;
	act.sa_handler = SIG_IGN;
	ret = sigaction(SIGPIPE, &act, NULL);
	if (ret < 0)
		goto err;

	pr_debug("Signal handler successfully installed");
	return 0;

err:
	ret = errno;
	pr_err("sigaction(): %s", strerror(ret));
	return -ret;
}

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
	case SOCK_TYPE_TCP:
		return run_server_tcp(cfg);
	default:
		pr_err("Invalid socket type: %hhu", cfg->sock.type);
		return -EINVAL;
	}
}
