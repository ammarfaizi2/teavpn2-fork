// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include <sys/epoll.h>
#include <teavpn2/server.h>

static int server_tcp_init_epoll(struct srv_ctx_tcp *ctx)
{
	int fd;

	fd = epoll_create(256);
	if (fd < 0) {
		fd = errno;
		pr_err("epoll_create(): %s", strerror(fd));
		return -fd;
	}

	ctx->epoll_fd = fd;
	pr_debug("Created epoll fd (%d)", fd);
	return 0;
}

static void server_tcp_destroy_epoll(struct srv_ctx_tcp *ctx)
{
	if (ctx->epoll_fd >= 0) {
		pr_debug("Closing epoll fd (%d)", ctx->epoll_fd);
		close_fd(&ctx->epoll_fd);
	}
}

int run_server_tcp_epoll(struct srv_ctx_tcp *ctx)
{
	int ret;

	ctx->epoll_fd = -1;

	ret = server_tcp_init_epoll(ctx);
	if (ret < 0)
		goto out;

out:
	server_tcp_destroy_epoll(ctx);
	return 0;
}
