// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include <sys/epoll.h>
#include <teavpn2/server.h>

static int server_tcp_init_epoll(struct srv_ctx_tcp *ctx)
{
	struct srv_cfg_sys *sys = &ctx->cfg->sys;
	uint8_t i;
	int fd;

	for (i = 0; i < sys->max_thread; i++)
		ctx->workers[i].epoll_fd = -1;

	for (i = 0; i < sys->max_thread; i++) {
		fd = __sys_epoll_create(256);
		if (fd < 0) {
			pr_err("epoll_create(): %s", strerror(-fd));
			return fd;
		}

		pr_debug("Created epoll fd (%d)", fd);
		ctx->workers[i].epoll_fd = fd;
	}

	return 0;
}

static void close_all_epoll_fds(struct srv_ctx_tcp *ctx)
{
	struct srv_cfg_sys *sys = &ctx->cfg->sys;
	uint8_t i;

	for (i = 0; i < sys->max_thread; i++) {
		if (ctx->workers[i].epoll_fd < 0)
			continue;

		pr_debug("Closing epoll fd (%d)", ctx->workers[i].epoll_fd);
		close_fd(&ctx->workers[i].epoll_fd);
	}
}

static void server_tcp_destroy_epoll(struct srv_ctx_tcp *ctx)
{
	close_all_epoll_fds(ctx);
}

static int server_tcp_run_event_loop_epoll(struct srv_ctx_tcp *ctx)
{
	return 0;
}

int run_server_tcp_epoll(struct srv_ctx_tcp *ctx)
{
	int ret;

	ret = server_tcp_init_epoll(ctx);
	if (ret < 0)
		goto out;

	ret = server_tcp_run_event_loop_epoll(ctx);
out:
	server_tcp_destroy_epoll(ctx);
	return 0;
}
