// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include <teavpn2/server.h>

static int server_tcp_init_sock(struct srv_ctx_tcp *ctx)
{
	struct sockaddr_storage *addr = &ctx->bind_addr;
	struct srv_cfg_sock *sock = &ctx->cfg->sock;
	char buf[STR_IP_AND_PORT];
	socklen_t len;
	int ret, fd;

	memset(addr, 0, sizeof(*addr));
	ret = str_to_sockaddr(addr, sock->bind_addr, sock->bind_port);
	if (ret) {
		printf("Invalid bind address %s (port = %hu)", sock->bind_addr,
		       sock->bind_port);
		return ret;
	}

	fd = socket(addr->ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		ret = errno;
		pr_err("socket(): %s", strerror(ret));
		return -ret;
	}

	pr_debug("Created TCP socket fd (%d)", fd);
	if (addr->ss_family == AF_INET)
		len = sizeof(struct sockaddr_in);
	else
		len = sizeof(struct sockaddr_in6);

	ret = bind(fd, (struct sockaddr *)addr, len);
	if (ret < 0) {
		ret = errno;
		pr_err("bind(): %s", strerror(ret));
		goto out_err;
	}

	ret = listen(fd, sock->backlog);
	if (ret < 0) {
		ret = errno;
		pr_err("listen(): %s", strerror(ret));
		goto out_err;
	}

	sockaddr_to_str(buf, addr);
	pr_info("Listening on %s", buf);
	ctx->tcp_fd = fd;
	return 0;

out_err:
	close(fd);
	return -ret;
}

static int server_tcp_init_ctx(struct srv_ctx_tcp *ctx)
{
	int ret;

	ret = server_tcp_init_sock(ctx);
	if (ret < 0)
		return ret;

	return 0;
}

static void server_tcp_destroy_ctx(struct srv_ctx_tcp *ctx)
{
	if (ctx->tcp_fd >= 0) {
		pr_debug("Closing TCP fd (%d)", ctx->tcp_fd);
		close_fd(&ctx->tcp_fd);
	}
}

int run_server_tcp(struct srv_cfg *cfg)
{
	struct srv_ctx_tcp ctx;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.cfg = cfg;
	ctx.epoll_fd = -1;
	ctx.tcp_fd = -1;

	ret = select_server_event_loop(cfg);
	if (ret < 0)
		goto out;

	ret = server_tcp_init_ctx(&ctx);
	if (ret < 0)
		goto out;

	switch (ret) {
	case EVT_EPOLL:
		ret = run_server_tcp_epoll(&ctx);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

out:
	server_tcp_destroy_ctx(&ctx);
	return ret;
}
