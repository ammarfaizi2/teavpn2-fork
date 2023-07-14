// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include <teavpn2/server.h>
#include "net.h"

static int server_tcp_init_sock(struct srv_ctx_tcp *ctx)
{
	struct sockaddr_storage *addr = &ctx->bind_addr;
	struct srv_cfg_sock *sock = &ctx->cfg->sock;
	char buf[STR_IP_PORT_LEN];
	socklen_t len;
	int ret, fd;

	ret = str_to_sockaddr(addr, sock->bind_addr, sock->bind_port);
	if (ret) {
		printf("Invalid bind address %s (port = %hu)", sock->bind_addr,
		       sock->bind_port);
		return ret;
	}

	fd = __sys_socket(addr->ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		pr_err("socket(): %s", strerror(-fd));
		return fd;
	}

	pr_debug("Created TCP socket fd (%d)", fd);

	len = get_sock_family_len(addr->ss_family);
	ret = __sys_bind(fd, (struct sockaddr *)addr, len);
	if (ret < 0) {
		pr_err("bind(): %s", strerror(-ret));
		goto out_err;
	}

	ret = __sys_listen(fd, sock->backlog);
	if (ret < 0) {
		pr_err("listen(): %s", strerror(-ret));
		goto out_err;
	}

	ctx->tcp_fd = fd;
	sockaddr_to_str(buf, addr);
	pr_info("Listening on %s", buf);
	return 0;

out_err:
	close(fd);
	return ret;
}

static int init_ctx(struct srv_ctx_tcp *ctx)
{
	struct srv_cfg_sys *sys = &ctx->cfg->sys;
	struct srv_cfg_net *net = &ctx->cfg->net;
	uint8_t i;
	int ret;

	ret = install_signal_stop_handler(&ctx->stop);
	if (ret < 0)
		return ret;

	ret = server_tcp_init_sock(ctx);
	if (ret < 0)
		return ret;

	ctx->workers = calloc(sys->max_thread, sizeof(*ctx->workers));
	if (!ctx->workers)
		return -ENOMEM;

	ctx->tun_fds = calloc(sys->max_thread, sizeof(*ctx->tun_fds));
	if (!ctx->tun_fds)
		return -ENOMEM;

	for (i = 0; i < sys->max_thread; i++) {
		int tun_fd;

		tun_fd = tun_alloc(net->dev, IFF_TUN | IFF_MULTI_QUEUE);
		if (tun_fd < 0)
			return tun_fd;

		pr_debug("Created TUN fd (%d)", tun_fd);
		ctx->workers[i].ctx = ctx;
		ctx->workers[i].tid = i;
		ctx->tun_fds[i] = tun_fd;
	}

	return 0;
}

static void destroy_ctx(struct srv_ctx_tcp *ctx)
{
	if (ctx->tcp_fd >= 0) {
		pr_debug("Closing TCP fd (%d)", ctx->tcp_fd);
		close_fd(&ctx->tcp_fd);
	}

	if (ctx->tun_fds) {
		uint8_t i;

		for (i = 0; i < ctx->cfg->sys.max_thread; i++) {
			int fd = ctx->tun_fds[i];
			pr_debug("Closing TUN fd (%d)...", fd);
			__sys_close(fd);
		}
	}

	free(ctx->workers);
	free(ctx->tun_fds);
}

int run_server_tcp(struct srv_cfg *cfg)
{
	struct srv_ctx_tcp ctx;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.cfg = cfg;
	ctx.tcp_fd = -1;

	ret = select_server_event_loop(cfg);
	if (ret < 0)
		goto out;

	ret = init_ctx(&ctx);
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
	destroy_ctx(&ctx);
	return ret;
}
