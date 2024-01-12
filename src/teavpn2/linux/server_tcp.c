// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include <teavpn2/server.h>
#include "net.h"
#include "server_tcp.h"

static int init_socket(struct srv_ctx_tcp *ctx)
{
	struct sockaddr_storage *addr = &ctx->bind_addr;
	struct srv_cfg_sock *sock = &ctx->cfg->sock;
	char buf[STR_IP_PORT_LEN];
	socklen_t len;
	int ret, fd;

	ret = str_to_sockaddr(addr, sock->bind_addr, sock->bind_port);
	if (ret) {
		pr_err("Invalid bind address %s (port = %hu)", sock->bind_addr, sock->bind_port);
		return ret;
	}

	fd = __sys_socket(addr->ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		pr_err("socket(): %s", strerror(-fd));
		return fd;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
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

static int destroy_socket(struct srv_ctx_tcp *ctx)
{
	if (ctx->tcp_fd >= 0) {
		pr_debug("Closing TCP fd (%d)", ctx->tcp_fd);
		close_fd(&ctx->tcp_fd);
	}

	return 0;
}

static int init_ctx(struct srv_ctx_tcp *ctx)
{
	struct srv_cfg_sock *sock = &ctx->cfg->sock;
	struct srv_cfg_sys *sys = &ctx->cfg->sys;
	struct srv_cfg_net *net = &ctx->cfg->net;
	uint32_t i;
	int ret;

	ret = install_signal_stop_handler(&ctx->stop);
	if (ret < 0)
		return ret;

	ret = init_socket(ctx);
	if (ret < 0)
		return ret;

	ctx->workers = calloc(sys->max_thread, sizeof(*ctx->workers));
	if (!ctx->workers) {
		ret = -ENOMEM;
		goto err_socket;
	}

	ctx->tun_fds = calloc(sys->max_thread, sizeof(*ctx->tun_fds));
	if (!ctx->tun_fds) {
		ret = -ENOMEM;
		goto err_workers;
	}

	ret = mutex_init(&ctx->clients_lock);
	if (ret < 0)
		goto err_tun_fds;

	pr_debug("Allocating %u client slots", sock->max_conn);
	ctx->clients = calloc(sock->max_conn, sizeof(*ctx->clients));
	if (!ctx->clients) {
		ret = -ENOMEM;
		goto err_clients_lock;
	}

	for (i = 0; i < sys->max_thread; i++) {
		int tun_fd;

		tun_fd = tun_alloc(net->dev, IFF_TUN | IFF_MULTI_QUEUE);
		if (tun_fd < 0) {
			pr_err("tun_alloc(): %s", strerror(-tun_fd));
			ret = tun_fd;
			goto err_tun_fds_close;
		}

		pr_debug("Created TUN fd (%d)", tun_fd);
		ctx->workers[i].ctx = ctx;
		ctx->workers[i].tid = i;
		ctx->tun_fds[i] = tun_fd;
	}

	for (i = 0; i < sock->max_conn; i++)
		ctx->clients[i].fd = -1;

	return 0;

err_tun_fds_close:
	while (i--)
		__sys_close(ctx->tun_fds[i]);
err_clients_lock:
	mutex_destroy(&ctx->clients_lock);
err_tun_fds:
	free(ctx->tun_fds);
err_workers:
	free(ctx->workers);
err_socket:
	destroy_socket(ctx);
	return ret;
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
	if (ctx->clients) {
		mutex_destroy(&ctx->clients_lock);
		free(ctx->clients);
	}
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
		return ret;

	switch (ret) {
	case EVT_EPOLL:
		ret = run_server_tcp_epoll(&ctx);
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}

	destroy_ctx(&ctx);
	return ret;
}

struct client_tcp *tcp_client_get(struct srv_ctx_tcp *ctx)
{
	uint16_t max_conn = ctx->cfg->sock.max_conn;
	struct client_tcp *clients = ctx->clients;
	struct client_tcp *ret = NULL;
	uint16_t i;

	mutex_lock(&ctx->clients_lock);
	for (i = 0; i < max_conn; i++) {
		if (clients[i].fd < 0) {
			ret = &clients[i];
			break;
		}
	}
	mutex_unlock(&ctx->clients_lock);

	return ret;
}

void tcp_client_put(struct srv_ctx_tcp *ctx, struct client_tcp *client)
{
	if (client->fd >= 0) {
		pr_debug("Closing client fd (%d) (src=%s)", client->fd, addr_to_str_pt(&client->src));
		__sys_close(client->fd);
	}

	mutex_lock(&ctx->clients_lock);
	memset(client, 0, sizeof(*client));
	client->fd = -1;
	mutex_unlock(&ctx->clients_lock);
}

static int server_handle_client_disconnect(struct srv_wrk_tcp *wrk,
					   struct client_tcp *cl)
{
	pr_info("Client %s disconnected (fd = %d)", addr_to_str_pt(&cl->src), cl->fd);
	tcp_client_put(wrk->ctx, cl);
	return 0;
}

static int handle_client(struct srv_wrk_tcp *wrk, struct client_tcp *client)
{
	client->cpkt_len = 0;

	return 0;
}

static int server_verify_packet(struct client_tcp *client)
{
	uint16_t total_len = client->cpkt_len;
	struct pkt *pkt = &client->cpkt;
	uint16_t expected_len;
	uint16_t pkt_len;

	if (unlikely(total_len < sizeof(pkt->hdr)))
		return -EAGAIN;

	pkt_len = ntohs(pkt->hdr.len);
	expected_len = pkt_len + sizeof(pkt->hdr);
	if (unlikely(expected_len > sizeof(*pkt))) {
		pr_err("Client %s sent invalid packet length (%hu)\n", addr_to_str_pt(&client->src), pkt_len);
		return -EINVAL;
	}

	if (unlikely(total_len < expected_len))
		return -EAGAIN;

	return 0;
}

int server_tcp_handle_client(struct srv_wrk_tcp *wrk, struct client_tcp *client)
{
	int err = 0;
	ssize_t ret;
	size_t len;
	char *buf;

	buf = ((char *)&client->cpkt) + client->cpkt_len;
	len = sizeof(client->cpkt) - client->cpkt_len;
	ret = __sys_recv(client->fd, buf, len, MSG_DONTWAIT);
	if (unlikely(ret < 0)) {

		if (ret == -EAGAIN)
			return 0;

		/*
		 * recv() error.
		 */
		pr_err("recv(): %s", strerror((int)-ret));
		err = (int)-ret;
		goto out_dc;
	}

	if (unlikely(ret == 0)) {
		/*
		 * The client closed the connection.
		 */
		goto out_dc;
	}

	client->cpkt_len += (uint16_t)ret;

	err = server_verify_packet(client);
	if (unlikely(err == -EINVAL)) {
		/*
		 * The client sent an invalid packet.
		 */
		goto out_dc;
	}

	if (ret == -EINPROGRESS)
		return 0;

	return handle_client(wrk, client);

out_dc:
	server_handle_client_disconnect(wrk, client);
	return err;
}
