// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#include <signal.h>
#include <sys/epoll.h>
#include <teavpn2/server.h>

static int epoll_add(int epoll_fd, int fd, uint32_t events,
		     union epoll_data data)
{
	struct epoll_event ev = {
		.events = events,
		.data = data,
	};
	int ret;

	ret = __sys_epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
	if (unlikely(ret < 0)) {
		pr_err("epoll_ctl(): %s", strerror(-ret));
		return ret;
	}

	return 0;
}

static int epoll_del(int epoll_fd, int fd)
{
	int ret;

	ret = __sys_epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
	if (unlikely(ret < 0)) {
		pr_err("epoll_ctl(): %s", strerror(-ret));
		return ret;
	}

	return 0;
}

__hot static int poll_for_events(struct srv_wrk_tcp *wrk)
{
	int ret;

	ret = __sys_epoll_wait(wrk->epoll_fd, wrk->events, 256, wrk->ep_timeout);
	if (unlikely(ret == -EINTR))
		return 0;

	return ret;
}

static int handle_accept_error(int err)
{
	if (err == -EAGAIN || err == -EWOULDBLOCK)
		return 0;

	if (err == -EMFILE || err == -ENFILE) {
		pr_err("Cannot accept new connection: %s", strerror(-err));
		return 0;
	}

	pr_err("accept(): %s", strerror(-err));
	return err;
}

static int handle_new_client(struct srv_wrk_tcp *tcp, uint64_t idx)
{
	int *fd_table = tcp->ctx->fd_table;
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);
	int ret, fd;

	fd = __sys_accept(tcp->ctx->tcp_fd, (struct sockaddr *)&addr, &len);
	if (unlikely(fd < 0))
		return handle_accept_error(fd);

	pr_debug("Accepted new connection (fd = %d)", fd);
	return 0;
}

__hot static int handle_event(struct srv_wrk_tcp *tcp, struct epoll_event *ev)
{
	uint64_t data = ev->data.u64;
	size_t client_idx_start;

	if (data == 0) {
		/*
		 * Handle new connection.
		 */
		return 0;
	}

	client_idx_start = tcp->ctx->cfg->sys.max_thread + 1;
	if (data >= client_idx_start) {
		/*
		 * Handle client.
		 */
		return 0;
	}

	/*
	 * Handle tun.
	 */
	return 0;
}

__hot static int run_event_loop(struct srv_wrk_tcp *wrk)
{
	int ret, i;

	ret = poll_for_events(wrk);
	if (unlikely(ret < 0)) {
		pr_err("epoll_wait(): %s", strerror(-ret));
		return ret;
	}

	for (i = 0; i < ret; i++) {
		struct epoll_event *ev = &wrk->events[i];
	}

	return 0;
}

__cold static void wait_for_all_threads_ready(struct srv_wrk_tcp *wrk)
{
	struct srv_ctx_tcp *ctx = wrk->ctx;
	uint8_t nr;

	if (wrk->tid > 0)
		pr_info("Worker %hhu is ready", wrk->tid);

	while (1) {
		nr = atomic_load(&ctx->online_workers);
		if (nr == ctx->cfg->sys.max_thread)
			break;
		if (ctx->stop)
			return;

		usleep(1000);
	}

	if (wrk->tid == 0)
		pr_info("All workers are ready");
}

static void *run_worker(void *arg)
{
	struct srv_wrk_tcp *wrk = arg;
	struct srv_ctx_tcp *ctx = wrk->ctx;
	int ret;

	atomic_fetch_add(&ctx->online_workers, 1u);
	wait_for_all_threads_ready(wrk);

	while (!ctx->stop) {
		ret = run_event_loop(wrk);
		if (unlikely(ret < 0)) {
			pr_err("run_event_loop(): %s", strerror(-ret));
			break;
		}
	}

	atomic_fetch_sub(&ctx->online_workers, 1u);
	pr_info("Thread %hhu is exiting...", wrk->tid);
	return NULL;
}

static int init_worker(struct srv_wrk_tcp *wrk)
{
	union epoll_data ed;
	int ret, tun_fd;

	ret = __sys_epoll_create(32);
	if (ret < 0) {
		pr_err("epoll_create(): %s", strerror(-ret));
		return ret;
	}

	pr_debug("Created epoll fd (%d)", ret);
	wrk->epoll_fd = ret;
	wrk->ep_timeout = 5000;

	ed.u64 = 1u + wrk->tid;
	tun_fd = wrk->ctx->tun_fds[wrk->tid];
	ret = epoll_add(wrk->epoll_fd, tun_fd, EPOLLIN, ed);
	if (ret < 0)
		goto err;

	/*
	 * Only spawn a worker thread if the thread ID is
	 * greater than 0 because the thread ID 0 is
	 * expected to be the main thread.
	 *
	 * Also, the mail thread is responsible for
	 * accepting new connections.
	 */
	if (wrk->tid == 0) {
		ed.u64 = 0;
		ret = epoll_add(wrk->epoll_fd, wrk->ctx->tcp_fd, EPOLLIN, ed);
		if (ret < 0)
			goto err;

		return ret;
	}

	pr_debug("Spawning worker thread (%hhu)", wrk->tid);
	ret = pthread_create(&wrk->thread, NULL, run_worker, wrk);
	if (ret) {
		pr_err("pthread_create(): %s", strerror(ret));
		ret = -ret;
		goto err;
	}

	return 0;

err:
	close_fd(&wrk->epoll_fd);
	return ret;
}

static int init_workers(struct srv_ctx_tcp *ctx)
{
	struct srv_cfg_sys *sys = &ctx->cfg->sys;
	uint8_t i;
	int ret;

	/*
	 * Note that the epoll_fd is also used as an indicator
	 * whether the worker thread is running or not. If the
	 * epoll fd is -1, then the worker thread is not running.
	 */
	for (i = 0; i < sys->max_thread; i++)
		ctx->workers[i].epoll_fd = -1;

	for (i = 0; i < sys->max_thread; i++) {
		ret = init_worker(&ctx->workers[i]);
		if (ret < 0) {
			pr_err("init_worker(&workers[%hhu]): %s", i, strerror(-ret));
			return ret;
		}
	}

	return 0;
}

static void join_all_workers(struct srv_ctx_tcp *ctx)
{
	uint8_t i;

	for (i = 0; i < ctx->cfg->sys.max_thread; i++) {
		int ret;

		/*
		 * Note that the epoll_fd is also used as an indicator
		 * whether the worker thread is running or not. If the
		 * epoll fd is -1, then the worker thread is not running.
		 *
		 * Also, if tid == 0, it does not have an LWP, so no need
		 * to join.
		 */
		if (i == 0 || ctx->workers[i].epoll_fd < 0)
			continue;

		pr_debug("Waiting for worker %hhu to exit...", i);
		pthread_kill(ctx->workers[i].thread, SIGINT);
		ret = pthread_join(ctx->workers[i].thread, NULL);
		if (ret)
			pr_err("pthread_join(): %s", strerror(ret));
	}
}

static void close_all_epoll_fds(struct srv_ctx_tcp *ctx)
{
	uint8_t i;

	for (i = 0; i < ctx->cfg->sys.max_thread; i++) {
		if (ctx->workers[i].epoll_fd < 0)
			continue;

		pr_debug("Closing epoll fd (%d)", ctx->workers[i].epoll_fd);
		close_fd(&ctx->workers[i].epoll_fd);
	}
}

static void destroy_workers(struct srv_ctx_tcp *ctx)
{
	/*
	 * Ensure the stop flag is set before waiting for all
	 * workers to stop.
	 */
	ctx->stop = true;
	pr_info("Server is exiting...");
	join_all_workers(ctx);
	close_all_epoll_fds(ctx);
}

int run_server_tcp_epoll(struct srv_ctx_tcp *ctx)
{
	int ret;

	ret = init_workers(ctx);
	if (ret < 0)
		goto out;

	run_worker(&ctx->workers[0]);
out:
	destroy_workers(ctx);
	return 0;
}
