// SPDX-License-Identifier: GPL-2.0
/*
 *  src/teavpn2/server/linux/tcp_io_uring.c
 *
 *  TeaVPN2 server core for Linux (io_uring support).
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include "./tcp_common.h"


static int init_iou_cqe_vec(struct iou_cqe_vec **cqe_vec_p)
{
	struct iou_cqe_vec *cqe_vec;

	cqe_vec = al64_malloc(IOUCL_VEC_NUM * sizeof(*cqe_vec));
	if (unlikely(!cqe_vec))
		return -ENOMEM;

	*cqe_vec_p = cqe_vec;
	return 0;
}


static int do_iou_send(struct srv_thread *thread, int fd,
		       struct iou_cqe_vec *cqev, int flags)
{
	int ret;
	struct io_uring_sqe *sqe;
	struct io_uring *ring = &thread->ring;

	sqe = io_uring_get_sqe(ring);
	if (unlikely(!sqe))
		return -EAGAIN;

	io_uring_prep_send(sqe, fd, cqev->raw_pkt, (unsigned)cqev->len, flags);
	io_uring_sqe_set_data(sqe, cqev);

	ret = io_uring_submit(ring);
	if (unlikely(ret < 0)) {
		pr_err("io_uring_submit(): " PRERF, PREAR(-ret));
		return ret;
	}
	return 0;
}


static int do_iou_write(struct srv_thread *thread, int fd,
			struct iou_cqe_vec *cqev)
{
	int ret;
	struct io_uring_sqe *sqe;
	struct io_uring *ring = &thread->ring;

	sqe = io_uring_get_sqe(ring);
	if (unlikely(!sqe))
		return -EAGAIN;

	io_uring_prep_write(sqe, fd, cqev->raw_pkt, (unsigned)cqev->len, 0);
	io_uring_sqe_set_data(sqe, cqev);

	ret = io_uring_submit(ring);
	if (unlikely(ret < 0)) {
		pr_err("io_uring_submit(): " PRERF, PREAR(-ret));
		return ret;
	}
	return 0;
}


static struct iou_cqe_vec *get_iou_cqe_vec(struct srv_thread *thread)
{
	int32_t idx;
	struct iou_cqe_vec *cqev;
	struct tv_stack	*ioucl_stk = &thread->ioucl_stk;

	bt_mutex_lock(&ioucl_stk->lock);
	idx = tv_stack_pop(ioucl_stk);
	bt_mutex_unlock(&ioucl_stk->lock);
	if (unlikely(idx == -1))
		return NULL;

	cqev = &thread->cqe_vec[idx];
	cqev->idx = (uint16_t)idx;
	cqev->vec_type = IOU_CQE_VEC_NOP;
	return cqev;
}


static void put_iou_cqe_vec(struct srv_thread *thread, struct iou_cqe_vec *cqev)
{
	int32_t idx;
	struct tv_stack	*ioucl_stk = &thread->ioucl_stk;

	bt_mutex_lock(&ioucl_stk->lock);
	idx = tv_stack_push(ioucl_stk, cqev->idx);
	bt_mutex_unlock(&ioucl_stk->lock);
	if (likely(idx != -1))
		return;

	panic("Wrong logic: Attempted to push to ioucl_stk when it is full "
	      "(thread=%u)", thread->idx);
}


static int __register_client(struct srv_thread *thread, int32_t idx, int cli_fd,
			     const char *src_ip, uint16_t src_port)
{
	int ret = 0;
	struct client_slot *client;
	struct io_uring_sqe *sqe = NULL;
	struct srv_thread *assignee = NULL;
	struct srv_state *state = thread->state;
	size_t i, recv_len, num_threads = state->cfg->sys.thread;
	uint16_t th_idx = 0; /* Thread index (the assignee). */


	if (num_threads <= 1) {
		/*
		 * We are single threaded.
		 */
		assignee = thread;
		sqe = io_uring_get_sqe(&assignee->ring);
		goto out_reg;
	}


	for (i = 0; i < (num_threads + 1u); i++) {
		/*
		 * We are multi threaded.
		 */
		_Atomic(uint32_t) *tr_as = &state->tr_assign;


		th_idx   = atomic_fetch_add(tr_as, 1) % state->cfg->sys.thread;
		assignee = &state->threads[th_idx];


		/*
		 * Try to get sqe from the assigned thread.
		 *
		 * If it doesn't have free sqe, try again with
		 * different assignee.
		 */
		sqe = io_uring_get_sqe(&assignee->ring);
		if (unlikely(!sqe))
			/*
			 * Try again, check another thread!
			 */
			continue;


		/*
		 * We got a thread with free sqe. Go on!
		 */
		break;
	}



out_reg:
	if (unlikely(!sqe)) {
		/*
		 * We have checked all threads, but couldn't find
		 * free sqe. So we need to drop this client.
		 */
		return -EAGAIN;
	}

	ret = teavpn2_server_tcp_socket_setup(cli_fd, state);
	if (unlikely(ret < 0))
		goto out;

	client = &state->clients[idx];
	recv_len = sizeof(client->raw_pkt);
	io_uring_prep_recv(sqe, cli_fd, client->raw_pkt, recv_len, MSG_WAITALL);
	io_uring_sqe_set_data(sqe, client);


	ret = io_uring_submit(&assignee->ring);
	if (unlikely(ret < 0)) {
		pr_err("io_uring_submit(): " PRERF, PREAR(-ret));
		goto out;
	}


	ret = 0;
	client->cli_fd   = cli_fd;
	client->src_port = src_port;
	sane_strncpy(client->src_ip, src_ip, sizeof(client->src_ip));
	prl_notice(0, "New connection from " PRWIU " (fd=%d) (target_thread=%u)",
		   W_IU(client), cli_fd, th_idx);
out:
	return ret;
}


static int register_client(struct srv_thread *thread, int cli_fd)
{
	int ret = 0;
	int32_t idx;
	uint16_t src_port = 0;
	char src_ip[IPV4_L] = {0};
	struct srv_state *state = thread->state;

	/*
	 * The remote IP and port in big-endian representation.
	 */
	struct sockaddr_in *saddr = &state->acc.addr;
	struct in_addr *sin_addr = &saddr->sin_addr;

	/*
	 * Get the human readable IP address.
	 */
	if (unlikely(!inet_ntop(AF_INET, sin_addr, src_ip, sizeof(src_ip)))) {
		ret = errno;
		pr_err("inet_ntop(): " PRERF, PREAR(ret));
		ret = -ret;
		goto out_close;
	}
	src_ip[sizeof(src_ip) - 1] = '\0';
	src_port = ntohs(saddr->sin_port);


	/*
	 * Lookup for free client slot.
	 */
	bt_mutex_lock(&state->cl_stk.lock);
	idx = tv_stack_pop(&state->cl_stk);
	bt_mutex_unlock(&state->cl_stk.lock);
	if (unlikely(idx == -1)) {
		pr_err("Client slot is full, cannot accept connection from "
		       "%s:%u (thread=%u)", src_ip, src_port, thread->idx);
		ret = -EAGAIN;
		goto out_close;
	}


	/*
	 * Register the client to the client slot array.
	 */
	ret = __register_client(thread, idx, cli_fd, src_ip, src_port);
	if (unlikely(ret)) {
		/*
		 * We need to push back this index,
		 * because this popped `idx` is not
		 * used at the moment.
		 */
		goto out_close_push;
	}
	return 0;


out_close_push:
	bt_mutex_lock(&state->cl_stk.lock);
	tv_stack_push(&state->cl_stk, (uint16_t)idx);
	bt_mutex_unlock(&state->cl_stk.lock);


out_close:
	pr_notice("Closing connection from %s:%u (fd=%d) (thread=%u) Error: "
		  PRERF "...", src_ip, src_port, cli_fd, thread->idx,
		  PREAR(-ret));
	close(cli_fd);
	return ret;
}


static int handle_event_tcp(struct srv_thread *thread, struct io_uring_cqe *cqe)
{
	int ret = 0, cli_fd;
	struct sockaddr *addr;
	struct accept_data *acc;
	struct io_uring_sqe *sqe;
	struct srv_state *state = thread->state;

	cli_fd = (int)cqe->res;
	if (unlikely(cli_fd < 0)) {
		ret = cli_fd;
		goto out_err;
	}

	ret = register_client(thread, cli_fd);
	if (unlikely(ret))
		goto out_err;

out_rearm:
	sqe = io_uring_get_sqe(&thread->ring);
	if (unlikely(!sqe)) {
		pr_emerg("Resource exhausted (thread=%u)", thread->idx);
		panic("io_uring run out of sqe on handle_event_tcp() "
		      "(thread=%u)", thread->idx);
		__builtin_unreachable();
	}

	acc          = &state->acc;
	acc->acc_fd  = -1;
	acc->addrlen = sizeof(acc->addr);
	memset(&acc->addr, 0, sizeof(acc->addr));
	addr = (struct sockaddr *)&acc->addr;
	io_uring_prep_accept(sqe, state->tcp_fd, addr, &acc->addrlen, 0);
	io_uring_sqe_set_data(sqe, UPTR(IOU_CQE_DRC_TCP_ACCEPT));

	ret = io_uring_submit(&thread->ring);
	if (unlikely(ret < 0)) {
		pr_err("io_uring_submit(): " PRERF, PREAR(-ret));
		return ret;
	}
	ret = 0;

	return ret;

out_err:
	if (unlikely(ret == -EAGAIN))
		goto out_rearm;

	/*
	 * Fatal error, stop everything!
	 */
	pr_err("accpet(): " PRERF, PREAR(-ret));
	state->stop = true;
	return ret;
}


static int send_handshake_response(struct srv_thread *thread,
				   struct client_slot *client)
{
	int ret = 0;
	size_t verlen;
	size_t send_len;
	struct iou_cqe_vec *cqev;
	struct tsrv_pkt *srv_pkt;
	struct tsrv_pkt_handshake *pkt_hss;

	cqev = get_iou_cqe_vec(thread);
	if (unlikely(!cqev)) {
		pr_err("Run out of CQE vector on send_handshake_response "
		       "when responding to " PRWIU " (thread=%u)", W_IU(client),
		       thread->idx);
		return -EAGAIN;
	}

	srv_pkt = &cqev->spkt;
	pkt_hss = &srv_pkt->handshake;
	pkt_hss->need_encryption = false;
	pkt_hss->has_min = false;
	pkt_hss->has_max = false;
	pkt_hss->cur.ver = VERSION;
	pkt_hss->cur.patch_lvl = PATCHLEVEL;
	pkt_hss->cur.sub_lvl = SUBLEVEL;
	verlen = sizeof(pkt_hss->cur.extra);
	sane_strncpy(pkt_hss->cur.extra, EXTRAVERSION, verlen);

	srv_pkt->type = TSRV_PKT_HANDSHAKE;
	srv_pkt->pad_len = 0u;
	srv_pkt->length = sizeof(*pkt_hss);
	send_len = TSRV_PKT_MIN_READ + sizeof(*pkt_hss);
	cqev->len = send_len;

	cqev->udata = client;
	cqev->vec_type = IOU_CQE_VEC_TCP_SEND;
	ret = do_iou_send(thread, client->cli_fd, cqev, 0);
	if (unlikely(ret < 0))
		return ret;

	return -EINPROGRESS;
}


static int handle_clpkt_handshake(struct srv_thread *thread,
				  struct client_slot *client, size_t fdata_len)
{
	int ret = 0;
	struct tcli_pkt *cli_pkt = &client->cpkt;
	struct tcli_pkt_handshake *pkt_hsc = &cli_pkt->handshake;

	bt_mutex_lock(&client->lock);
	if (unlikely(client->is_authenticated)) {
		ret = 0;
		goto out;
	}

	if (fdata_len != sizeof(*pkt_hsc)) {
		pr_notice("Got mismatch handshake length from "  PRWIU
			  " (expected length = %zu; actual length = %zu) "
			  " (thread=%u)",
			  W_IU(client), sizeof(*pkt_hsc), fdata_len,
			  thread->idx);
		ret = -EBADMSG;
		goto out;
	}

	/* For C string print safety. */
	pkt_hsc->cur.extra[sizeof(pkt_hsc->cur.extra) - 1] = '\0';
	pr_notice("Got protocol handshake from " PRWIU
		  " (TeaVPN2-v%hhu.%hhu.%hhu%s) (thread=%u)",
		  W_IU(client),
		  pkt_hsc->cur.ver,
		  pkt_hsc->cur.patch_lvl,
		  pkt_hsc->cur.sub_lvl,
		  pkt_hsc->cur.extra,
		  thread->idx);

	ret = send_handshake_response(thread, client);
out:
	bt_mutex_unlock(&client->lock);
	return ret;
}


static int handle_clpkt_auth(struct srv_thread *thread,
			     struct client_slot *client, size_t fdata_len)
{
	int ret = 0;
	int send_ret;
	struct iou_cqe_vec *cqev;
	struct tsrv_pkt *srv_pkt;
	struct tsrv_pkt_auth_res *auth_res;
	struct tcli_pkt *cli_pkt = &client->cpkt;
	struct tcli_pkt_auth *auth = &cli_pkt->auth;

	bt_mutex_lock(&client->lock);
	if (unlikely(client->is_authenticated)) {
		ret = 0;
		goto out;
	}

	if (unlikely(fdata_len != sizeof(*auth))) {
		pr_notice("Invalid auth packet length from " PRWIU
			  " (expected = %zu; actual = %zu) (thread=%u)",
			  W_IU(client), sizeof(*auth), fdata_len, thread->idx);
		ret = -EBADMSG;
		goto out_cred_clean;
	}

	cqev = get_iou_cqe_vec(thread);
	if (unlikely(!cqev)) {
		pr_notice("Running out of cqes when handling auth from " PRWIU
			  " (thread=%u)", W_IU(client), thread->idx);
		ret = -EAGAIN;
		goto out_cred_clean;
	}

	srv_pkt  = &cqev->spkt;
	auth_res = &srv_pkt->auth_res;
	memset(auth_res, 0, sizeof(*auth_res));
	if (!teavpn2_server_auth(thread->state->cfg, auth, auth_res)) {
		pr_notice("Authentication failed from " PRWIU " (thread=%u)",
			  W_IU(client), thread->idx);
		ret = -EACCES;
		auth_res->is_ok = 0;
	} else {
		pr_notice("Authentication success from " PRWIU " (thread=%u)",
			  W_IU(client), thread->idx);
		auth_res->is_ok  = 1;
		client->is_authenticated = true;
		sane_strncpy(client->username, auth->username,
			     sizeof(client->username));
	}

	srv_pkt->type    = TSRV_PKT_AUTH_RES;
	srv_pkt->pad_len = 0u;
	srv_pkt->length  = sizeof(*auth_res);
	cqev->vec_type   = IOU_CQE_VEC_NOP;
	cqev->len        = TSRV_PKT_MIN_READ + sizeof(*auth_res);
	send_ret = do_iou_send(thread, client->cli_fd, cqev, 0);
	if (ret) {
		/*
		 * If the auth fails, we don't care about the do_iou_send()
		 * return value.
		 */
		ret = 0;
		goto out_cred_clean;
	} else {
		ret = send_ret;
	}

out_cred_clean:
	/* Clean the sensitive data up! */
	memset(auth->username, 0, sizeof(auth->username));
	memset(auth->password, 0, sizeof(auth->password));
out:
	bt_mutex_unlock(&client->lock);
	return ret;
}


static int handle_clpkt_iface_data(struct srv_thread *thread,
				   struct client_slot *client, size_t fdata_len)
{
	struct iou_cqe_vec *cqev;
	struct tcli_pkt *cli_pkt = &client->cpkt;

	cqev = get_iou_cqe_vec(thread);
	if (unlikely(!cqev)) {
		pr_err("Run out of CQE vector on handle_clpkt_iface_data "
		       "when receiving from " PRWIU " (thread=%u)", W_IU(client),
		       thread->idx);
		return -EAGAIN;
	}

	cqev->vec_type = IOU_CQE_VEC_TUN_WRITE;
	cqev->len      = fdata_len;
	memcpy(&cqev->raw_pkt, &cli_pkt->iface_data, fdata_len);
	return do_iou_write(thread, thread->tun_fd, cqev);

	/* TODO: Broadcast packet to clients, or send route it. */
}


static int ____handle_client_data(struct srv_thread *thread,
				  struct client_slot *client, size_t fdata_len)
{
	int ret = 0;
	switch (client->cpkt.type) {
	case TCLI_PKT_NOP:
		break;
	case TCLI_PKT_HANDSHAKE:
		ret = handle_clpkt_handshake(thread, client, fdata_len);
		break;
	case TCLI_PKT_AUTH:
		ret = handle_clpkt_auth(thread, client, fdata_len);
		break;
	case TCLI_PKT_IFACE_DATA:
		ret = handle_clpkt_iface_data(thread, client, fdata_len);
		break;
	case TCLI_PKT_REQSYNC:
		break;
	case TCLI_PKT_CLOSE:
		break;
	}
	return ret;
}


static int __handle_client_data(struct srv_thread *thread,
				struct client_slot *client, size_t recv_s)
{
	int ret = 0;
	size_t fdata_len; /* Full expected data length for this packet    */
	size_t cdata_len; /* Current received data length for this packet */
	struct tcli_pkt *cli_pkt = &client->cpkt;

check_again:
	if (unlikely(recv_s < TCLI_PKT_MIN_READ)) {
		/*
		 * We haven't received mandatory information such
		 * as packet type, padding and data length.
		 *
		 * Let's wait a bit longer.
		 *
		 * Bail out!
		 */
		goto out;
	}


	fdata_len = cli_pkt->length;
	cdata_len = recv_s - TCLI_PKT_MIN_READ;
	pr_debug("Got fdata_len = %zu", fdata_len);
	if (unlikely(cdata_len < fdata_len)) {
		/*
		 * We haven't completely received the data.
		 *
		 * Let's wait a bit longer.
		 *
		 * Bail out!
		 */
		goto out;
	}


	if (unlikely(fdata_len > sizeof(*cli_pkt))) {
		/*
		 * Packet is too long. This is wrong!
		 */
		ret = -EBADMSG;
		recv_s = 0;
		goto out;
	}


	ret = ____handle_client_data(thread, client, fdata_len);
	if (unlikely(ret)) {
		recv_s = 0;
		goto out;
	}


	if (recv_s > (TCLI_PKT_MIN_READ + fdata_len)) {
		/*
		 * We have extra bytes on the tail.
		 *
		 * Must memmove() to the front before
		 * we run out of buffer!
		 */
		size_t  crln  = TCLI_PKT_MIN_READ + fdata_len;
		char   *head  = (char *)cli_pkt;
		char   *tail  = head + crln;
		recv_s       -= crln;
		memmove(head, tail, recv_s);
		pr_debug("Got extra bytes, memmove() (recv_s=%zu) "
			 "(fdata_len=%zu)", recv_s, fdata_len);
		goto check_again;
	}


	/*
	 * We are done, reset the buffer offset to zero.
	 */
	recv_s = 0;
out:
	client->recv_s = recv_s;
	return ret;
}


static int rearm_io_uring_recv_for_client(struct srv_thread *thread,
					  struct client_slot *client)
{
	int ret;
	int cli_fd;
	size_t recv_s;
	char *recv_buf;
	size_t recv_len;
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(&thread->ring);
	if (unlikely(!sqe)) {
		pr_err("Running out of SQE to recv from " PRWIU " (thread=%u)",
		       W_IU(client), thread->idx);
		return -EAGAIN;
	}

	cli_fd   = client->cli_fd;
	recv_s   = client->recv_s;
	recv_buf = client->raw_pkt + recv_s;
	recv_len = sizeof(client->raw_pkt) - recv_s;

	io_uring_prep_recv(sqe, cli_fd, recv_buf, recv_len, MSG_WAITALL);
	io_uring_sqe_set_data(sqe, client);
	assert(client->__iou_cqe_vec_type == IOU_CQE_VEC_TCP_RECV);

	ret = io_uring_submit(&thread->ring);
	if (unlikely(ret < 0)) {
		pr_err("io_uring_submit(): " PRERF " | " PRWIU " (thread=%u)",
		       PREAR(-ret), W_IU(client), thread->idx);
		return ret;
	}

	return 0;
}


static void close_client_conn(struct srv_thread *thread,
			      struct client_slot *client)
{
	uint16_t cli_idx = client->idx;
	struct srv_state *state = thread->state;

	pr_notice("Closing connection from " PRWIU " (fd=%d) (thread=%u)...",
		  W_IU(client), client->cli_fd, thread->idx);

	close(client->cli_fd);
	reset_client_state(client, cli_idx);

	bt_mutex_lock(&state->cl_stk.lock);
	tv_stack_push(&state->cl_stk, cli_idx);
	bt_mutex_unlock(&state->cl_stk.lock);
}


static int handle_client_data(struct srv_thread *thread,
			      struct io_uring_cqe *cqe,
			      struct client_slot *client)
{
	int ret = 0;
	size_t recv_s;
	ssize_t recv_ret = (ssize_t)cqe->res;

	recv_s = client->recv_s;
	if (unlikely(recv_ret == 0)) {
		pr_notice("recv() from " PRWIU " returned 0", W_IU(client));
		goto out_close;
	}

	if (unlikely(recv_ret < 0)) {
		pr_notice("recv() from " PRWIU " error | " PRERF, W_IU(client),
			  PREAR((int)-recv_ret));
		goto out_close;
	}

	recv_s += (size_t)recv_ret;
	pr_debug("recv() %*zd bytes from " PRWIU " (recv_s=%zu) (thread=%u)", 5,
		 recv_ret, W_IU(client), recv_s, thread->idx);


	ret = __handle_client_data(thread, client, recv_s);
	if (unlikely(ret && (ret != -EINPROGRESS))) {
		pr_debug("____handle_client_data returned " PRERF, PREAR(-ret));
		goto out_close;
	}

	ret = rearm_io_uring_recv_for_client(thread, client);
	if (unlikely(ret))
		goto out_close;

	return 0;

out_close:
	close_client_conn(thread, client);
	return 0;
}


static int rearm_io_uring_read_tun(struct srv_thread *thread)
{
	int ret;
	struct io_uring_sqe *sqe;
	void *tun_buf = &thread->spkt.iface_data;
	unsigned int tun_buf_size = sizeof(thread->spkt.iface_data);

	sqe = io_uring_get_sqe(&thread->ring);
	if (unlikely(!sqe))
		panic("Run out of SQE when reading from TUN fd (thread=%u)",
		      thread->idx);

	io_uring_prep_read(sqe, thread->tun_fd, tun_buf, tun_buf_size, 0);
	io_uring_sqe_set_data(sqe, UPTR(IOU_CQE_DRC_TUN_READ));
	ret = io_uring_submit(&thread->ring);
	if (unlikely(ret < 0))
		panic("io_uring_submit() when reading from TUN fd: " PRERF
		      " (thread=%u)", PREAR(-ret), thread->idx);

	return 0;
}


static int handle_tun_read(struct srv_thread *thread, struct io_uring_cqe *cqe)
{
	int ret;
	size_t i;
	size_t num_of_clients;
	ssize_t read_ret = (ssize_t)cqe->res;
	struct tsrv_pkt *srv_pkt, *srv_pkt0 = &thread->spkt;
	struct client_slot *clients = thread->state->clients;

	if (unlikely(read_ret < 0)) {
		pr_err("read() from tun_fd " PRERF, PREAR((int)-read_ret));
		return (int)read_ret;
	}

	num_of_clients = thread->state->cfg->sock.max_conn;
	for (i = 0; i < num_of_clients; i++) {
		struct iou_cqe_vec *cqev;
		struct client_slot *client = &clients[i];

		if (!client->is_authenticated)
			continue;

		cqev = get_iou_cqe_vec(thread);
		if (unlikely(!cqev))
			return -EAGAIN;

		srv_pkt          = &cqev->spkt;
		srv_pkt->type    = TCLI_PKT_IFACE_DATA;
		srv_pkt->pad_len = 0u;
		srv_pkt->length  = (uint16_t)((size_t)read_ret);
		cqev->vec_type   = IOU_CQE_VEC_TCP_SEND;
		cqev->len        = TCLI_PKT_MIN_READ + (size_t)read_ret;
		memcpy(&srv_pkt->iface_data, &srv_pkt0->iface_data,
		       (size_t)read_ret);
		cqev->udata = UPTR(TCLI_PKT_MIN_READ + (size_t)read_ret);

		ret = do_iou_send(thread, client->cli_fd, cqev, 0);
		if (unlikely(ret < 0))
			return ret;
	}
	pr_debug("TUN read %d bytes (thread=%u)", cqe->res, thread->idx);
	rearm_io_uring_read_tun(thread);
	return 0;
}


static int handle_iou_cqe_vec(struct srv_thread *thread,
			      struct io_uring_cqe *cqe, void *fret)
{
	int ret = 0;
	union uni_iou_cqe_vec *vcqe = fret;

	switch (vcqe->vec_type) {
	case IOU_CQE_VEC_NOP:
		pr_debug("Got IOU_CQE_VEC_NOP %d", cqe->res);
		put_iou_cqe_vec(thread, fret);
		break;
	case IOU_CQE_VEC_TUN_WRITE:
		pr_debug("Got IOU_CQE_VEC_TUN_WRITE %d", cqe->res);
		put_iou_cqe_vec(thread, fret);
		break;
	case IOU_CQE_VEC_TCP_SEND:
		pr_debug("Got IOU_CQE_VEC_TCP_SEND (%d %zu) (len = %zu) (fdata_len = %zu)",
			  cqe->res, (size_t)vcqe->send.udata,
			  (size_t)vcqe->send.len,
			  (size_t)vcqe->send.spkt.length);
		put_iou_cqe_vec(thread, fret);
		break;
	case IOU_CQE_VEC_TCP_RECV:
		ret = handle_client_data(thread, cqe, fret);
		/* Don't put, it is not iou_cqe_vec! */
		break;
	default:
		VT_HEXDUMP(vcqe, 2048);
		panic("Got invalid vcqe on handle_iou_cqe_vec() (%u)",
		      vcqe->vec_type);
	}

	return ret;
}


static int handle_event(struct srv_thread *thread, struct io_uring_cqe *cqe)
{
	void *fret;
	int ret = 0;
	uintptr_t type;

	if (unlikely(!cqe))
		return 0;

	fret = io_uring_cqe_get_data(cqe);
	type = (uintptr_t)fret;
	switch (type) {
	case IOU_CQE_DRC_NOP:
		pr_debug("Got IOU_CQE_DRC_NOP");
		break;
	case IOU_CQE_DRC_TUN_READ:
		ret = handle_tun_read(thread, cqe);
		break;
	case IOU_CQE_DRC_TCP_ACCEPT:
		ret = handle_event_tcp(thread, cqe);
		break;
	default:
		ret = handle_iou_cqe_vec(thread, cqe, fret);
		break;
	}

	return ret;
}


static int do_uring_wait(struct srv_thread *thread, struct io_uring_cqe **cqe_p)
{
	int ret;
	struct io_uring *ring = &thread->ring;
	struct __kernel_timespec *ts = &thread->ring_timeout;

	ret = io_uring_wait_cqes(ring, cqe_p, 1, ts, NULL);
	if (likely(!ret))
		return 0;

	if (unlikely(ret == -ETIME))
		return ret;

	if (unlikely(ret == -EINTR)) {
		pr_notice("Interrupted (thread=%u)", thread->idx);
		return -EINTR;
	}

	pr_err("io_uring_wait_cqe(): " PRERF, PREAR(-ret));
	return -ret;
}


static int handle_io_uring_cqes(struct srv_thread *thread,
				struct io_uring_cqe *cqe)
{
	int ret = 0;
	unsigned head, count = 0;
	struct io_uring *ring = &thread->ring;

	io_uring_for_each_cqe(ring, head, cqe) {
		count++;
		ret = handle_event(thread, cqe);
		if (unlikely(ret))
			break;
	}
	io_uring_cq_advance(ring, count);
	return ret;
}


static int do_io_uring_event_loop(struct srv_thread *thread)
{
	int ret;
	struct io_uring_cqe *cqe = NULL;

	ret = do_uring_wait(thread, &cqe);
	if (likely(ret == 0))
		return handle_io_uring_cqes(thread, cqe);
	

	if (unlikely(ret == -ETIME)) {
		/* io_uring reached its timeout. */
		return 0;
	}

	if (unlikely(ret == -EINTR)) {
		struct srv_state *state = thread->state;
		if (state->intr_sig == -1) {
			pr_notice("Ummm... are we traced? (thread=%u)",
				  thread->idx);
			return 0;
		}
		teavpn2_server_tcp_wait_for_thread_to_exit(state, true);
		return -EINTR;
	}
	return ret;
}


__no_inline static void *run_thread(void *thread_p)
{
	int ret = 0;
	struct srv_thread *thread = thread_p;
	struct srv_state *state = thread->state;

	atomic_fetch_add(&state->online_tr, 1);
	teavpn2_server_tcp_wait_threads(state, thread->idx == 0);
	atomic_store(&thread->is_online, true);

	while (likely(!state->stop)) {
		ret = do_io_uring_event_loop(thread);
		if (unlikely(ret))
			break;
	}

	atomic_store(&thread->is_online, false);
	atomic_fetch_sub(&state->online_tr, 1);
	pr_notice("Thread %u is exiting (stop=%hhu)", thread->idx, state->stop);

	return (void *)(intptr_t)ret;
}


static __u32 cpu_bind_ydyd(cpu_set_t *cpus, unsigned *bc)
{
	int i, c = CPU_COUNT(cpus);

	while (1) {
		i = (int)((*bc)++);
		i = i % c;
		if (CPU_ISSET(i, cpus))
			return (__u32)i;
	}
}


static int init_threads(struct srv_state *state)
{
	int ret = 0;
	unsigned bc = 0;
	unsigned ring_flags;
	struct srv_thread *threads;
	cpu_set_t __maybe_unused cpus;
	struct io_uring_params ring_params;
	size_t i, nn = state->cfg->sys.thread;

	ring_flags = IORING_SETUP_CLAMP | IORING_SETUP_SQPOLL; // may add SQPOLL later.

	if (ring_flags & IORING_SETUP_SQPOLL) {
		/*
		 * Can we bind our io_uring context to SMP core?
		 */
		CPU_ZERO(&cpus);
		ret = sched_getaffinity(0, sizeof(cpus), &cpus);
		if (unlikely(ret < 0)) {
			ret = errno;
			pr_err("sched_getaffinity() " PRERF, PREAR(ret));
			ret = 0;
		} else if (CPU_COUNT(&cpus) > 1) {
			/*
			 * Bind the io_uring context to specific core to
			 * reduce CPU cache pollution and CPU migration!
			 */
			ring_flags |= IORING_SETUP_SQ_AFF;
			pr_notice("We have %d available CPU(s)", CPU_COUNT(&cpus));
		} else {
			/*
			 * We only have 1 CPU, don't use SQPOLL!
			 */
			ring_flags &= ~IORING_SETUP_SQPOLL;
		}
	}
	

	threads = state->threads;
	for (i = 0; i < nn; i++) {
		struct io_uring_sqe *sqe;
		int tun_fd = state->tun_fds[i];
		struct srv_thread *thread = &threads[i];
		struct io_uring *ring = &thread->ring;
		void *tun_buf = &thread->spkt.iface_data;
		unsigned int tun_buf_size = sizeof(thread->spkt.iface_data);

		ret = tv_stack_init(&thread->ioucl_stk, IOUCL_VEC_NUM);
		if (unlikely(ret)) {
			pr_err("tv_stack_init(): " PRERF, PREAR(-ret));
			break;
		}

		ret = init_iou_cqe_vec(&thread->cqe_vec);
		if (unlikely(ret)) {
			pr_err("init_iou_cqe_vec(): " PRERF, PREAR(-ret));
			break;
		}

		pr_notice("Initializing io_uring context... (thread=%zu)", i);
		memset(&ring_params, 0, sizeof(ring_params));
		ring_params.flags = ring_flags;

		if (ring_flags & IORING_SETUP_SQPOLL)
			ring_params.sq_thread_idle = 1000;

		if (ring_flags & (IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF)) {
			__u32 core_num = cpu_bind_ydyd(&cpus, &bc);
			ring_params.sq_thread_cpu = core_num;
			pr_notice("Binding io_uring SQThread %zu to CPU %u...",
				  i, core_num);
		}

		ret = io_uring_queue_init_params(255, ring, &ring_params);
		if (unlikely(ret)) {
			pr_err("io_uring_queue_init_params(): " PRERF,
			       PREAR(-ret));
			break;
		}

		thread->ring_init = true;
		thread->tun_fd = tun_fd;
		thread->state  = state;
		thread->idx    = (uint16_t)i;
		thread->read_s = 0;
		thread->ring_timeout.tv_sec = 10;

		sqe = io_uring_get_sqe(ring);
		if (unlikely(!sqe)) {
			pr_err("io_uring_get_sqe(): " PRERF, PREAR(ENOMEM));
			ret = -ENOMEM;
			break;
		}

		io_uring_prep_read(sqe, tun_fd, tun_buf, tun_buf_size, 0);
		io_uring_sqe_set_data(sqe, UPTR(IOU_CQE_DRC_TUN_READ));

		/*
		 * Don't spawn a thread for `i == 0`,
		 * because we are going to run it on
		 * the main thread.
		 */
		if (unlikely(i == 0))
			continue;

		ret = io_uring_submit(ring);
		if (unlikely(ret < 0)) {
			pr_err("io_uring_submit(): " PRERF, PREAR(-ret));
			break;
		}

		ret = pthread_create(&thread->thread, NULL, run_thread, thread);
		if (unlikely(ret)) {
			pr_err("pthread_create(): " PRERF, PREAR(ret));
			ret = -ret;
			break;
		}

		ret = pthread_detach(thread->thread);
		if (unlikely(ret)) {
			pr_err("pthread_detach(): " PRERF, PREAR(ret));
			ret = -ret;
			break;
		}
	}

	return ret;
}


static int run_main_thread(struct srv_state *state)
{
	int ret;
	void *fret;
	struct accept_data *acc;
	struct io_uring_sqe *sqe;
	struct srv_thread *thread;
	struct sockaddr *addr;

	/*
	 * Main thread is responsible to accept
	 * new connections, so we add tcp_fd to
	 * its uring queue resource.
	 */
	acc    = &state->acc;
	thread = &state->threads[0];

	sqe = io_uring_get_sqe(&thread->ring);
	if (unlikely(!sqe)) {
		pr_err("io_uring_get_sqe(): " PRERF, PREAR(ENOMEM));
		ret = -ENOMEM;
		goto out;
	}

	acc->acc_fd  = -1;
	acc->addrlen = sizeof(acc->addr);
	memset(&acc->addr, 0, sizeof(acc->addr));
	addr = (struct sockaddr *)&acc->addr;
	io_uring_prep_accept(sqe, state->tcp_fd, addr, &acc->addrlen, 0);
	io_uring_sqe_set_data(sqe, UPTR(IOU_CQE_DRC_TCP_ACCEPT));


	ret = io_uring_submit(&thread->ring);
	if (unlikely(ret < 0)) {
		pr_err("io_uring_submit(): " PRERF, PREAR(-ret));
		goto out;
	}

	fret = run_thread(thread);
	ret  = (int)((intptr_t)fret);
out:
	return ret;
}



static void destroy_io_uring_context(struct srv_state *state)
{
	struct srv_thread *threads = state->threads;
	size_t i, nn = state->cfg->sys.thread;

	for (i = 0; i < nn; i++) {
		struct srv_thread *thread = &threads[i];

		if (thread->ring_init) {
			pr_notice("Destroying io_uring context... (thread=%zu)",
				  i);
			io_uring_queue_exit(&thread->ring);
		}

		al64_free(thread->cqe_vec);
		tv_stack_destroy(&thread->ioucl_stk);
	}
}


int teavpn2_server_tcp_event_loop_io_uring(struct srv_state *state)
{
	int ret = 0;

	ret = init_threads(state);
	if (unlikely(ret)) {
		pr_err("init_threads(): " PRERF, PREAR(-ret));
		goto out;
	}

	ret = run_main_thread(state);
out:
	teavpn2_server_tcp_wait_for_thread_to_exit(state, false);
	destroy_io_uring_context(state);
	return ret;
}