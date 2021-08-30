// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <teavpn2/client/common.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/client/linux/udp.h>


static struct cli_udp_state *g_state = NULL;


static void interrupt_handler(int sig)
{
	struct cli_udp_state *state;

	state = g_state;
	if (unlikely(!state))
		panic("interrupt_handler is called when g_state is NULL");

	if (state->sig == -1) {
		state->stop = true;
		state->sig  = sig;
		putchar('\n');
	}
}


static int init_tun_fds(struct cli_udp_state *state)
{
	uint8_t i, nn = (uint8_t)state->cfg->sys.thread_num;
	int *tun_fds = calloc_wrp((size_t)nn, sizeof(*tun_fds));

	if (unlikely(!tun_fds))
		return -errno;

	for (i = 0; i < nn; i++)
		tun_fds[i] = -1;

	state->tun_fds = tun_fds;
	return 0;
}


static int select_event_loop(struct cli_udp_state *state)
{
	struct cli_cfg_sock *sock = &state->cfg->sock;
	const char *evtl = sock->event_loop;

	if ((evtl[0] == '\0') || (!strcmp(evtl, "epoll"))) {
		state->evt_loop = EVTL_EPOLL;
	} else if (!strcmp(evtl, "io_uring") ||
		   !strcmp(evtl, "io uring") ||
		   !strcmp(evtl, "iouring") ||
		   !strcmp(evtl, "uring")) {
		state->evt_loop = EVTL_IO_URING;
	} else {
		pr_err("Invalid socket event loop: \"%s\"", evtl);
		return -EINVAL;
	}
	return 0;
}


static int init_state(struct cli_udp_state *state)
{
	int ret;

	prl_notice(2, "Initializing client state...");
	g_state = state;
	state->udp_fd = -1;
	state->sig = -1;

	ret = init_tun_fds(state);
	if (unlikely(ret))
		return ret;

	ret = select_event_loop(state);
	if (unlikely(ret))
		return ret;

	switch (state->evt_loop) {
	case EVTL_EPOLL:
		state->epl_threads = NULL;
		break;
	case EVTL_IO_URING:
		break;
	case EVTL_NOP:
	default:
		panic("Aiee... invalid event loop value (%u)", state->evt_loop);
		__builtin_unreachable();
	}

	prl_notice(2, "Setting up interrupt handler...");
	if (signal(SIGINT, interrupt_handler) == SIG_ERR)
		goto sig_err;
	if (signal(SIGTERM, interrupt_handler) == SIG_ERR)
		goto sig_err;
	if (signal(SIGHUP, interrupt_handler) == SIG_ERR)
		goto sig_err;
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		goto sig_err;

	prl_notice(2, "Client state initialized successfully!");
	return ret;

sig_err:
	ret = errno;
	pr_err("signal(): " PRERF, PREAR(ret));
	return -ret;
}


static int init_socket(struct cli_udp_state *state)
{
	int ret;
	int type;
	int udp_fd;
	struct sockaddr_in addr;
	struct cli_cfg_sock *sock = &state->cfg->sock;

	type = SOCK_DGRAM;
	if (state->evt_loop != EVTL_IO_URING)
		type |= SOCK_NONBLOCK;

	state->udp_fd = -1;
	udp_fd = socket(AF_INET, type, 0);
	if (unlikely(udp_fd < 0)) {
		ret = errno;
		pr_err("socket(AF_INET, SOCK_DGRAM%s, 0): " PRERF,
		       (type & SOCK_NONBLOCK) ? " | SOCK_NONBLOCK" : "",
		       PREAR(ret));
		return -ret;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(sock->server_port);
	addr.sin_addr.s_addr = inet_addr(sock->server_addr);

	ret = connect(udp_fd, (struct sockaddr *)&addr, sizeof(addr));
	if (unlikely(ret < 0)) {
		ret = errno;
		pr_err("connect(): " PRERF, PREAR(ret));
		goto out_err;
	}

	state->udp_fd = udp_fd;
	return 0;

out_err:
	close(udp_fd);
	return -ret;
}


static int init_iface(struct cli_udp_state *state)
{
	const char *dev = state->cfg->iface.dev;
	int ret = 0, tun_fd, *tun_fds = state->tun_fds;
	uint8_t i, nn = (uint8_t)state->cfg->sys.thread_num;
	short flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;

	prl_notice(2, "Initializing virtual network interface...");

	for (i = 0; i < nn; i++) {
		prl_notice(4, "Initializing tun_fds[%hhu]...", i);

		tun_fd = tun_alloc(dev, flags);
		if (unlikely(tun_fd < 0)) {
			pr_err("tun_alloc(\"%s\", %d): " PRERF, dev, flags,
				PREAR(-tun_fd));
			ret = tun_fd;
			goto err;
		}

		ret = fd_set_nonblock(tun_fd);
		if (unlikely(ret < 0)) {
			pr_err("fd_set_nonblock(%d): " PRERF, tun_fd,
				PREAR(-ret));
			close(tun_fd);
			goto err;
		}

		tun_fds[i] = tun_fd;
		prl_notice(4, "Successfully initialized tun_fds[%hhu] (fd=%d)",
			   i, tun_fd);
	}

	prl_notice(2, "Virtual network interface initialized successfully!");
	return ret;
err:
	while (i--) {
		close(tun_fds[i]);
		tun_fds[i] = -1;
	}
	return ret;
}


static ssize_t do_send_to(int udp_fd, const void *pkt, size_t send_len)
{
	int ret;
	ssize_t send_ret;
	send_ret = sendto(udp_fd, pkt, send_len, 0, NULL, 0);
	if (unlikely(send_ret < 0)) {
		ret = errno;
		pr_err("sendto(): " PRERF, PREAR(ret));
		return -ret;
	}
	if (unlikely((size_t)send_ret != send_len)) {
		pr_err("send_ret != send_len");
		return -EBADMSG;
	}
	pr_debug("sendto() %zd bytes", send_ret);
	return send_ret;
}


static ssize_t do_recv_from(int udp_fd, void *pkt, size_t recv_len)
{
	int ret;
	ssize_t recv_ret;
	recv_ret = recvfrom(udp_fd, pkt, recv_len, 0, NULL, 0);
	if (unlikely(recv_ret < 0)) {
		ret = errno;
		pr_err("recvfrom(): " PRERF, PREAR(ret));
		return -ret;
	}
	pr_debug("recvfrom() %zd bytes", recv_ret);
	return recv_ret;
}


static int poll_fd_input(struct cli_udp_state *state, int fd, int timeout)
{
	int ret;
	nfds_t nfds = 1;
	struct pollfd fds[1];

poll_again:
	fds[0].fd = fd;
	fds[0].events = POLLIN | POLLPRI;
	ret = poll(fds, nfds, timeout);
	if (unlikely(ret < 0)) {
		ret = errno;
		if (ret != EINTR)
			return -ret;

		prl_notice(2, "poll() is interrupted!");
		if (!state->stop) {
			prl_notice(2, "Executing poll() again...");
			goto poll_again;
		}
		return -ret;
	}
	if (ret == 0)
		return -ETIMEDOUT;

	return ret;
}


static int _do_handshake(struct cli_udp_state *state)
{
	size_t send_len;
	ssize_t send_ret;
	int udp_fd = state->udp_fd;
	struct cli_pkt *pkt = &state->pkt.cli;
	struct pkt_handshake *hand = &pkt->handshake;
	struct teavpn2_version *cur = &hand->cur;

	memset(hand, 0, sizeof(*hand));
	cur->ver = VERSION;
	cur->patch_lvl = PATCHLEVEL;
	cur->sub_lvl = SUBLEVEL;
	strncpy(cur->extra, EXTRAVERSION, sizeof(cur->extra));
	cur->extra[sizeof(cur->extra) - 1] = '\0';

	prl_notice(2, "Initializing protocol handshake...");
	pkt->type    = TCLI_PKT_HANDSHAKE;
	pkt->len     = htons(sizeof(*hand));
	pkt->pad_len = 0u;
	send_len     = PKT_MIN_LEN + sizeof(*hand);
	send_ret     = do_send_to(udp_fd, pkt, send_len);
	return (send_ret >= 0) ? 0 : (int)send_ret;
}


static int server_handshake_chk(struct srv_pkt *srv_pkt, size_t len)
{
	struct pkt_handshake *hand = &srv_pkt->handshake;
	struct teavpn2_version *cur = &hand->cur;
	const size_t expected_len = sizeof(*hand);

	if (len < (PKT_MIN_LEN + expected_len)) {
		pr_err("Invalid handshake packet length (expected_len = %zu;"
		       " actual = %zu)", PKT_MIN_LEN + expected_len, len);
		return -EBADMSG;
	}

	srv_pkt->len = ntohs(srv_pkt->len);
	if ((size_t)srv_pkt->len != expected_len) {
		pr_err("Invalid handshake packet length (expected_len = %zu;"
		       " srv_pkt->len = %hhu)", expected_len, srv_pkt->len);
		return -EBADMSG;
	}

	if (srv_pkt->type != TSRV_PKT_HANDSHAKE) {
		pr_err("Invalid packet type "
		       "(expected = TSRV_PKT_HANDSHAKE (%hhu);"
		       " actual = %hhu",
		       TSRV_PKT_HANDSHAKE, srv_pkt->type);
		return -EBADMSG;
	}

	/* For printing safety! */
	cur->extra[sizeof(cur->extra) - 1] = '\0';
	prl_notice(2, "Got server handshake response "
		   "(server version: TeaVPN2-%hhu.%hhu.%hhu%s)",
		   cur->ver,
		   cur->patch_lvl,
		   cur->sub_lvl,
		   cur->extra);


	if ((cur->ver != VERSION) || (cur->patch_lvl != PATCHLEVEL) ||
	    (cur->sub_lvl != SUBLEVEL)) {
	    	pr_err("Server version is not supported for this client");
		return -EBADMSG;
	}

	return 0;
}


static int wait_for_handshake_response(struct cli_udp_state *state)
{
	int ret;
	ssize_t recv_ret;
	int udp_fd = state->udp_fd;
	struct srv_pkt *srv_pkt = &state->pkt.srv;
	struct pkt_handshake *hand = &srv_pkt->handshake;
	struct teavpn2_version *cur = &hand->cur;

	prl_notice(2, "Waiting for server handshake response...");
	ret = poll_fd_input(state, udp_fd, 5000);
	if (unlikely(ret < 0))
		return ret;

	recv_ret = do_recv_from(udp_fd, srv_pkt, PKT_MAX_LEN);
	if (unlikely(recv_ret < 0))
		return (int)recv_ret;

	return server_handshake_chk(srv_pkt, (size_t)recv_ret);
}


static int do_handshake(struct cli_udp_state *state)
{
	int ret;
	uint8_t try_count = 0;
	const uint8_t max_try = 5;

try_again:
	ret = _do_handshake(state);
	if (unlikely(ret))
		return ret;

	ret = wait_for_handshake_response(state);
	if (ret == -ETIMEDOUT && try_count++ < max_try)
		goto try_again;

	return ret;
}


static int _do_auth(struct cli_udp_state *state)
{
	size_t send_len;
	ssize_t send_ret;
	struct cli_pkt *pkt = &state->pkt.cli;
	struct pkt_auth *auth = &pkt->auth;
	struct cli_cfg_auth *auth_c = &state->cfg->auth;

	strncpy(auth->username, auth_c->username, sizeof(auth->username));
	strncpy(auth->password, auth_c->password, sizeof(auth->password));
	auth->username[sizeof(auth->username) - 1] = '\0';
	auth->password[sizeof(auth->password) - 1] = '\0';

	prl_notice(2, "Authenticating as %s...", auth->username);
	pkt->type    = TCLI_PKT_AUTH;
	pkt->len     = htons(sizeof(*auth));
	pkt->pad_len = 0u;
	send_len     = PKT_MIN_LEN + sizeof(*auth);
	send_ret     = do_send_to(state->udp_fd, pkt, send_len);
	return (send_ret >= 0) ? 0 : (int)send_ret;
}


static int wait_for_auth_response(struct cli_udp_state *state)
{
	int ret;

	prl_notice(2, "Waiting for server auth response...");
	ret = poll_fd_input(state, state->udp_fd, 5000);
	if (unlikely(ret < 0))
		return ret;

	return 0;
}


static int do_auth(struct cli_udp_state *state)
{
	int ret;
	uint8_t try_count = 0;
	const uint8_t max_try = 5;

try_again:
	ret = _do_auth(state);
	if (unlikely(ret))
		return ret;

	ret = wait_for_auth_response(state);
	if (ret == -ETIMEDOUT && try_count++ < max_try)
		goto try_again;

	return ret;
}


static int run_client_event_loop(struct cli_udp_state *state)
{
	switch (state->evt_loop) {
	case EVTL_EPOLL:
		return teavpn2_udp_client_epoll(state);
	case EVTL_IO_URING:
		pr_err("run_client_event_loop() with io_uring: " PRERF,
			PREAR(EOPNOTSUPP));
		return -EOPNOTSUPP;
	case EVTL_NOP:
	default:
		panic("Aiee... invalid event loop value (%u)", state->evt_loop);
		__builtin_unreachable();
	}
}


static void close_tun_fds(struct cli_udp_state *state)
{
	uint8_t i, nn = (uint8_t)state->cfg->sys.thread_num;
	int *tun_fds = state->tun_fds;

	if (!tun_fds)
		return;

	for (i = 0; i < nn; i++) {
		if (tun_fds[i] == -1)
			continue;
		prl_notice(2, "Closing tun_fds[%hhu] (fd=%d)...", i, tun_fds[i]);
	}
	al64_free(tun_fds);
}


static void close_udp_fd(struct cli_udp_state *state)
{
	if (state->udp_fd != -1) {
		prl_notice(2, "Closing udp_fd (fd=%d)...", state->udp_fd);
		close(state->udp_fd);
		state->udp_fd = -1;
	}
}


static void destroy_state(struct cli_udp_state *state)
{
	close_tun_fds(state);
	close_udp_fd(state);
}


int teavpn2_client_udp_run(struct cli_cfg *cfg)
{
	int ret = 0;
	struct cli_udp_state *state;

	/* This is a large struct, don't use stack. */
	state = calloc_wrp(1ul, sizeof(*state));
	if (unlikely(!state))
		return -ENOMEM;

	state->cfg = cfg;
	ret = init_state(state);
	if (unlikely(ret))
		goto out;
	ret = init_socket(state);
	if (unlikely(ret))
		goto out;
	ret = init_iface(state);
	if (unlikely(ret))
		goto out;
	ret = do_handshake(state);
	if (unlikely(ret))
		goto out;
	ret = do_auth(state);
	if (unlikely(ret))
		goto out;
	ret = run_client_event_loop(state);
out:
	if (unlikely(ret))
		pr_err("teavpn2_client_udp_run(): " PRERF, PREAR(-ret));

	destroy_state(state);
	al64_free(state);
	return ret;
}
