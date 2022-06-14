// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022  Ammar Faizi <ammarfaizi2@gmail.com>
 */
#include <time.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <pthread.h>
#include <sys/mman.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <teavpn2/mutex.h>
#include <teavpn2/stack.h>
#include <teavpn2/packet.h>
#include <teavpn2/server/common.h>
#include <teavpn2/net/linux/iface.h>
#include <teavpn2/server/linux/server.h>

struct udp_sess {
	/*
	 * Private IP of this session (virtual network interface).
	 */
	uint32_t				ipv4_iff;

	/*
	 * UDP session source address and source port (public).
	 */
	uint32_t				src_addr;
	uint16_t				src_port;

	/*
	 * UDP sessions are stored in the array. @idx contains
	 * the index of each instance. Useful for pushing the
	 * session index onto the stack.
	 */
	uint16_t				idx;

	/*
	 * Loop counter. This determines how many recvfrom() calls
	 * has been invoked for this session.
	 */
	uint32_t				loop_c;

	/*
	 * UDP is stateless, we may not know whether the client is
	 * still online or not. @last_act can be used to handle
	 * timeout for session closing in case we have an abnormal
	 * session termination. Useful for zombie reaper thread.
	 */
	time_t					last_act;

	/*
	 * UDP session source address and source port in network
	 * byte order. Useful for sendto() call.
	 */
	struct sockaddr_in			addr;

	/*
	 * Username of this session.
	 */
	char					username[0x100];

	/*
	 * Human readable C string of @src_addr.
	 */
	char					str_src_addr[IPV4_L];

	/*
	 * Error counter.
	 */
	uint8_t					err_c;

	bool					is_authenticated;
	bool					is_connected;
};

struct udp_state {
	/*
	 * To determine whether the event loop should stop.
	 */
	volatile bool				stop;

	/*
	 * Signal caught from signal_handler.
	 */
	int					sig;

	/*
	 * Number of online sessions.
	 */
	uint16_t				nr_on_sess;

	/*
	 * Array of index of @sess whose the session is online.
	 */
	uint16_t				*list_on_sess;

	/*
	 *
	 */


	/*
	 * UDP session array.
	 */
	struct udp_sess				sess[] __aligned(64);
};

static DEFINE_MUTEX(g_state_mutex);
static struct udp_state *g_state = NULL;

static void memzero_explicit(void *addr, size_t len)
{
	__asm__ volatile ("":"+r"(addr)::"memory");
	memset(addr, 0, len);
	__asm__ volatile ("":"+r"(addr)::"memory");
}

#define USE_ASAN 1
static void *alloc_pinned(size_t len)
{
#if !USE_ASAN
	void *r;
	int err;

	len = (len + 4095ul) & -4096ul;
	r = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE,
		 -1, 0);
	if (unlikely(r == MAP_FAILED)) {
		err = errno;
		pr_err("mmap(): " PRERF, PREAR(err));
		return NULL;
	}

	err = mlock(r, len);
	if (unlikely(err < 0)) {
		err = errno;
		pr_err("mlock(): " PRERF, PREAR(err));
		munmap(r, len);
		return NULL;
	}
	return r;
#else
	return calloc(1, len);
#endif
}

static void *alloc_pinned_faulted(size_t len)
{
	void *ret;

	ret = alloc_pinned(len);
	if (unlikely(!ret))
		return ret;

	memzero_explicit(ret, len);
	return ret;
}

static __cold int init_state(struct udp_state **state_p, struct srv_cfg *cfg)
	__must_hold(&g_state_mutex)
{
	struct udp_state *state;
	size_t max_conn = cfg->sock.max_conn + 1;
	size_t size;

	lockdep_assert_held(&g_state_mutex);

	size = sizeof(*state) + (max_conn * sizeof(*state->sess));
	state = alloc_pinned_faulted(size);
	if (!state)
		return -ENOMEM;

	state->stop = false;
	state->sig = -1;
	state->nr_on_sess = 0;
	state->list_on_sess = NULL;
	memset(state->sess, 0, max_conn * sizeof(*state->sess));
	*state_p = state;
	g_state = state;
	return 0;
}

static __cold int signal_handler(int sig)
{
	struct udp_state *state;

	state = g_state;
	if (unlikely(!state)) {
		panic("signal_intr_handler is called when g_state is NULL");
		__builtin_unreachable();
	}

	if (state->sig == -1) {
		state->stop = true;
		state->sig = sig;
		putchar('\n');
	}
}

static __cold int set_signal_handler(bool set)
{
	struct sigaction sa;
	int ret;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = set ? signal_handler : SIG_DFL;
	if (unlikely(sigaction(SIGINT, &sa, NULL) < 0))
		goto err;
	if (unlikely(sigaction(SIGHUP, &sa, NULL) < 0))
		goto err;
	if (unlikely(sigaction(SIGTERM, &sa, NULL) < 0))
		goto err;

	sa.sa_handler = set ? SIG_IGN : SIG_DFL;
	if (unlikely(sigaction(SIGPIPE, &sa, NULL) < 0))
		goto err;

	return 0;

err:
	ret = errno;
	pr_err("sigaction(): " PRERF, PREAR(ret));
	return -ret;
}

static void destroy_state(struct udp_state *state)
	__must_hold(&g_state_mutex)
{
	lockdep_assert_held(&g_state_mutex);
}

int teavpn2_server_udp_run(struct srv_cfg *cfg)
{
	struct udp_state *state = NULL;
	int ret;

	mutex_lock(&g_state_mutex);
	ret = init_state(&state, cfg);
	mutex_unlock(&g_state_mutex);
	if (unlikely(ret))
		return ret;

	ret = set_signal_handler(true);
	if (unlikely(ret))
		goto out;


out_del_sig:
	set_signal_handler(false);
out:
	mutex_lock(&g_state_mutex);
	destroy_state(state);
	mutex_unlock(&g_state_mutex);
	return ret;
}
