// SPDX-License-Identifier: GPL-2.0-only
/*
 *  src/teavpn2/server/linux/tcp.c
 *
 *  TCP handler for TeaVPN2 server
 *
 *  Copyright (C) 2021  Ammar Faizi
 */

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <linux/ip.h>
#include <inttypes.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <teavpn2/cpu.h>
#include <teavpn2/base.h>
#include <teavpn2/auth.h>
#include <teavpn2/net/iface.h>
#include <teavpn2/lib/string.h>
#include <teavpn2/server/tcp.h>
#include <teavpn2/net/tcp_pkt.h>


/* Shut the clang up! */
#if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Weverything"
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

#if defined(__clang__)
#  pragma clang diagnostic pop
#endif


#define CLIENT_MAX_ERROR	(0x0fu)
#define SERVER_MAX_ERROR	(0x0fu)
#define EPOLL_CLIENT_MAP_SIZE	(0xffffu)
#define EPOLL_INPUT_EVENTS	(EPOLLIN | EPOLLPRI)

#define IP_MAP_SHIFT		(0x00001u)	/* Preserve map to nop */
#define IP_MAP_TO_NOP		(0x00000u)	/* Unused map slot     */

#define THREAD_MAX_WAIT_ITR	(10000)

/* Macros for printing  */
#define W_IP(CLIENT) ((CLIENT)->src_ip), ((CLIENT)->src_port)
#define W_UN(CLIENT) ((CLIENT)->uname)
#define W_IU(CLIENT) W_IP(CLIENT), W_UN(CLIENT)
#define PRWIU "%s:%d (%s)"


struct client_slot {
	bool			is_auth;
	bool			is_used;
	bool			is_conn;
	uint8_t			err_c;

	/* Client file descriptor */
	int			cli_fd;

	/* Send counter */
	uint32_t		send_c;

	/* Recv counter */
	uint32_t		recv_c;

	/*
	 * To find the index in client slots which
	 * refer to its client instance.
	 *
	 *   state->clients[slot_index]
	 *
	 */
	uint16_t		slot_index;

	/* Remote address and port */
	uint16_t		src_port;
	char			src_ip[IPV4_L];

	/* Client username */
	char			uname[64];

	uint32_t		private_ip;
	size_t			recv_s;
	utcli_pkt_t		recv_buf;
};


typedef enum srv_thread_type_t_{
	ST_ACCEPT_AND_TUN_TAP,
	ST_CLIENTS_ONLY,
	ST_MIXED
} srv_thread_type_t;


struct srv_thread {
	srv_thread_type_t	type;
	int			epoll_fd;
	struct srv_tcp_state	*state;
	pthread_mutex_t		mutex;
	pthread_t		thread;
	bool			mutex_need_destroy;
	struct_pad(0, 7);
};


struct srv_tcp_state {
	struct iface_cfg	siff;

	bool			need_ssl_cleanup;
	bool			stop_event_loop;
	bool			need_iface_down;
	bool			set_affinity_ok;
	bool			mutex_need_destroy;
	uint8_t			err_c;

	/* File descriptors */
	int			tcp_fd;
	int			tun_fd;

	SSL_CTX			*ssl_ctx;
	struct srv_cfg		*cfg;

	/*
	 * We only support maximum of CIDR /16 number of clients.
	 * So this will be `uint16_t [256][256]`.
	 *
	 * The value of ip_map[i][j] is an index of `clients`
	 * slot in this struct. So you can access it like this:
	 * ```c
	 *    struct client_slot *client;
	 *    uint16_t map_to = ip_map[i][j];
	 *
	 *    if (map_to != IP_MAP_TO_NOP) {
	 *        client = &state->clients[map_to - IP_MAP_SHIFT];
	 *
	 *        // use client->xxxx here
	 *
	 *    } else {
	 *        // map is not mapped to client slot
	 *    }
	 * ```
	 */
	uint16_t		(*ip_map)[256];
	struct client_slot	*clients;
	uint16_t		*epoll_map;


	/* How many calls read(tun_fd, buf, size)? */
	uint32_t		read_tun_c;

	/* How many calls write(tun_fd, buf, size)? */
	uint32_t		write_tun_c;

	/* How many bytes has been read() from tun_fd */
	uint64_t		up_bytes;

	/* How many bytes has been write()'en to tun_fd */
	uint64_t		down_bytes;

	cpu_set_t		affinity;
	utsrv_pkt_t		send_buf;

	/* Array of threads */
	struct srv_thread 	*threads;
	pthread_mutex_t		global_mutex;
};


static struct srv_tcp_state *g_state;


static void handle_interrupt(int sig)
{
	struct srv_tcp_state *state = g_state;
	state->stop_event_loop = true;
	putchar('\n');
	pr_notice("Signal %d (%s) has been caught", sig, strsignal(sig));
}


static inline void reset_client_slot(struct client_slot *client,
				     uint16_t slot_index)
{
	client->is_auth    = false;
	client->is_used    = false;
	client->is_conn    = false;
	client->err_c      = 0;
	client->cli_fd     = -1;
	client->recv_c     = 0;
	client->send_c     = 0;
	client->recv_s     = 0;
	client->slot_index = slot_index;
	client->src_port   = 0;
	client->src_ip[0]  = '\0';
	client->uname[0]   = '_';
	client->uname[1]   = '\0';
	client->private_ip = 0;
	client->recv_s     = 0;
}


static void *calloc_wrp(size_t nmemb, size_t size)
{
	void *ret;
	ret = calloc(nmemb, size);
	if (unlikely(ret == NULL)) {
		int err = errno;
		pr_err("calloc(): " PRERF, PREAR(err));
		return NULL;
	}

	return ret;
}


static int init_state_ip_map(struct srv_tcp_state *state)
{
	uint16_t (*ip_map)[256];

	ip_map = calloc_wrp(256, sizeof(*ip_map));
	if (unlikely(ip_map == NULL))
		return -ENOMEM;

	for (uint16_t i = 0; i < 256; i++) {
		for (uint16_t j = 0; j < 256; j++) {
			ip_map[i][j] = IP_MAP_TO_NOP;
		}
	}

	state->ip_map = ip_map;
	return 0;
}


static int init_state_client_slot(struct srv_tcp_state *state)
{
	uint16_t max_conn = state->cfg->sock.max_conn;
	struct client_slot *clients;

	clients = calloc_wrp(max_conn, sizeof(*clients));
	if (unlikely(clients == NULL))
		return -ENOMEM;

	while (max_conn--)
		reset_client_slot(&clients[max_conn], max_conn);

	state->clients = clients;
	return 0;
}


static int init_state_epoll_map(struct srv_tcp_state *state)
{
	uint16_t *epoll_map;

	epoll_map = calloc_wrp(EPOLL_CLIENT_MAP_SIZE, sizeof(*epoll_map));
	if (unlikely(epoll_map == NULL))
		return -ENOMEM;

	state->epoll_map = epoll_map;
	return 0;
}


static int init_state_threads(struct srv_tcp_state *state)
{
	struct srv_thread *threads;
	struct srv_cfg *cfg = state->cfg;
	uint8_t num_of_threads = cfg->num_of_threads;

	if (unlikely(num_of_threads == 0)) {
		pr_err("Number of threads cannot be zero, please fix your "
		       "config");
		return -EINVAL;
	}

	threads = calloc(num_of_threads, sizeof(*threads));
	if (unlikely(threads == NULL))
		return -ENOMEM;

	for (uint8_t i = 0; i < num_of_threads; i++) {
		threads[i].state    = state;
		threads[i].epoll_fd = -1;
	}

	if (num_of_threads == 1) {
		/*
		 * We only have one thread, so we have to mix
		 * the workloads (accept, read, write) and
		 * (recv, send).
		 */
		threads[0].type  = ST_MIXED;
	} else
	if (num_of_threads > 1) {
		/*
		 * We have more than one thread, so we distribute
		 * the workloads.
		 *
		 * Main thread     : (accept, read, write)
		 * Other thread(s) : (recv, send)
		 */
		threads[0].type  = ST_ACCEPT_AND_TUN_TAP;

		for (uint8_t i = 1; i < num_of_threads; i++) {
			threads[i].type  = ST_CLIENTS_ONLY;
		}
	}

	state->threads = threads;
	return 0;
}


static int init_state(struct srv_tcp_state *state)
{
	int retval;

	state->need_ssl_cleanup   = false;
	state->stop_event_loop    = false;
	state->need_iface_down    = false;
	state->set_affinity_ok    = false;
	state->mutex_need_destroy = false;
	state->err_c              = 0;
	state->tun_fd             = -1;
	state->tcp_fd             = -1;
	state->ssl_ctx            = NULL;
	state->read_tun_c         = 0;
	state->write_tun_c        = 0;
	state->up_bytes           = 0;
	state->down_bytes         = 0;
	state->threads            = NULL;

	if (unlikely(init_state_ip_map(state) < 0))
		return -1;
	if (unlikely(init_state_client_slot(state) < 0))
		return -1;
	if (unlikely(init_state_epoll_map(state) < 0))
		return -1;
	if (unlikely(init_state_threads(state) < 0))
		return -1;

	retval = pthread_mutex_init(&state->global_mutex, NULL);
	if (unlikely(retval != 0)) {
		int err = (retval > 0) ? retval : -retval;
		pr_err("pthread_mutex_init(): " PRERF, PREAR(err));
		return -1;
	}
	state->mutex_need_destroy = true;
	return 0;
}


static int init_iface(struct srv_tcp_state *state)
{
	int tun_fd;
	struct iface_cfg *i = &state->siff;
	struct srv_iface_cfg *j = &state->cfg->iface;

	prl_notice(0, "Creating virtual network interface: \"%s\"...", j->dev);

	tun_fd = tun_alloc(j->dev, IFF_TUN | IFF_NO_PI);
	if (unlikely(tun_fd < 0))
		return -1;
	if (unlikely(fd_set_nonblock(tun_fd) < 0))
		goto out_err;

	memset(i, 0, sizeof(struct iface_cfg));
	sane_strncpy(i->dev, j->dev, sizeof(i->dev));
	sane_strncpy(i->ipv4, j->ipv4, sizeof(i->ipv4));
	sane_strncpy(i->ipv4_netmask, j->ipv4_netmask, sizeof(i->ipv4_netmask));
	i->mtu = j->mtu;

	if (unlikely(!teavpn_iface_up(i))) {
		pr_err("Cannot raise virtual network interface up");
		goto out_err;
	}

	state->tun_fd = tun_fd;
	state->need_iface_down = true;
	return 0;
out_err:
	close(tun_fd);
	return -1;
}


static int init_openssl(struct srv_tcp_state *state)
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	state->need_ssl_cleanup = true;
	return 0;
}


static void cleanup_openssl(struct srv_tcp_state *state)
{
	if (likely(state->need_ssl_cleanup)) {
		CRYPTO_cleanup_all_ex_data();
		ERR_free_strings();
		EVP_cleanup();
		state->need_ssl_cleanup = false;
	}
}


static SSL_CTX *create_ssl_context()
{
	int err;
	SSL_CTX *ctx;
	const SSL_METHOD *method;

	method = SSLv23_server_method();
	ctx    = SSL_CTX_new(method);
	if (unlikely(!ctx)) {
		err = errno;
		pr_err("Unable to create SSL context: " PRERF, PREAR(err));
		return NULL;
	}

	return ctx;
}


static int configure_ssl_context(SSL_CTX *ssl_ctx, struct srv_tcp_state *state)
{
	int retval;
	unsigned long err;
	const char *cert, *key;
	struct srv_cfg *cfg = state->cfg;

	cert = cfg->sock.ssl_cert;
	key  = cfg->sock.ssl_priv_key;

	if (unlikely(cert == NULL)) {
		pr_err("Missing sock->ssl_cert " PRERF, PREAR(EFAULT));
		return -1;
	}

	if (unlikely(key == NULL)) {
		pr_err("Missing sock->ssl_priv_key " PRERF, PREAR(EFAULT));
		return -1;
	}

	retval = SSL_CTX_use_certificate_file(ssl_ctx, cert, SSL_FILETYPE_PEM);
	if (unlikely(retval <= 0)) {
		err = ERR_get_error();
		pr_err("SSL_CTX_use_certificate_file(\"%s\"): "
		       "[%lu]:[%s]:[%s]:[%s]",
		       key,
		       err,
		       ERR_lib_error_string(err),
		       ERR_func_error_string(err),
		       ERR_reason_error_string(err));
		return -1;
	}

	retval = SSL_CTX_use_PrivateKey_file(ssl_ctx, key, SSL_FILETYPE_PEM);
	if (unlikely(retval <= 0)) {
		err = ERR_get_error();
		pr_err("SSL_CTX_use_PrivateKey_file(\"%s\"): "
		       "[%lu]:[%s]:[%s]:[%s]",
		       key,
		       err,
		       ERR_lib_error_string(err),
		       ERR_func_error_string(err),
		       ERR_reason_error_string(err));
		return -1;
	}

	return 0;
}


static int init_ssl_context(struct srv_tcp_state *state)
{
	SSL_CTX *ssl_ctx;

	ssl_ctx = create_ssl_context();
	if (unlikely(ssl_ctx == NULL))
		return -1;

	if (unlikely(configure_ssl_context(ssl_ctx, state) < 0)) {
		SSL_CTX_free(ssl_ctx);
		return -1;
	}

	state->ssl_ctx = ssl_ctx;
	return 0;
}


static int set_socket_so_incoming_cpu(int tcp_fd, struct srv_tcp_state *state)
{
	int first_isset = -1, second_isset = -1, incoming_cpu = -1;
	const void *ptr = (const void *)&incoming_cpu;
	socklen_t len = sizeof(incoming_cpu);

	/*
	 * Take second_isset CPU, if there is no second_isset CPU,
	 * then use first_isset CPU
	 */
	for (int i = 0; i < CPU_SETSIZE; i++) {
		if (!CPU_ISSET(i, &state->affinity))
			continue;
		
		if (first_isset == -1) {
			first_isset = i;
		} else
		if (second_isset == -1) {
			second_isset = i;
		} else {
			break;
		}
	}

	prl_notice(6, "first_isset CPU = %d", first_isset);
	prl_notice(6, "second_isset CPU = %d", second_isset);

	/* We have second_isset CPU */
	if (second_isset != -1) {
		incoming_cpu = second_isset;
		goto out_set;
	}

	/*
	 * We don't have second_isset CPU, but we have
	 * fisrt_isset CPU.
	 */
	if (first_isset != -1) {
		incoming_cpu = first_isset;
		goto out_set;
	}

	/*
	 * Wait what?
	 * We don't have CPU affinity at all?!
	 */
	return 0;
out_set:
	return setsockopt(tcp_fd, SOL_SOCKET, SO_INCOMING_CPU, ptr, len);
}


static int socket_setup(int tcp_fd, struct srv_tcp_state *state)
{
	int y;
	int err;
	int retval;
	const char *lv, *on; /* level and optname */
	socklen_t len = sizeof(y);
	struct srv_cfg *cfg = state->cfg;
	const void *py = (const void *)&y;

	y = 1;
	retval = setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, py, len);
	if (unlikely(retval < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_REUSEADDR";
		goto out_err;
	}

	y = 1;
	retval = setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, py, len);
	if (unlikely(retval < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_REUSEADDR";
		goto out_err;
	}

	y = 1;
	retval = setsockopt(tcp_fd, IPPROTO_TCP, TCP_NODELAY, py, len);
	if (unlikely(retval < 0)) {
		lv = "IPPROTO_TCP";
		on = "TCP_NODELAY";
		goto out_err;
	}

	y = 6;
	retval = setsockopt(tcp_fd, SOL_SOCKET, SO_PRIORITY, py, len);
	if (unlikely(retval < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_PRIORITY";
		goto out_err;
	}

	y = 1024 * 1024 * 4;
	retval = setsockopt(tcp_fd, SOL_SOCKET, SO_RCVBUFFORCE, py, len);
	if (unlikely(retval < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_RCVBUFFORCE";
		goto out_err;
	}

	y = 1024 * 1024 * 4;
	retval = setsockopt(tcp_fd, SOL_SOCKET, SO_SNDBUFFORCE, py, len);
	if (unlikely(retval < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_SNDBUFFORCE";
		goto out_err;
	}

	y = 50000;
	retval = setsockopt(tcp_fd, SOL_SOCKET, SO_BUSY_POLL, py, len);
	if (unlikely(retval < 0)) {
		lv = "SOL_SOCKET";
		on = "SO_BUSY_POLL";
		goto out_err;
	}


	retval = set_socket_so_incoming_cpu(tcp_fd, state);
	if (unlikely(retval < 0)) {
		lv  = "SOL_SOCKET";
		on  = "SO_INCOMING_CPU";
		err = errno;

		/*
		 * SO_INCOMING_CPU is not mandatory, so
		 * if it fails, keep the success state.
		 */
		pr_err("setsockopt(tcp_fd, %s, %s): " PRERF, lv, on,
		       PREAR(err));
		retval = 0;
	}


	/*
	 * Use cfg to set some socket options.
	 */
	(void)cfg;
	return retval;
out_err:
	err = errno;
	pr_err("setsockopt(tcp_fd, %s, %s): " PRERF, lv, on, PREAR(err));
	return retval;
}


static int init_socket(struct srv_tcp_state *state)
{
	int err;
	int tcp_fd;
	int retval;
	struct sockaddr_in addr;
	struct srv_sock_cfg *sock = &state->cfg->sock;

	prl_notice(0, "Creating TCP socket...");
	tcp_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (unlikely(tcp_fd < 0)) {
		err = errno;
		pr_err("socket(): " PRERF, PREAR(err));
		return -1;
	}

	prl_notice(0, "Setting socket file descriptor up...");
	retval = socket_setup(tcp_fd, state);
	if (unlikely(retval < 0))
		goto out_err;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(sock->bind_port);
	addr.sin_addr.s_addr = inet_addr(sock->bind_addr);

	retval = bind(tcp_fd, (struct sockaddr *)&addr, sizeof(addr));
	if (unlikely(retval < 0)) {
		err = errno;
		pr_err("bind(): " PRERF, PREAR(err));
		goto out_err;
	}

	retval = listen(tcp_fd, sock->backlog);
	if (unlikely(retval < 0)) {
		err = errno;
		pr_err("listen(): " PRERF, PREAR(err));
		goto out_err;
	}

	state->tcp_fd = tcp_fd;
	prl_notice(0, "Listening on %s:%d...", sock->bind_addr,
		   sock->bind_port);
	return 0;
out_err:
	close(tcp_fd);
	return -1;
}


static int epoll_add(int epl_fd, int fd, uint32_t events)
{
	int err;
	struct epoll_event event;

	/* Shut the valgrind up! */
	memset(&event, 0, sizeof(struct epoll_event));

	event.events = events;
	event.data.fd = fd;
	if (unlikely(epoll_ctl(epl_fd, EPOLL_CTL_ADD, fd, &event) < 0)) {
		err = errno;
		pr_err("epoll_ctl(EPOLL_CTL_ADD): " PRERF, PREAR(err));
		return -1;
	}
	return 0;
}


static int init_epoll_for_threads(struct srv_thread *threads,
				  uint8_t num_of_threads, uint16_t max_conn)
{
	uint8_t i;
	for (i = 0; i < num_of_threads; i++) {
		int num, epoll_fd;
		switch (threads[i].type) {
		case ST_MIXED:
			num = (int)max_conn + 3;
			break;
		case ST_ACCEPT_AND_TUN_TAP:
			num = 3;
			break;
		case ST_CLIENTS_ONLY:
			num = (int)max_conn;
			break;
		}

		epoll_fd = epoll_create(num);
		if (unlikely(epoll_fd < 0)) {
			int err = errno;
			pr_err("epoll_create(): " PRERF, PREAR(err));
			goto out_err;
		}
		threads[i].epoll_fd = epoll_fd;
	}

	return 0;

out_err:
	while (i--)
		close(threads[i].epoll_fd);
	return -1;
}


static int run_workers(struct srv_tcp_state *state)
{
	int retval;
	struct srv_thread *threads = state->threads;
	uint16_t max_conn = state->cfg->sock.max_conn;
	uint8_t num_of_threads = state->cfg->num_of_threads;

	prl_notice(0, "Initializing worker(s)...");

	retval = init_epoll_for_threads(threads, num_of_threads, max_conn);
	if (unlikely(retval < 0))
		return -1;
	return 0;
}


static void close_epoll(struct srv_thread *threads, uint8_t num_of_threads)
{
	if (unlikely(!threads))
		return;

	for (uint8_t i = 0; i < num_of_threads; i++) {
		int epoll_fd = threads[i].epoll_fd;
		if (likely(epoll_fd != -1)) {
			prl_notice(0, "Closing state->threads[%u].epoll_fd "
				   "(%d)", i, epoll_fd);
			close(epoll_fd);
		}
	}
}


static void close_file_descriptors(struct srv_tcp_state *state)
{
	int tun_fd = state->tun_fd;
	int tcp_fd = state->tcp_fd;

	if (likely(tun_fd != -1)) {
		prl_notice(0, "Closing state->tun_fd (%d)", tun_fd);
		close(tun_fd);
	}

	if (likely(tcp_fd != -1)) {
		prl_notice(0, "Closing state->tcp_fd (%d)", tcp_fd);
		close(tcp_fd);
	}

	/* TODO: close clients file descriptors */

	close_epoll(state->threads, state->cfg->num_of_threads);
}


static void destroy_state(struct srv_tcp_state *state)
{
	close_file_descriptors(state);

	if (state->ssl_ctx != NULL)
		SSL_CTX_free(state->ssl_ctx);

	if (state->mutex_need_destroy)
		pthread_mutex_destroy(&state->global_mutex);

	cleanup_openssl(state);
	free(state->ip_map);
	free(state->clients);
	free(state->epoll_map);
	free(state->threads);
}


int teavpn_server_tcp_handler(struct srv_cfg *cfg)
{
	int retval = 0;
	struct srv_tcp_state state;

	/* Shut the valgrind up! */
	memset(&state, 0, sizeof(state));

	state.cfg = cfg;
	g_state = &state;
	signal(SIGHUP, handle_interrupt);
	signal(SIGINT, handle_interrupt);
	signal(SIGTERM, handle_interrupt);
	signal(SIGQUIT, handle_interrupt);
	signal(SIGPIPE, SIG_IGN);

	retval = init_state(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_iface(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_openssl(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_ssl_context(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_socket(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = run_workers(&state);
out:
	destroy_state(&state);
	return retval;
}