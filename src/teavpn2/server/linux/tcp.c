
#include <unistd.h>
#include <signal.h>
#include <stdalign.h>
#include <sys/epoll.h>
#include <netinet/tcp.h>
#include <teavpn2/base.h>
#include <teavpn2/net/iface.h>
#include <teavpn2/server/tcp.h>


#define EPT_MAP_SIZE	(0xffffu)
#define EPT_MAP_NOP	(0xffffu)	/* Unused map (nop = no operation for index) */
#define EPT_MAP_TO_TUN	(0x0u)
#define EPT_MAP_TO_NET	(0x1u)
#define EPT_MAP_ADD	(0x2u)
#define EPOLL_IN_EVT	(EPOLLIN | EPOLLPRI)

/* Macros for printing */
#define W_IP(CL) ((CL)->src_ip), ((CL)->src_port)
#define W_UN(CL) ((CL)->uname)
#define W_IU(CL) W_IP(CL), W_UN(CL)
#define PRWIU "%s:%d (%s)"

struct tcp_client {
	int			cli_fd;		/* Client TCP file descriptor */
	uint32_t		recv_c;		/* sys_recv counter           */
	uint32_t		send_c;		/* sys_send counter           */
	uint16_t		sidx;		/* Client slot index          */
	char			uname[64];	/* Client username            */
	bool			is_auth;	/* Is authenticated?          */
	bool			is_used;	/* Is used?                   */
	bool			is_conn;	/* Is connected?              */
	uint8_t			err_c;		/* Error counter              */
	char			src_ip[IPV4_L];	/* Source IP                  */
	uint16_t		src_port;	/* Source port                */
};


struct _cl_stk {
	/*
	 * Stack to retrieve client slot in O(1) time complexity
	 */
	uint16_t		sp;		/* Stack pointer              */
	uint16_t		max_sp;		/* Max stack pointer          */
	struct_pad(0, 4);
	uint16_t		*arr;		/* The array container        */
};


struct srv_tcp_state {
	pid_t			pid;		/* Main process PID           */
	int			epl_fd;		/* Epoll fd                   */
	int			net_fd;		/* Main TCP socket fd         */
	int			tun_fd;		/* TUN/TAP fd                 */
	bool			stop;		/* Stop the event loop?       */
	struct_pad(0, 7);
	struct _cl_stk		cl_stk;		/* Stack for slot resolution  */
	uint16_t		*epl_map;	/* Epoll map to client slot   */
	struct tcp_client	*(*ipm)[256];	/* IP address map             */
	struct tcp_client	*clients;	/* Client slot                */
	struct srv_cfg		*cfg;		/* Config                     */
};


static struct srv_tcp_state *g_state;


static void interrupt_handler(int sig)
{
	struct srv_tcp_state *state = g_state;

	state->stop = true;
	putchar('\n');
	pr_notice("Signal %d (%s) has been caught", sig, strsignal(sig));
}


static int32_t push_cl(struct _cl_stk *cl_stk, uint16_t val)
{
	uint16_t sp = cl_stk->sp;

	assert(sp > 0);
	cl_stk->arr[--sp] = val;
	cl_stk->sp = sp;
	return (int32_t)val;
}


static int32_t pop_cl(struct _cl_stk *cl_stk)
{
	int32_t val;
	uint16_t sp = cl_stk->sp;
	uint16_t max_sp = cl_stk->max_sp;

	/* sp must never be higher than max_sp */
	assert(sp <= max_sp);

	if (unlikely(sp == max_sp)) {
		/* There is nothing on the stack */
		return -1;
	}

	val = (int32_t)cl_stk->arr[sp];
	cl_stk->sp = ++sp;
	return (int32_t)val;
}


static void tcp_client_init(struct tcp_client *client, uint16_t sidx)
{
	client->cli_fd   = -1;
	client->recv_c   = 0;
	client->send_c   = 0;
	client->uname[0] = '_';
	client->uname[1] = '\0';
	client->sidx     = sidx;
	client->is_used  = false;
	client->is_auth  = false;
	client->is_conn  = false;
	client->err_c    = 0;
}


static int init_state(struct srv_tcp_state *state)
{
	int err;
	uint16_t max_conn;
	struct _cl_stk *cl_stk;
	uint16_t *epl_map = NULL;
	uint16_t *stack_arr = NULL;
	struct tcp_client *clients = NULL;
	struct tcp_client *(*ipm)[256] = NULL;

	max_conn = state->cfg->sock.max_conn;

	clients = calloc(max_conn, sizeof(struct tcp_client));
	if (unlikely(clients == NULL))
		goto out_err;

	stack_arr = calloc(max_conn, sizeof(uint16_t));
	if (unlikely(stack_arr == NULL))
		goto out_err;

	epl_map = calloc(EPT_MAP_SIZE, sizeof(uint16_t));
	if (unlikely(epl_map == NULL))
		goto out_err;

	ipm = calloc(256u, sizeof(struct tcp_client *[256u]));
	if (unlikely(ipm == NULL))
		goto out_err;

	cl_stk         = &state->cl_stk;
	cl_stk->sp     = max_conn; /* Stack growsdown, so start from high idx */
	cl_stk->max_sp = max_conn;
	cl_stk->arr    = stack_arr;

	for (uint16_t i = 0; i < max_conn; i++)
		tcp_client_init(clients + i, i);

	for (uint16_t i = 0; i < EPT_MAP_SIZE; i++)
		epl_map[i] = EPT_MAP_NOP;

	for (uint16_t i = max_conn; i--;)
		push_cl(&state->cl_stk, i);

	for (uint16_t i = 0; i < 256u; i++) {
		for (uint16_t j = 0; j < 256u; j++) {
			ipm[i][j] = NULL;
		}
	}

	state->epl_fd    = -1;
	state->net_fd    = -1;
	state->tun_fd    = -1;
	state->stop      = false;
	state->epl_map   = epl_map;
	state->ipm       = ipm;
	state->clients   = clients;
	state->pid       = getpid();

	prl_notice(0, "My PID is %d", state->pid);

	return 0;

out_err:
	err = errno;
	free(clients);
	free(stack_arr);
	free(epl_map);
	pr_err("calloc: Cannot allocate memory: " PRERF, PREAR(err));
	return -ENOMEM;
}


static int socket_setup(int fd, struct srv_cfg *cfg)
{
	int rv;
	int err;
	int y;
	socklen_t len = sizeof(y);
	const void *pv = (const void *)&y;

	y = 1;
	rv = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	y = 1;
	rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	y = 1;
	rv = setsockopt(fd, SOL_SOCKET, SO_INCOMING_CPU, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	y = 1024 * 1024 * 2;
	rv = setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	y = 1024 * 1024 * 2;
	rv = setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	y = 5000;
	rv = setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, pv, len);
	if (unlikely(rv < 0))
		goto out_err;

	/*
	 * TODO: Utilize `cfg` to set some socket options from config
	 */
	(void)cfg;
	return rv;
out_err:
	err = errno;
	pr_err("setsockopt(): " PRERF, PREAR(err));
	return rv;
}


static int init_iface(struct srv_tcp_state *state)
{
	int fd;
	struct iface_cfg i;
	struct srv_iface_cfg *j = &state->cfg->iface;

	prl_notice(0, "Creating virtual network interface: \"%s\"...", j->dev);

	fd = tun_alloc(j->dev, IFF_TUN);
	if (unlikely(fd < 0))
		return -1;
	if (unlikely(fd_set_nonblock(fd) < 0))
		goto out_err;

	memset(&i, 0, sizeof(struct iface_cfg));
	strncpy(i.dev, j->dev, sizeof(i.dev) - 1);
	strncpy(i.ipv4, j->ipv4, sizeof(i.ipv4) - 1);
	strncpy(i.ipv4_netmask, j->ipv4_netmask, sizeof(i.ipv4_netmask) - 1);
	i.mtu = j->mtu;

	if (unlikely(!teavpn_iface_up(&i))) {
		pr_err("Cannot raise virtual network interface up");
		goto out_err;
	}

	state->tun_fd = fd;
	return 0;
out_err:
	close(fd);
	return -1;
}


static int init_socket(struct srv_tcp_state *state)
{
	int fd;
	int err;
	int retval;
	struct sockaddr_in addr;
	struct srv_sock_cfg *sock = &state->cfg->sock;

	prl_notice(0, "Creating TCP socket...");
	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
	if (unlikely(fd < 0)) {
		err = errno;
		retval = -err;
		pr_err("socket(): " PRERF, PREAR(err));
		goto out_err;
	}

	prl_notice(0, "Setting up socket file descriptor...");
	retval = socket_setup(fd, state->cfg);
	if (unlikely(retval < 0))
		goto out_err;

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(sock->bind_port);
	addr.sin_addr.s_addr = inet_addr(sock->bind_addr);

	retval = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (unlikely(retval < 0)) {
		err = errno;
		retval = -err;
		pr_err("bind(): " PRERF, PREAR(err));
		goto out_err;
	}

	retval = listen(fd, sock->backlog);
	if (unlikely(retval < 0)) {
		err = errno;
		retval = -err;
		pr_err("listen(): " PRERF, PREAR(err));
		goto out_err;
	}

	state->net_fd = fd;
	prl_notice(0, "Listening on %s:%u...", sock->bind_addr,
		   sock->bind_port);

	return retval;
out_err:
	if (fd > 0)
		close(fd);
	return retval;
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


static int init_epoll(struct srv_tcp_state *state)
{
	int err;
	int ret;
	int epl_fd = -1;
	int tun_fd = state->tun_fd;
	int net_fd = state->net_fd;

	prl_notice(0, "Initializing epoll fd...");
	epl_fd = epoll_create((int)state->cfg->sock.max_conn + 3);
	if (unlikely(epl_fd < 0))
		goto out_create_err;

	state->epl_map[tun_fd] = EPT_MAP_TO_TUN;
	ret = epoll_add(epl_fd, tun_fd, EPOLL_IN_EVT);
	if (unlikely(ret < 0))
		goto out_err;

	state->epl_map[net_fd] = EPT_MAP_TO_NET;
	ret = epoll_add(epl_fd, net_fd, EPOLL_IN_EVT);
	if (unlikely(ret < 0))
		goto out_err;

	state->epl_fd = epl_fd;
	return 0;

out_create_err:
	err = errno;
	pr_err("epoll_create(): " PRERF, PREAR(err));
out_err:
	if (epl_fd > 0)
		close(epl_fd);
	return -1;
}


static void handle_iface_read(int tun_fd, struct srv_tcp_state *state)
{
	(void)tun_fd;
	(void)state;
}


static bool resolve_new_conn(int cli_fd, struct sockaddr_in *addr,
			     struct srv_tcp_state *state)
{
	(void)cli_fd;
	(void)addr;
	(void)state;

	int err;
	uint16_t idx;
	uint16_t sport;
	int32_t ret_idx;
	char buf[IPV4_L + 1];
	struct tcp_client *client;
	uint32_t saddr = addr->sin_addr.s_addr;

	const char *sip;

	/* Get readable source IP address */
	sip = inet_ntop(AF_INET, &addr->sin_addr, buf, IPV4_L);
	if (unlikely(sip == NULL)) {
		err = errno;
		err = err ? err : EINVAL;
		pr_err("inet_ntop(%u): " PRERF, saddr, PREAR(err));
		return false;
	}

	/* Get readable source port */
	sport = ntohs(addr->sin_port);

	ret_idx = pop_cl(&state->cl_stk);
	if (unlikely(ret_idx == -1)) {
		prl_notice(0, "Client slot is full, can't accept connection");
		prl_notice(0, "Dropping connection from %s:%u", sip, sport);
		return false;
	}


	/*
	 * Welcome new connection.
	 * We have an available slot for this new client.
	 */
	idx = (uint16_t)ret_idx;
	err = epoll_add(state->epl_fd, cli_fd, EPOLL_IN_EVT);
	if (unlikely(err < 0)) {
		pr_error("Cannot accept new connection from %s:%u because of "
			 "error on epoll_add()", sip, sport);
		return false;
	}


	/*
	 * state->epl_map[cli_fd] must not be in use
	 */
	assert(state->epl_map[cli_fd] == EPT_MAP_NOP);


	/*
	 * Map the FD to translate to idx later
	 */
	state->epl_map[cli_fd] = idx + EPT_MAP_ADD;


	client = &state->clients[idx];

	client->is_used  = true;
	client->is_conn  = true;
	client->cli_fd   = cli_fd;
	client->src_port = sport;

	strncpy(client->src_ip, sip, IPV4_L - 1);
	client->src_ip[IPV4_L - 1] = '\0';

	assert(client->sidx == idx);

	prl_notice(0, "New connection from " PRWIU " (fd:%d)", W_IU(client),
		   cli_fd);

	return true;
}


static void accept_new_conn(int net_fd, struct srv_tcp_state *state)
{
	int err;
	int cli_fd;
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(struct sockaddr_in);

	memset(&addr, 0, addrlen);
	cli_fd = accept(net_fd, (void *)&addr, &addrlen);
	if (unlikely(cli_fd < 0)) {
		err = errno;
		if (err == EAGAIN)
			return;

		pr_err("accept: " PRERF, PREAR(err));
		return;
	}

	if (unlikely(!resolve_new_conn(cli_fd, &addr, state)))
		close(cli_fd);
}


static int handle_event(struct srv_tcp_state *state, struct epoll_event *event)
{
	int fd;
	bool is_err;
	uint16_t map_to;
	uint32_t revents;
	uint16_t *epl_map = state->epl_map;
	const uint32_t errev = EPOLLERR | EPOLLHUP;

	fd      = event->data.fd;
	revents = event->events;
	is_err  = ((revents & errev) != 0);
	map_to  = epl_map[fd];

	switch (map_to) {
	case EPT_MAP_TO_TUN:
		if (unlikely(is_err)) {
			pr_err("tun_fd wait error");
			return -1;
		}
		handle_iface_read(fd, state);
		break;
	case EPT_MAP_TO_NET:
		if (unlikely(is_err)) {
			pr_err("net_fd wait error");
			return -1;
		}
		accept_new_conn(fd, state);
		break;
	default:
		map_to -= EPT_MAP_ADD;
		break;
	}

	return 0;
}


static int event_loop(struct srv_tcp_state *state)
{
	int err;
	int epl_ret;
	int retval = 0;
	int maxevents = 32;
	int epl_fd = state->epl_fd;
	struct epoll_event events[32];

	while (likely(!state->stop)) {
		epl_ret = epoll_wait(epl_fd, events, maxevents, 3000);
		if (unlikely(epl_ret == 0)) {
			/*
			 * epoll reached timeout.
			 *
			 * TODO: Do something meaningful here...
			 * Maybe keep alive ping to clients?
			 */
			continue;
		}

		if (unlikely(epl_ret < 0)) {
			err = errno;
			if (err == EINTR) {
				retval = 0;
				prl_notice(0, "Interrupted!");
				continue;
			}

			retval = -err;
			pr_error("epoll_wait(): " PRERF, PREAR(err));
			break;
		}

		for (int i = 0; likely(i < epl_ret); i++) {
			retval = handle_event(state, &events[i]);
			if (retval < 0)
				goto out;
		}
	}

out:
	return retval;
}


static void destroy_state(struct srv_tcp_state *state)
{
	int epl_fd = state->epl_fd;
	int tun_fd = state->tun_fd;
	int net_fd = state->net_fd;
	struct tcp_client *clients = state->clients;
	uint16_t max_conn = state->cfg->sock.max_conn;

	prl_notice(0, "Cleaning state...");
	state->stop = true;

	if (likely(tun_fd != -1)) {
		prl_notice(0, "Closing state->tun_fd (%d)", tun_fd);
		close(tun_fd);
	}

	if (likely(net_fd != -1)) {
		prl_notice(0, "Closing state->net_fd (%d)", net_fd);
		close(net_fd);
	}

	if (likely(epl_fd != -1)) {
		prl_notice(0, "Closing state->epl_fd (%d)", epl_fd);
		close(epl_fd);
	}

	if (unlikely(clients != NULL)) {
		while (likely(max_conn--)) {
			struct tcp_client *client = clients + max_conn;

			if (unlikely(!client->is_used))
				goto clear;
			
			prl_notice(0, "Closing clients[%d].cli_fd (%d)",
				   max_conn, client->cli_fd);
			close(client->cli_fd);

		clear:
			memset(client, 0, sizeof(struct tcp_client));
		}
	}

	free(state->ipm);
	free(state->clients);
	free(state->epl_map);
	free(state->cl_stk.arr);

	state->ipm = NULL;
	state->clients = NULL;
	state->epl_map = NULL;
	state->cl_stk.arr = NULL;
	prl_notice(0, "Cleaned up!");
}


int teavpn_server_tcp_handler(struct srv_cfg *cfg)
{
	int retval;
	struct srv_tcp_state state;

	/* Shut the valgrind up! */
	memset(&state, 0, sizeof(struct srv_tcp_state));

	state.cfg = cfg;
	g_state = &state;
	signal(SIGHUP, interrupt_handler);
	signal(SIGINT, interrupt_handler);
	signal(SIGTERM, interrupt_handler);
	signal(SIGQUIT, interrupt_handler);
	signal(SIGPIPE, SIG_IGN);

	retval = init_state(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_iface(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_socket(&state);
	if (unlikely(retval < 0))
		goto out;
	retval = init_epoll(&state);
	if (unlikely(retval < 0))
		goto out;
	prl_notice(0, "Initialization Sequence Completed");
	retval = event_loop(&state);
out:
	destroy_state(&state);
	return retval;
}
