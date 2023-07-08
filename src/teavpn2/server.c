// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */
#include <teavpn2/server.h>
#include <teavpn2/helpers.h>

#include <getopt.h>
#include <inih/inih.h>

static const struct option long_opts[] = {
	/* Help, version and verbose. */
	{"help",           no_argument,       NULL, 'h'},
	{"version",        no_argument,       NULL, 'V'},
	{"verbose",        optional_argument, NULL, 'v'},

	/*
	 * Socket configuration.
	 */
	{"encrypt",        no_argument,       NULL, 'E'},
	{"sock-type",      required_argument, NULL, 's'},
	{"bind-addr",      required_argument, NULL, 'H'},
	{"bind-port",      required_argument, NULL, 'P'},
	{"backlog",        required_argument, NULL, 'B'},
	{"max-conn",       required_argument, NULL, 'M'},
	{"event-loop",     required_argument, NULL, 'e'},
	{"ssl-cert",       required_argument, NULL, 'C'},
	{"ssl-priv-key",   required_argument, NULL, 'K'},

	/*
	 * Network configuration.
	 */
	{"dev",            required_argument, NULL, 'D'},
	{"mtu",            required_argument, NULL, 'm'},
	{"ipv4",           required_argument, NULL, '4'},
	{"ipv6",           required_argument, NULL, '6'},

	/*
	 * System configuration.
	 */
	{"config",         required_argument, NULL, 'c'},
	{"data-dir",       required_argument, NULL, 'd'},
	{"max-thread",     required_argument, NULL, 't'},

	{NULL, 0, NULL, 0}
};
static const char short_opts[] = "hVv::"
				 "Es:H:P:B:M:e:C:K:"
				 "D:m:4:6:"
				 "c:d:t:";


/*
 * Socket configuration default values.
 */
static const bool d_use_encryption = false;
static const uint8_t d_sock_type = SOCK_DGRAM;
static const char d_bind_addr[] = "::";
static const uint16_t d_bind_port = 61111;
static const int d_backlog = 128;
static const uint32_t d_max_conn = 1024;
static const char d_event_loop[] = "epoll";
static const char d_ssl_cert[] = "/etc/teavpn2/server.crt";
static const char d_ssl_priv_key[] = "/etc/teavpn2/server.key";

/*
 * Network configuration default values.
 */
static const char d_dev[] = "tvpn-s0";
static const uint16_t d_mtu = 1400;
static const char d_ipv4[] = "10.77.77.1";
static const char d_ipv6[] = "fc:aaaa:bbbb:cccc:1";

/*
 * System configuration default values.
 */
static const char d_config[] = "/etc/teavpn2/server.conf";
static const char d_data_dir[] = "/var/lib/teavpn2";
static const uint8_t d_max_thread = 4;


__cold static void set_default_value_cfg_server(struct srv_cfg *cfg)
{
	struct srv_cfg_sock *sock = &cfg->sock;
	struct srv_cfg_net *net = &cfg->net;
	struct srv_cfg_sys *sys = &cfg->sys;

	memset(cfg, 0, sizeof(*cfg));

	/* Socket configuration. */
	sock->use_encryption = d_use_encryption;
	sock->type = d_sock_type;
	memcpy(sock->bind_addr, d_bind_addr, sizeof(d_bind_addr));
	sock->bind_port = d_bind_port;
	sock->backlog = d_backlog;
	sock->max_conn = d_max_conn;
	memcpy(sock->event_loop, d_event_loop, sizeof(d_event_loop));
	sock->ssl_cert = d_ssl_cert;
	sock->ssl_priv_key = d_ssl_priv_key;

	/* Network configuration. */
	memcpy(net->dev, d_dev, sizeof(d_dev));
	net->mtu = d_mtu;
	memcpy(net->ipv4, d_ipv4, sizeof(d_ipv4));
	memcpy(net->ipv6, d_ipv6, sizeof(d_ipv6));

	/* System configuration. */
	sys->cfg_file = d_config;
	sys->data_dir = d_data_dir;
	sys->max_thread = d_max_thread;
}

__cold static void show_server_help(const char *app)
{
	printf("Usage: %s server [OPTIONS]\n", app);
	printf("\n Options:\n");
	printf("  -h, --help              Show this help message and exit\n");
	printf("  -V, --version           Show version information and exit\n");
	printf("  -v, --verbose[=LEVEL]   Increase verbosity level (range: 0-3) [default: 0]\n");
	printf("\n");
	printf("  -E, --encrypt           Enable encryption\n");
	printf("  -s, --sock-type=TYPE    Set socket type (tcp/udp) [default: udp]\n");
	printf("  -H, --bind-addr=ADDR    Set bind address [default: %s]\n", d_bind_addr);
	printf("  -P, --bind-port=PORT    Set bind port [default: %hu]\n", d_bind_port);
	printf("  -B, --backlog=NUM       Set listen backlog, only for TCP [default: %d]\n", d_backlog);
	printf("  -M, --max-conn=NUM      Set the maximum number of connections [default: %u]\n", d_max_conn);
	printf("  -e, --event-loop=NAME   Set event loop (epoll/poll/io_uring) [default: %s]\n", d_event_loop);
	printf("  -C, --ssl-cert=FILE     Set SSL certificate file [default: %s]\n", d_ssl_cert);
	printf("  -K, --ssl-priv-key=FILE Set SSL private key file [default: %s]\n", d_ssl_priv_key);
	printf("\n");
	printf("  -D, --dev=NAME          Set device name [default: %s]\n", d_dev);
	printf("  -m, --mtu=MTU           Set MTU [default: %hu]\n", d_mtu);
	printf("  -4, --ipv4=ADDR         Set IPv4 address [default: %s]\n", d_ipv4);
	printf("  -6, --ipv6=ADDR         Set IPv6 address [default: %s]\n", d_ipv6);
	printf("\n");
	printf("  -c, --config=FILE       Set configuration file [default: %s]\n", d_config);
	printf("  -d, --data-dir=DIR      Set data directory [default: %s]\n", d_data_dir);
	printf("  -t, --max-thread=NUM    Set the maximum number of threads [default: %hhu]\n", d_max_thread);
	printf("\n");
}

__cold static void print_server_einval(const char *app)
{
	fprintf(stderr, "\nTry `%s server --help' for more information.\n", app);
}

__cold static int parse_argv_server(int argc, char *argv[], struct srv_cfg *cfg)
{
	struct srv_cfg_sock *sock = &cfg->sock;
	struct srv_cfg_net *net = &cfg->net;
	struct srv_cfg_sys *sys = &cfg->sys;
	int ret;

	while (1) {
		int c = getopt_long(argc, argv, short_opts, long_opts, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			show_server_help(argv[0]);
			return 1;
		case 'V':
			show_version();
			return 1;
		case 'v':
			__log_level = 1;
			if (optarg)
				__log_level = (uint8_t)atoi(optarg);
			break;
		case 'c':
			sys->cfg_file = optarg;
			break;
		case 'd':
			sys->data_dir = optarg;
			break;
		case 't':
			sys->max_thread = (uint8_t)atoi(optarg);
			break;
		case 'D':
			strecpy(net->dev, optarg, sizeof(net->dev));
			break;
		case 'm':
			net->mtu = (uint16_t)atoi(optarg);
			break;
		case '4':
			strecpy(net->ipv4, optarg, sizeof(net->ipv4));
			break;
		case '6':
			strecpy(net->ipv6, optarg, sizeof(net->ipv6));
			break;
		case 's':
			ret = parse_socket_type(optarg, &sock->type);
			break;
		case 'H':
			strecpy(sock->bind_addr, optarg,
				sizeof(sock->bind_addr));
			break;
		case 'P':
			sock->bind_port = (uint16_t)atoi(optarg);
			break;
		case 'B':
			sock->backlog = (uint16_t)atoi(optarg);
			break;
		case 'E':
			sock->use_encryption = true;
			break;
		case 'M':
			sock->max_conn = (uint16_t)atoi(optarg);
			break;
		case '?':
		default:
			print_server_einval(argv[0]);
			return -EINVAL;
		}

		if (ret < 0)
			return ret;
	}

	return 0;
}

struct cfg_parse_ctx {
	struct srv_cfg	*cfg;
	int		err;
};

static int server_cfg_parse_sock(struct cfg_parse_ctx *ctx, const char *name,
				 const char *val, int lineno)
{
	struct srv_cfg_sock *sock = &ctx->cfg->sock;
	struct srv_cfg_sys *sys = &ctx->cfg->sys;

	if (!strcmp(name, "use_encryption")) {
		sock->use_encryption = (bool)atoi(val);
	} else if (!strcmp(name, "type")) {
		int ret = parse_socket_type(val, &sock->type);
		if (ret < 0) {
			fprintf(stderr, "Invalid socket type \"%s\" in %s:%d\n",
				val, sys->cfg_file, lineno);
			ctx->err = ret;
			return 0;
		}
	} else if (!strcmp(name, "bind_addr")) {
		strecpy(sock->bind_addr, val, sizeof(sock->bind_addr));
	} else if (!strcmp(name, "bind_port")) {
		sock->bind_port = (uint16_t)atoi(val);
	} else if (!strcmp(name, "backlog")) {
		sock->backlog = (uint16_t)atoi(val);
	} else if (!strcmp(name, "max_conn")) {
		sock->max_conn = (uint16_t)atoi(val);
	} else {
		fprintf(stderr, "Unknown option \"%s\" in %s:%d\n", name,
			sys->cfg_file, lineno);
		ctx->err = -EINVAL;
		return 0;
	}

	return 1;
}

static int server_cfg_parse_net(struct cfg_parse_ctx *ctx, const char *name,
				const char *val, int lineno)
{
	struct srv_cfg_net *net = &ctx->cfg->net;
	struct srv_cfg_sys *sys = &ctx->cfg->sys;

	if (!strcmp(name, "dev")) {
		strecpy(net->dev, val, sizeof(net->dev));
	} else if (!strcmp(name, "mtu")) {
		net->mtu = (uint16_t)atoi(val);
	} else if (!strcmp(name, "ipv4")) {
		strecpy(net->ipv4, val, sizeof(net->ipv4));
	} else if (!strcmp(name, "ipv6")) {
		strecpy(net->ipv6, val, sizeof(net->ipv6));
	} else {
		fprintf(stderr, "Unknown option \"%s\" in %s:%d\n", name,
			sys->cfg_file, lineno);
		ctx->err = -EINVAL;
		return 0;
	}

	return 1;
}

static int server_cfg_parse_sys(struct cfg_parse_ctx *ctx, const char *name,
				const char *val, int lineno)
{
	struct srv_cfg_sys *sys = &ctx->cfg->sys;

	if (!strcmp(name, "cfg_file")) {
		sys->cfg_file = val;
	} else if (!strcmp(name, "data_dir")) {
		sys->data_dir = val;
	} else if (!strcmp(name, "max_thread")) {
		sys->max_thread = (uint8_t)atoi(val);
	} else {
		fprintf(stderr, "Unknown option \"%s\" in %s:%d\n", name,
			sys->cfg_file, lineno);
		ctx->err = -EINVAL;
		return 0;
	}

	return 1;
}

/*
 * If success, returns 1.
 * If failure, returns 0.
 */
static int server_cfg_parser(void *user, const char *section, const char *name,
			     const char *val, int lineno)
{
	struct cfg_parse_ctx *ctx = (struct cfg_parse_ctx *)user;
	struct srv_cfg_sys *sys = &ctx->cfg->sys;

	if (!strcmp(section, "sock"))
		return server_cfg_parse_sock(ctx, name, val, lineno);
	else if (!strcmp(section, "net"))
		return server_cfg_parse_net(ctx, name, val, lineno);
	else if (!strcmp(section, "sys"))
		return server_cfg_parse_sys(ctx, name, val, lineno);

	fprintf(stderr, "Unknown section \"%s\" in %s:%d\n", section,
		sys->cfg_file, lineno);
	return 0;
}

static int load_cfg_server(struct srv_cfg *cfg)
{
	const char *file = cfg->sys.cfg_file;
	struct cfg_parse_ctx ctx;
	FILE *handle;
	int ret;

	/*
	 * Use --config="" to disable the configuration file.
	 */
	if (!file || !file[0])
		return 0;

	handle = fopen(file, "rb");
	if (!handle && file != d_config) {
		ret = -errno;
		fprintf(stderr, "Failed to open configuration file: %s: %s\n",
			file, strerror(-ret));
		return ret;
	}

	/*
	 * If the configuration file is not specified, we will use the
	 * default configuration file.
	 *
	 * If the default configuration file cannot be opened, we will
	 * use the default configuration.
	 */
	if (!handle)
		return 0;

	ctx.cfg = cfg;
	ctx.err = 0;
	ret = ini_parse_file(handle, server_cfg_parser, &ctx);
	fclose(handle);
	if (ret < 0) {
		ret = ctx.err;
		fprintf(stderr, "Failed to parse configuration file: %s: %s\n",
			file, strerror(-ret));
		return ret;
	}

	return 0;
}

int run_server(int argc, char *argv[])
{
	struct srv_cfg cfg;
	int ret;

	/*
	 * A preparation to get the configuration file.
	 */
	ret = parse_argv_server(argc, argv, &cfg);
	if (ret)
		goto out;

	set_default_value_cfg_server(&cfg);
	ret = load_cfg_server(&cfg);
	if (ret < 0)
		goto out;

	/*
	 * Call it again.
	 *
	 * The command line arguments override the values in the
	 * configuration file.
	 */
	optind = 1;
	ret = parse_argv_server(argc, argv, &cfg);
	if (ret)
		goto out;

	ret = run_server_app(&cfg);
out:
	if (ret < 0)
		return -ret;

	return 0;
}
