// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef TEAVPN2__PACKET_H
#define TEAVPN2__PACKET_H

#include <teavpn2/common.h>
#include <assert.h>
#include <stdint.h>

enum {
	TCLI_PKT_HANDSHAKE	= 0u,
	TCLI_PKT_AUTH		= 1u,
	TCLI_PKT_TUN_DATA	= 2u,
	TCLI_PKT_REQSYNC	= 3u,
	TCLI_PKT_SYNC		= 4u,
	TCLI_PKT_CLOSE		= 5u,
};

enum {
	TSRV_PKT_HANDSHAKE		= 0u,
	TSRV_PKT_AUTH_OK		= 1u,
	TSRV_PKT_TUN_DATA		= 2u,
	TSRV_PKT_REQSYNC		= 3u,
	TSRV_PKT_SYNC			= 4u,
	TSRV_PKT_CLOSE			= 5u,
	TSRV_PKT_HANDSHAKE_REJECT	= 6u,
	TSRV_PKT_AUTH_REJECT		= 7u,
	TSRV_PKT_IPV4_ADDR		= 8u,
	TSRV_PKT_IPV6_ADDR		= 9u,
};

/*
 * Handshake reject type. Only sent by the server.
 */
enum {
	TSRV_HSRJ_VERSION_TOO_LOW	= 0u,
	TSRV_HSRJ_VERSION_TOO_HIGH	= 1u,
	TSRV_HSRJ_INVALID		= 2u,
};

/*
 * Authentication reject type. Only sent by the server.
 */
enum {
	TSRV_AURJ_INVALID_USERNAME	= 0u,
	TSRV_AURJ_INVALID_PASSWORD	= 1u,

	/*
	 * The server database of the user is invalid.
	 * This is a server side problem.
	 */
	TSRV_AURJ_INVALID_SERVER_CRED	= 2u,

	TSRV_AURJ_INVALID		= 3u,
};

#define PER_PACKET_SIZE		2048

struct pkt_header {
	uint8_t		type;
	uint8_t		pad_len;
	uint16_t	len;
};
OFFSET_ASSERT(struct pkt_header, 0, type);
OFFSET_ASSERT(struct pkt_header, 1, pad_len);
OFFSET_ASSERT(struct pkt_header, 2, len);
SIZE_ASSERT(struct pkt_header, 4);
#define PKT_HEADER_SIZE	4


/*
 * The handshake packet is used to negotiate the version
 * between client and server. Sent by both client and server.
 */
struct pkt_handshake {
	struct teavpn2_version	cur;
	struct teavpn2_version	min;
	struct teavpn2_version	max;
};
OFFSET_ASSERT(struct pkt_handshake, 0, cur);
OFFSET_ASSERT(struct pkt_handshake, 32, min);
OFFSET_ASSERT(struct pkt_handshake, 64, max);
SIZE_ASSERT(struct pkt_handshake, 96);


/*
 * The authentication packet is used to authenticate the client
 * to the server. Only sent by the client.
 */
struct pkt_auth {
	char		username[256];
	char		password[256];
};
OFFSET_ASSERT(struct pkt_auth, 0, username);
OFFSET_ASSERT(struct pkt_auth, 256, password);
SIZE_ASSERT(struct pkt_auth, 512);


/*
 * The handshake reject packet is used to reject the handshake
 * packet from the client. Only sent by the server.
 */
struct pkt_hsrj {
	uint8_t		reason;
	char		extra[31];
};
OFFSET_ASSERT(struct pkt_hsrj, 0, reason);
OFFSET_ASSERT(struct pkt_hsrj, 1, extra);
SIZE_ASSERT(struct pkt_hsrj, 32);


/*
 * The authentication reject packet is used to reject the
 * authentication packet from the client. Only sent by the server.
 */
struct pkt_aurj {
	uint8_t		reason;
	char		extra[31];
};
OFFSET_ASSERT(struct pkt_aurj, 0, reason);
OFFSET_ASSERT(struct pkt_aurj, 1, extra);
SIZE_ASSERT(struct pkt_aurj, 32);


/*
 * The IPv4 address assignment packet.
 * Only sent by the server.
 */
struct pkt_iface4 {
	uint8_t		ip[4];
	uint8_t		gateway[4];
	uint8_t		cidr;
	uint8_t		__pad[7];
};
OFFSET_ASSERT(struct pkt_iface4, 0, ip);
OFFSET_ASSERT(struct pkt_iface4, 4, gateway);
OFFSET_ASSERT(struct pkt_iface4, 8, cidr);
OFFSET_ASSERT(struct pkt_iface4, 9, __pad);
SIZE_ASSERT(struct pkt_iface4, 16);


/*
 * The IPv6 address assignment packet.
 * Only sent by the server.
 */
struct pkt_iface6 {
	uint8_t		ip[16];
	uint8_t		gateway[16];
	uint8_t		cidr;
	uint8_t		__pad[31];
};
OFFSET_ASSERT(struct pkt_iface6, 0, ip);
OFFSET_ASSERT(struct pkt_iface6, 16, gateway);
OFFSET_ASSERT(struct pkt_iface6, 32, cidr);
OFFSET_ASSERT(struct pkt_iface6, 33, __pad);
SIZE_ASSERT(struct pkt_iface6, 64);


struct pkt {
	struct pkt_header hdr;
	union {
		uint8_t	__raw[PER_PACKET_SIZE - PKT_HEADER_SIZE];

		/*
		 * Sent by the client and server.
		 */
		struct pkt_handshake	handshake;

		/*
		 * Only sent by the client.
		 */
		struct pkt_auth		auth;

		/*
		 * Only sent by the server.
		 */
		struct pkt_hsrj		hsrj;
		struct pkt_aurj		aurj;
		struct pkt_iface4	iface4;
		struct pkt_iface6	iface6;
	};
};
OFFSET_ASSERT(struct pkt, 0, hdr);
OFFSET_ASSERT(struct pkt, 4, __raw);
OFFSET_ASSERT(struct pkt, 4, handshake);
OFFSET_ASSERT(struct pkt, 4, auth);
OFFSET_ASSERT(struct pkt, 4, hsrj);
OFFSET_ASSERT(struct pkt, 4, aurj);
OFFSET_ASSERT(struct pkt, 4, iface4);
OFFSET_ASSERT(struct pkt, 4, iface6);
SIZE_ASSERT(struct pkt, PER_PACKET_SIZE);

#endif /* #ifndef TEAVPN2__PACKET_H */
