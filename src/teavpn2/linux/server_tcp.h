// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#ifndef TEAVPN2__SERVER__SERVER_TCP_H
#define TEAVPN2__SERVER__SERVER_TCP_H

struct client_tcp *tcp_client_get(struct srv_ctx_tcp *ctx);
void tcp_client_put(struct srv_ctx_tcp *ctx, struct client_tcp *client);

#endif /* #ifndef TEAVPN2__SERVER__SERVER_TCP_H */
