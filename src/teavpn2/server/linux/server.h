// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */

#ifndef TEAVPN2__SERVER__LINUX__SERVER_H
#define TEAVPN2__SERVER__LINUX__SERVER_H

typedef _Atomic(uint16_t) atomic_u16;

enum ev_loop {
	EL_EPOLL,
	EL_IO_URING
};

struct srv_state {
	/*
	 * To determine whether the event loop should stop.
	 */
	volatile bool				stop;

	/*
	 * The event loop type. Currently, the only valid
	 * values are EL_EPOLL and EL_IO_URING.
	 */
	uint8_t					evt_loop_type;
};


#endif /* #ifndef TEAVPN2__SERVER__LINUX__SERVER_H */
