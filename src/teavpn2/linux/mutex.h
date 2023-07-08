// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 * Copyright (C) 2023  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */

#ifndef TEAVPN2__AP__LINUX__MUTEX_H
#define TEAVPN2__AP__LINUX__MUTEX_H

#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>

#define CONFIG_DEBUG_MUTEX

struct qmutex {
	pthread_mutex_t		mutex;

#ifdef CONFIG_DEBUG_MUTEX
	_Atomic(bool)		locked;
	void			*leak_assert;
#endif
};

struct qcond {
	pthread_cond_t		cond;
};

typedef struct qmutex mutex_t;
typedef struct qcond cond_t;

extern int mutex_init(mutex_t *m);
extern int mutex_destroy(mutex_t *m);
extern int mutex_lock(mutex_t *m);
extern int mutex_unlock(mutex_t *m);
extern int mutex_trylock(mutex_t *m);

extern int cond_init(cond_t *c);
extern int cond_destroy(cond_t *c);
extern int cond_wait(cond_t *c, mutex_t *m);
extern int cond_signal(cond_t *c);
extern int cond_broadcast(cond_t *c);

#endif
