// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 */

#include <teavpn2/helpers.h>

int close_fd(int *fd)
{
	int ret;

	ret = __sys_close(*fd);
	*fd = -1;
	return ret; 
}
