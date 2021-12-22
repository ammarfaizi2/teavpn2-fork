// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Alviro Iskandar Setiawan <alviro.iskandar@gmail.com>
 */

#include <stdio.h>
#include <teavpn2/common.h>
#include <teavpn2/gui/event_callback.h>

void *client_udata = NULL;
void (*client_on_connect)(void *udata) = NULL;
void (*client_on_disconnect)(void *udata) = NULL;
void (*client_on_error)(void *udata, int code) = NULL;

static void callback_client_on_connect(void *udata)
{
	pr_notice("callback_client_on_connect: Data = %s", (char *) udata);
	pr_notice("callback_client_on_connect: Connected!");
}

static void callback_client_on_disconnect(void *udata)
{
	pr_notice("callback_client_on_disconnect: Data = %s", (char *) udata);
	pr_notice("callback_client_on_disconnect: Disconnected!");
}

static void callback_client_on_error(void *udata, int code)
{
	pr_notice("callback_client_on_error: Data = %s", (char *) udata);
	pr_err("callback_client_on_error: Error occured: " PRERF, PREAR(code));
}

void register_client_callbacks(void *udata)
{
	client_udata = udata;
	client_on_connect = callback_client_on_connect;
	client_on_disconnect = callback_client_on_disconnect;
	client_on_error = callback_client_on_error;
}
