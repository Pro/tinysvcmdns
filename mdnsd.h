/*
 * tinysvcmdns - a tiny MDNS implementation for publishing services
 * Copyright (C) 2011 Darell Tan
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __MDNSD_H__
#define __MDNSD_H__

#include <stdint.h>

struct mdnsd;
struct mdns_service;

// starts a MDNS responder instance
// returns NULL if unsuccessful
struct mdnsd *mdnsd_start();

// stops the given MDNS responder instance
void mdnsd_stop(struct mdnsd *s);

// sets the hostname for the given MDNS responder instance
void mdnsd_set_hostname(struct mdnsd *svr, const char *hostname, uint32_t ip);

// registers a service with the MDNS responder instance
struct mdns_service *mdnsd_register_svc(struct mdnsd *svr, const char *instance_name, 
		const char *type, uint16_t port, const char *hostname, const char *txt[]);

// destroys the mdns_service struct returned by mdnsd_register_svc()
void mdns_service_destroy(struct mdns_service *srv);


#endif/*!__MDNSD_H__*/
