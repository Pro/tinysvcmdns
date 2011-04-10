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

#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "mdns.h"
#include "mdnsd.h"

int main(int argc, char *argv[]) {
	// create host entries
	char *hostname = "some-random-host.local";

	struct mdnsd *svr = mdnsd_start();
	if (svr == NULL) {
		printf("mdnsd_start() error\n");
		return 1;
	}

	printf("mdnsd_start OK. press ENTER to add hostname & service\n");
	getchar();

	mdnsd_set_hostname(svr, hostname, inet_addr("192.168.0.29"));

	const char *txt[] = {
		"path=/mywebsite", 
		NULL
	};
	struct mdns_service *svc = mdnsd_register_svc(svr, "My Website", 
									"_http._tcp.local", 8080, NULL, txt);
	mdns_service_destroy(svc);

	printf("added service and hostname. press ENTER to exit\n");
	getchar();

	mdnsd_stop(svr);

	return 0;
}

