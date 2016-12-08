/*
 * tinysvcmdns - a tiny MDNS implementation for publishing services
 * Copyright (C) 2011 Darell Tan
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "mdns_config.h"


#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <process.h>
#define LOG_ERR 3
#else
	#include <sys/select.h>
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <syslog.h>
	#include <pthread.h>
	#include <unistd.h>
#endif

#if !defined __APPLE__  && !defined _WIN32
// in strict ansi mode, the struct is not defined
struct ip_mreq_custom
{
	/* IP multicast address of group.  */
	struct in_addr imr_multiaddr;

	/* Local IP address of interface.  */
	struct in_addr imr_interface;
};
#else
#define ip_mreq_custom ip_mreq
#endif


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#ifndef _WIN32
#define os_mutex_init(lock) pthread_mutex_init(lock, NULL);
#define os_mutex_lock(lock) pthread_mutex_lock(lock)
#define os_mutex_unlock(lock) pthread_mutex_unlock(lock)
#define os_mutex_destroy(lock) pthread_mutex_destroy(lock)
#define os_mutex pthread_mutex_t
#define os_prepare_thread() \
		pthread_t tid; \
		pthread_attr_t attr; \
		pthread_attr_init(&attr); \
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
#define os_create_thread(fun, arg) pthread_create(&tid, &attr, (void *(*)(void *)) fun, (void *) arg)
#define os_create_thread_successful(fun, arg) (os_create_thread(fun, arg) == 0)
#define os_socket int
#define os_invalid_socket(sock) ((sock) < 0)
#define os_select(nfds, readfds, writefds, errorfds, timeout) select(nfds, readfds, writefds, errorfds, timeout)
#else
#define os_mutex_init(lock) InitializeCriticalSectionAndSpinCount(lock, 0x00000400)
#define os_mutex_lock(lock) EnterCriticalSection(lock)
#define os_mutex_unlock(lock) LeaveCriticalSection(lock)
#define os_mutex_destroy(lock) DeleteCriticalSection(lock)
#define os_mutex CRITICAL_SECTION
#define os_prepare_thread()
#define os_create_thread(fun, arg) _beginthread( (void (*)(void *)) fun, 0, arg )
#define os_create_thread_successful(fun, arg) (os_create_thread(fun, arg) != (uintptr_t)(-1))
#define os_socket SOCKET
#define os_invalid_socket(sock) ((sock) == INVALID_SOCKET)
#define os_select(nfds, readfds, writefds, errorfds, timeout) select(0, readfds, writefds, errorfds, timeout)
#endif


/*
 * Define a proper IP socket level if not already done.
 * Required to compile on OS X
 */
#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

#include "mdns.h"
#include "mdnsd.h"

#define MDNS_ADDR "224.0.0.251"
#define MDNS_PORT 5353

#define PACKET_SIZE 65536

#define SERVICES_DNS_SD_NLABEL \
		((uint8_t *) "\x09_services\x07_dns-sd\x04_udp\x05local")

struct mdnsd {
	os_mutex data_lock;
	os_socket sockfd;
	os_socket notify_pipe[2];
	int stop_flag;

	struct rr_group *group;
	struct rr_list *announce;
	struct rr_list *services;
	uint8_t *hostname;
};

struct mdns_service {
	struct rr_list *entries;
};

/////////////////////////////////


#define log_message(loglevel, format, ...) fprintf (stderr, format, ##__VA_ARGS__)

static os_socket create_recv_sock(void) {
	os_socket sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (os_invalid_socket(sd)) {
		log_message(LOG_ERR, "recv socket(): %s", strerror(errno));
		return sd;
	}

	int r = -1;

	int on = 1;
	if ((r = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on))) < 0) {
		log_message(LOG_ERR, "recv setsockopt(SO_REUSEADDR): %s", strerror(errno));
		return r;
	}

	/* bind to an address */
	struct sockaddr_in serveraddr;
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(MDNS_PORT);
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);	/* receive multicast */
	if ((r = bind(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr))) < 0) {
		log_message(LOG_ERR, "recv bind(): %s", strerror(errno));
	}

	// add membership to receiving socket
	struct ip_mreq_custom mreq;
	memset(&mreq, 0, sizeof(struct ip_mreq_custom));
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	mreq.imr_multiaddr.s_addr = inet_addr(MDNS_ADDR);
	if ((r = setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *) &mreq, sizeof(mreq))) < 0) {
		log_message(LOG_ERR, "recv setsockopt(IP_ADD_MEMBERSHIP): %s", strerror(errno));
		return r;
	}

	// enable loopback in case someone else needs the data
	if ((r = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, (char *) &on, sizeof(on))) < 0) {
		log_message(LOG_ERR, "recv setsockopt(IP_MULTICAST_LOOP): %s", strerror(errno));
		return r;
	}


#ifdef IP_PKTINFO
	if ((r = setsockopt(sd, SOL_IP, IP_PKTINFO, (char *) &on, sizeof(on))) < 0) {
		log_message(LOG_ERR, "recv setsockopt(IP_PKTINFO): %s", strerror(errno));
		return r;
	}
#endif

	return sd;
}

static long int send_packet(os_socket fd, const void *data, size_t len) {
	static struct sockaddr_in toaddr;
	if (toaddr.sin_family != AF_INET) {
		memset(&toaddr, 0, sizeof(struct sockaddr_in));
		toaddr.sin_family = AF_INET;
		toaddr.sin_port = htons(MDNS_PORT);
		toaddr.sin_addr.s_addr = inet_addr(MDNS_ADDR);
	}

	return sendto(fd, data, len, 0, (struct sockaddr *) &toaddr, sizeof(struct sockaddr_in));
}

// populate the specified list which matches the RR name and type
// type can be RR_ANY, which populates all entries EXCEPT RR_NSEC
static uint16_t populate_answers(struct mdnsd *svr, struct rr_list **rr_head, uint8_t *name, enum rr_type type) {
	uint16_t num_ans = 0;

	// check if we have the records
	os_mutex_lock(&svr->data_lock);
	struct rr_group *ans_grp = rr_group_find(svr->group, name);
	if (ans_grp == NULL) {
		os_mutex_unlock(&svr->data_lock);
		return num_ans;
	}

	// decide which records should go into answers
	struct rr_list *n = ans_grp->rr;
	for (; n; n = n->next) {
		// exclude NSEC for RR_ANY
		if (type == RR_ANY && n->e->type == RR_NSEC)
			continue;

		if ((type == n->e->type || type == RR_ANY) && cmp_nlabel(name, n->e->name) == 0) {
			num_ans = (uint16_t)(num_ans + rr_list_append(rr_head, n->e));
		}
	}

	os_mutex_unlock(&svr->data_lock);

	return num_ans;
}

// given a list of RRs, look up related records and add them
static void add_related_rr(struct mdnsd *svr, struct rr_list *list, struct mdns_pkt *reply) {
	for (; list; list = list->next) {
		struct rr_entry *ans = list->e;

		switch (ans->type) {
			case RR_PTR:
				// target host A, AAAA records
				reply->num_add_rr = (uint16_t)(reply->num_add_rr + populate_answers(svr, &reply->rr_add,
										MDNS_RR_GET_PTR_NAME(ans), RR_ANY));
				break;

			case RR_SRV:
				// target host A, AAAA records
				reply->num_add_rr = (uint16_t)(reply->num_add_rr + populate_answers(svr, &reply->rr_add,
										ans->data.SRV.target, RR_ANY));

				// perhaps TXT records of the same name?
				// if we use RR_ANY, we risk pulling in the same RR_SRV
				reply->num_add_rr = (uint16_t)(reply->num_add_rr + populate_answers(svr, &reply->rr_add,
										ans->name, RR_TXT));
				break;

			case RR_A:
			case RR_AAAA:
				reply->num_add_rr = (uint16_t)(reply->num_add_rr + populate_answers(svr, &reply->rr_add,
										ans->name, RR_NSEC));
				break;

			default:
				// nothing to add
				break;
		}
	}
}

// creates an announce packet given the type name PTR 
static void announce_srv(struct mdnsd *svr, struct mdns_pkt *reply, uint8_t *name) {
	mdns_init_reply(reply, 0);

	reply->num_ans_rr = (uint16_t)(reply->num_ans_rr + populate_answers(svr, &reply->rr_ans, name, RR_PTR));
	
	// remember to add the services dns-sd PTR too
	reply->num_ans_rr = (uint16_t)(reply->num_ans_rr + populate_answers(svr, &reply->rr_ans,
								SERVICES_DNS_SD_NLABEL, RR_PTR));

	// see if we can match additional records for answers
	add_related_rr(svr, reply->rr_ans, reply);

	// additional records for additional records
	add_related_rr(svr, reply->rr_add, reply);
}

// processes the incoming MDNS packet
// returns >0 if processed, 0 otherwise
static int process_mdns_pkt(struct mdnsd *svr, struct mdns_pkt *pkt, struct mdns_pkt *reply) {
	assert(pkt != NULL);

	// is it standard query?
	if ((pkt->flags & MDNS_FLAG_RESP) == 0 && 
			MDNS_FLAG_GET_OPCODE(pkt->flags) == 0) {
		mdns_init_reply(reply, pkt->id);

		DEBUG_PRINTF("flags = %04x, qn = %d, ans = %d, add = %d\n", 
						pkt->flags,
						pkt->num_qn,
						pkt->num_ans_rr,
						pkt->num_add_rr);

		// loop through questions
		struct rr_list *qnl = pkt->rr_qn;
		for (int i = 0; i < pkt->num_qn; i++, qnl = qnl->next) {
			struct rr_entry *qn = qnl->e;
			int num_ans_added = 0;

			char *namestr = nlabel_to_str(qn->name);
			DEBUG_PRINTF("qn #%d: type %s (%02x) %s - ", i, rr_get_type_name(qn->type), qn->type, namestr);
			free(namestr);

			// check if it's a unicast query - we ignore those
			if (qn->unicast_query) {
				DEBUG_PRINTF("skipping unicast query\n");
				continue;
			}

			num_ans_added = populate_answers(svr, &reply->rr_ans, qn->name, qn->type);
			reply->num_ans_rr = (uint16_t)(reply->num_ans_rr + num_ans_added);

			DEBUG_PRINTF("added %d answers\n", num_ans_added);
		}

		// remove our replies if they were already in their answers
		struct rr_list *ans = NULL, *prev_ans = NULL;
		for (ans = reply->rr_ans; ans; ) {
			struct rr_list *next_ans = ans->next;
			struct rr_entry *known_ans = rr_entry_match(pkt->rr_ans, ans->e);

			// discard answers that have at least half of the actual TTL
			if (known_ans != NULL && known_ans->ttl >= ans->e->ttl / 2) {
				char *namestr = nlabel_to_str(ans->e->name);
				DEBUG_PRINTF("removing answer for %s\n", namestr);
				free(namestr);

				// check if list item is head
				if (prev_ans == NULL)
					reply->rr_ans = ans->next;
				else
					prev_ans->next = ans->next;
				free(ans);

				ans = prev_ans;

				// adjust answer count
				reply->num_ans_rr--;
			}

			prev_ans = ans;
			ans = next_ans;
		}


		// see if we can match additional records for answers
		add_related_rr(svr, reply->rr_ans, reply);

		// additional records for additional records
		add_related_rr(svr, reply->rr_add, reply);

		DEBUG_PRINTF("\n");

		return reply->num_ans_rr;
	}

	return 0;
}

static int create_pipe(os_socket handles[2]) {
#ifdef _WIN32
	SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
	if (os_invalid_socket(sock)) {
		return -1;
	}
	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(0);
	serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR) {
		closesocket(sock);
		return -1;
	}
	if (listen(sock, 1) == SOCKET_ERROR) {
		closesocket(sock);
		return -1;
	}
	int len = sizeof(serv_addr);
	if (getsockname(sock, (SOCKADDR*)&serv_addr, &len) == SOCKET_ERROR) {
		closesocket(sock);
		return -1;
	}
	if (os_invalid_socket(handles[1] = socket(PF_INET, SOCK_STREAM, 0))) {
		closesocket(sock);
		return -1;
	}
	if (connect(handles[1], (struct sockaddr*)&serv_addr, len) == SOCKET_ERROR) {
		closesocket(sock);
		return -1;
	}
	if (os_invalid_socket(handles[0] = accept(sock, (struct sockaddr*)&serv_addr, &len))) {
		closesocket((SOCKET)handles[1]);
		handles[1] = (int)INVALID_SOCKET;
		closesocket(sock);
		return -1;
	}
	closesocket(sock);
	return 0;
#else
	return pipe(handles);
#endif
}

static long int read_pipe(os_socket s, char* buf, size_t len) {
#ifdef _WIN32
	int ret = recv(s, buf, (int) len, 0);
	if (ret < 0 && WSAGetLastError() == WSAECONNRESET) {
		ret = 0;
	}
	return ret;
#else
	return read(s, buf, len);
#endif
}

static long int write_pipe(os_socket s, char* buf, size_t len) {
#ifdef _WIN32
	return send(s, buf, (int) len, 0);
#else
	return write(s, buf, len);
#endif
}

static int close_pipe(os_socket s) {
#ifdef _WIN32
	return closesocket(s);
#else
	return close(s);
#endif
}

// main loop to receive, process and send out MDNS replies
// also handles MDNS service announces
static void main_loop(struct mdnsd *svr) {
	fd_set sockfd_set;
	os_socket max_fd = svr->sockfd;
	char notify_buf[2];	// buffer for reading of notify_pipe

	void *pkt_buffer = malloc(PACKET_SIZE);

	if (svr->notify_pipe[0] > max_fd)
		max_fd = svr->notify_pipe[0];
	(void)max_fd; // avoid 'unused value' warning under _WIN32

	struct mdns_pkt *mdns_reply = malloc(sizeof(struct mdns_pkt));
	memset(mdns_reply, 0, sizeof(struct mdns_pkt));

	while (! svr->stop_flag) {
		FD_ZERO(&sockfd_set);
		FD_SET((unsigned int) svr->sockfd, &sockfd_set);
		FD_SET((unsigned int) svr->notify_pipe[0], &sockfd_set);
		os_select(max_fd + 1, &sockfd_set, NULL, NULL, NULL);

		if (FD_ISSET((unsigned int) svr->notify_pipe[0], &sockfd_set)) {
			// flush the notify_pipe
			read_pipe(svr->notify_pipe[0], (char*)&notify_buf, 1);
		} else if (FD_ISSET((unsigned int) svr->sockfd, &sockfd_set)) {
			struct sockaddr_in fromaddr;
			socklen_t sockaddr_size = sizeof(struct sockaddr_in);

			long int recvsize = recvfrom(svr->sockfd, pkt_buffer, PACKET_SIZE, 0,
				(struct sockaddr *) &fromaddr, &sockaddr_size);
			if (recvsize < 0) {
				log_message(LOG_ERR, "recv(): %s", strerror(errno));
			}

			DEBUG_PRINTF("data from=%s size=%ld\n", inet_ntoa(fromaddr.sin_addr), recvsize);
			struct mdns_pkt *mdns = mdns_parse_pkt(pkt_buffer, (size_t)recvsize);
			if (mdns != NULL) {
				if (process_mdns_pkt(svr, mdns, mdns_reply)) {
					size_t replylen = mdns_encode_pkt(mdns_reply, pkt_buffer, PACKET_SIZE);
					if (replylen == 0)
						log_message(LOG_ERR, "mdns_encode_pkt: empty package");
					else
						send_packet(svr->sockfd, pkt_buffer, replylen);
				} else if (mdns->num_qn == 0) {
					DEBUG_PRINTF("(no questions in packet)\n\n");
				}

				mdns_pkt_destroy(mdns);
			}
		}

		// send out announces
		while (1) {
			struct rr_entry *ann_e = NULL;

			// extract from head of list
			os_mutex_lock(&svr->data_lock);
			if (svr->announce) 
				ann_e = rr_list_remove(&svr->announce, svr->announce->e);
			os_mutex_unlock(&svr->data_lock);

			if (! ann_e)
				break;

			char *namestr = nlabel_to_str(ann_e->name);
			DEBUG_PRINTF("sending announce for %s\n", namestr);
			free(namestr);

			announce_srv(svr, mdns_reply, ann_e->name);

			if (mdns_reply->num_ans_rr > 0) {
				size_t replylen = mdns_encode_pkt(mdns_reply, pkt_buffer, PACKET_SIZE);
				if (replylen == 0)
					log_message(LOG_ERR, "mdns_encode_pkt: empty package");
				else
					send_packet(svr->sockfd, pkt_buffer, replylen);
			}
		}
	}

	// main thread terminating. send out "goodbye packets" for services
	mdns_init_reply(mdns_reply, 0);

	os_mutex_lock(&svr->data_lock);
	struct rr_list *svc_le = svr->services;
	for (; svc_le; svc_le = svc_le->next) {
		// set TTL to zero
		svc_le->e->ttl = 0;
		mdns_reply->num_ans_rr = (uint16_t)(mdns_reply->num_ans_rr+rr_list_append(&mdns_reply->rr_ans, svc_le->e));
	}
	os_mutex_unlock(&svr->data_lock);

	// send out packet
	if (mdns_reply->num_ans_rr > 0) {
		size_t replylen = mdns_encode_pkt(mdns_reply, pkt_buffer, PACKET_SIZE);
		if (replylen == 0)
			log_message(LOG_ERR, "mdns_encode_pkt: empty package");
		else
			send_packet(svr->sockfd, pkt_buffer, replylen);
	}

	// destroy packet
	mdns_init_reply(mdns_reply, 0);
	free(mdns_reply);

	free(pkt_buffer);

	close_pipe(svr->sockfd);

	svr->stop_flag = 2;
}

/////////////////////////////////////////////////////


void mdnsd_set_hostname(struct mdnsd *svr, const char *hostname, uint32_t ip) {
	struct rr_entry *a_e = NULL,
					*nsec_e = NULL;

	// currently can't be called twice
	// dont ask me what happens if the IP changes
	assert(svr->hostname == NULL);

	a_e = rr_create_a(create_nlabel(hostname), ip);

	nsec_e = rr_create(create_nlabel(hostname), RR_NSEC);
	rr_set_nsec(nsec_e, RR_A);

	os_mutex_lock(&svr->data_lock);
	svr->hostname = create_nlabel(hostname);
	rr_group_add(&svr->group, a_e);
	rr_group_add(&svr->group, nsec_e);
	os_mutex_unlock(&svr->data_lock);
}

void mdnsd_add_rr(struct mdnsd *svr, struct rr_entry *rr) {
	os_mutex_lock(&svr->data_lock);
	rr_group_add(&svr->group, rr);
	os_mutex_unlock(&svr->data_lock);
}

struct mdns_service *mdnsd_register_svc(struct mdnsd *svr, const char *instance_name, 
		const char *type, uint16_t port, const char *hostname, const char *txt[]) {
	struct rr_entry *txt_e = NULL, 
					*srv_e = NULL, 
					*ptr_e = NULL,
					*bptr_e = NULL;
	uint8_t *target;
	uint8_t *inst_nlabel, *type_nlabel, *nlabel;
	struct mdns_service *service = malloc(sizeof(struct mdns_service));
	memset(service, 0, sizeof(struct mdns_service));

	// combine service name
	type_nlabel = create_nlabel(type);
	inst_nlabel = create_nlabel(instance_name);
	nlabel = join_nlabel(inst_nlabel, type_nlabel);

	// create TXT record
	if (txt && *txt) {
		txt_e = rr_create(dup_nlabel(nlabel), RR_TXT);
		rr_list_append(&service->entries, txt_e);

		// add TXTs
		for (; *txt; txt++) 
			rr_add_txt(txt_e, *txt);
	}

	// create SRV record
	assert(hostname || svr->hostname);	// either one as target
	target = hostname ? 
				create_nlabel(hostname) : 
				dup_nlabel(svr->hostname);

	srv_e = rr_create_srv(dup_nlabel(nlabel), port, target);
	rr_list_append(&service->entries, srv_e);

	// create PTR record for type
	ptr_e = rr_create_ptr(type_nlabel, srv_e);

	// create services PTR record for type
	// this enables the type to show up as a "service"
	bptr_e = rr_create_ptr(dup_nlabel(SERVICES_DNS_SD_NLABEL), ptr_e);

	// modify lists here
	os_mutex_lock(&svr->data_lock);

	if (txt_e)
		rr_group_add(&svr->group, txt_e);
	rr_group_add(&svr->group, srv_e);
	rr_group_add(&svr->group, ptr_e);
	rr_group_add(&svr->group, bptr_e);

	// append PTR entry to announce list
	rr_list_append(&svr->announce, ptr_e);
	rr_list_append(&svr->services, ptr_e);

	os_mutex_unlock(&svr->data_lock);

	// don't free type_nlabel - it's with the PTR record
	free(nlabel);
	free(inst_nlabel);

	// notify server
	write_pipe(svr->notify_pipe[1], ".", 1);

	return service;
}

void mdns_service_destroy(struct mdns_service *srv) {
	assert(srv != NULL);
	rr_list_destroy(srv->entries, 0);
	free(srv);
}

struct mdnsd *mdnsd_start(void) {
	struct mdnsd *server = malloc(sizeof(struct mdnsd));
	memset(server, 0, sizeof(struct mdnsd));

	if (create_pipe(server->notify_pipe) != 0) {
		log_message(LOG_ERR, "pipe(): %s\n", strerror(errno));
		free(server);
		return NULL;
	}

	server->sockfd = create_recv_sock();
	if (os_invalid_socket(server->sockfd)) {
		log_message(LOG_ERR, "unable to create recv socket");
		free(server);
		return NULL;
	}

	os_mutex_init(&server->data_lock);

	os_prepare_thread();
	if (!os_create_thread_successful(main_loop, server)) {
		os_mutex_destroy(&server->data_lock);
		free(server);
		return NULL;
	}

	return server;
}

void mdnsd_stop(struct mdnsd *s) {
	assert(s != NULL);

	struct timeval tv = {
		.tv_sec = 0,
		.tv_usec = 500 * 1000,
	};

	s->stop_flag = 1;
	write_pipe(s->notify_pipe[1], ".", 1);

	while (s->stop_flag != 2)
		select(0, NULL, NULL, NULL, &tv);

	close_pipe(s->notify_pipe[0]);
	close_pipe(s->notify_pipe[1]);

	os_mutex_destroy(&s->data_lock);
	rr_group_destroy(s->group);
	rr_list_destroy(s->announce, 0);
	rr_list_destroy(s->services, 0);

	if (s->hostname)
		free(s->hostname);

	free(s);
}

