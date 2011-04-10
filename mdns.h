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

#ifndef __MDNS_H__
#define __MDNS_H__

#include <stdint.h>
#include <stdlib.h>

#define MALLOC_ZERO_STRUCT(x, type) \
	x = malloc(sizeof(struct type)); \
	memset(x, 0, sizeof(struct type));

#define DECL_MALLOC_ZERO_STRUCT(x, type) \
	struct type * MALLOC_ZERO_STRUCT(x, type)

#ifndef NDEBUG
  #define DEBUG_PRINTF(...) printf(__VA_ARGS__)
#else
  #define DEBUG_PRINTF(...) ((void) 0)
#endif


struct rr_data_srv {
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	uint8_t *target;	// host
};

struct rr_data_txt {
	struct rr_data_txt *next;
	uint8_t *txt;
};

struct rr_data_nsec {
	//uint8_t *name;	// same as record

	// NSEC occupies the 47th bit, 5 bytes
	//uint8_t bitmap_len;	// = 5
	uint8_t bitmap[5];	// network order: first byte contains LSB
};

struct rr_data_ptr {
	uint8_t *name;		// NULL if entry is to be used
	struct rr_entry *entry;
};

struct rr_data_a {
	uint32_t addr;
};

struct rr_entry {
	uint8_t *name;

	enum rr_type {
		RR_A		= 0x01,
		RR_PTR		= 0x0C,
		RR_TXT		= 0x10,
		RR_AAAA		= 0x1C,
		RR_SRV		= 0x21,
		RR_NSEC		= 0x2F,
		RR_ANY		= 0xFF,
	} type;

	uint32_t ttl;

	// for use in Questions only
	char unicast_query;

	// for use in Answers only
	char cache_flush;

	uint16_t rr_class;

	// RR data
	union {
		struct rr_data_nsec NSEC;
		struct rr_data_srv  SRV;
		struct rr_data_txt  TXT;
		struct rr_data_ptr  PTR;
		struct rr_data_a    A;
	} data;
};

struct rr_list {
	struct rr_entry *e;
	struct rr_list *next;
};

struct rr_group {
	uint8_t *name;

	struct rr_list *rr;

	struct rr_group *next;
};

#define MDNS_FLAG_RESP 	(1 << 15)	// Query=0 / Response=1
#define MDNS_FLAG_AA	(1 << 10)	// Authoritative
#define MDNS_FLAG_TC	(1 <<  9)	// TrunCation
#define MDNS_FLAG_RD	(1 <<  8)	// Recursion Desired
#define MDNS_FLAG_RA	(1 <<  7)	// Recursion Available
#define MDNS_FLAG_Z		(1 <<  6)	// Reserved (zero)

#define MDNS_FLAG_GET_RCODE(x)	(x & 0x0F)
#define MDNS_FLAG_GET_OPCODE(x)	((x >> 11) & 0x0F)

struct mdns_pkt {
	uint16_t id;	// transaction ID
	uint16_t flags;
	uint16_t num_qn;
	uint16_t num_ans_rr;
	uint16_t num_auth_rr;
	uint16_t num_add_rr;

	struct rr_list *rr_qn;		// questions
	struct rr_list *rr_ans;		// answer RRs
	struct rr_list *rr_auth;	// authority RRs
	struct rr_list *rr_add;		// additional RRs
};

struct mdns_pkt *mdns_parse_pkt(uint8_t *pkt_buf, size_t pkt_len);

void mdns_init_reply(struct mdns_pkt *pkt, uint16_t id);
size_t mdns_encode_pkt(struct mdns_pkt *answer, uint8_t *pkt_buf, size_t pkt_len);

void mdns_pkt_destroy(struct mdns_pkt *p);
void rr_group_destroy(struct rr_group *group);
struct rr_group *rr_group_find(struct rr_group *g, uint8_t *name);
struct rr_entry *rr_entry_find(struct rr_list *rr_list, uint8_t *name, uint16_t type);
void rr_group_add(struct rr_group **group, struct rr_entry *rr);

int rr_list_count(struct rr_list *rr);
int rr_list_append(struct rr_list **rr_head, struct rr_entry *rr);
struct rr_entry *rr_list_remove(struct rr_list **rr_head, struct rr_entry *rr);
void rr_list_destroy(struct rr_list *rr, char destroy_items);

struct rr_entry *rr_create_ptr(uint8_t *name, struct rr_entry *d_rr);
struct rr_entry *rr_create_srv(uint8_t *name, uint16_t port, uint8_t *target);
struct rr_entry *rr_create_a(uint8_t *name, uint32_t addr);
struct rr_entry *rr_create(uint8_t *name, enum rr_type type);
void rr_set_nsec(struct rr_entry *rr_nsec, enum rr_type type);
void rr_add_txt(struct rr_entry *rr_txt, const char *txt);

uint8_t *create_label(const char *txt);
uint8_t *create_nlabel(const char *name);
char *nlabel_to_str(const uint8_t *name);
uint8_t *dup_label(const uint8_t *label);
uint8_t *dup_nlabel(const uint8_t *n);
uint8_t *join_nlabel(const uint8_t *n1, const uint8_t *n2);

#endif /*!__MDNS_H__*/
