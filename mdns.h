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

#ifndef __MDNS_H__
#define __MDNS_H__

#include "mdns_config.h"

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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
	// cppcheck-suppress unusedStructMember
	uint16_t priority;
	// cppcheck-suppress unusedStructMember
	uint16_t weight;
	// cppcheck-suppress unusedStructMember
	uint16_t port;
	// cppcheck-suppress unusedStructMember
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
	// cppcheck-suppress unusedStructMember
	uint8_t bitmap[5];	// network order: first byte contains LSB
};

struct rr_data_ptr {
	// cppcheck-suppress unusedStructMember
	uint8_t *name;		// NULL if entry is to be used
	struct rr_entry *entry;
};

struct rr_data_a {
	// cppcheck-suppress unusedStructMember
	uint32_t addr;
};

struct rr_data_aaaa {
	struct in6_addr *addr;
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
		struct rr_data_aaaa AAAA;
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

// gets the PTR target name, either from "name" member or "entry" member
#define MDNS_RR_GET_PTR_NAME(rr)  (rr->data.PTR.name != NULL ? rr->data.PTR.name : rr->data.PTR.entry->name)

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

MDNS_EXPORT struct mdns_pkt *mdns_parse_pkt(uint8_t *pkt_buf, size_t pkt_len);

MDNS_EXPORT void mdns_init_reply(struct mdns_pkt *pkt, uint16_t id);
MDNS_EXPORT size_t mdns_encode_pkt(struct mdns_pkt *answer, uint8_t *pkt_buf, size_t pkt_len);

void MDNS_EXPORT mdns_pkt_destroy(struct mdns_pkt *p);
void MDNS_EXPORT rr_group_destroy(struct rr_group *group);
MDNS_EXPORT struct rr_group* rr_group_find(struct rr_group *g, uint8_t *name);
MDNS_EXPORT struct rr_entry* rr_entry_find(struct rr_list *rr_list, uint8_t *name, uint16_t type);
MDNS_EXPORT struct rr_entry* rr_entry_match(struct rr_list *rr_list, struct rr_entry *entry);
void MDNS_EXPORT rr_group_add(struct rr_group **group, struct rr_entry *rr);

size_t MDNS_EXPORT rr_list_count(struct rr_list *rr);
uint16_t MDNS_EXPORT rr_list_append(struct rr_list **rr_head, struct rr_entry *rr);
struct rr_entry* rr_list_remove(struct rr_list **rr_head, struct rr_entry *rr);
void MDNS_EXPORT rr_list_destroy(struct rr_list *rr, char destroy_items);

MDNS_EXPORT struct rr_entry* rr_create_ptr(uint8_t *name, struct rr_entry *d_rr);
MDNS_EXPORT struct rr_entry* rr_create_srv(uint8_t *name, uint16_t port, uint8_t *target);
MDNS_EXPORT struct rr_entry* rr_create_aaaa(uint8_t *name, struct in6_addr *addr);
MDNS_EXPORT struct rr_entry* rr_create_a(uint8_t *name, uint32_t addr);
MDNS_EXPORT struct rr_entry* rr_create(uint8_t *name, enum rr_type type);
void MDNS_EXPORT rr_set_nsec(struct rr_entry *rr_nsec, enum rr_type type);
void MDNS_EXPORT rr_add_txt(struct rr_entry *rr_txt, const char *txt);

MDNS_EXPORT const char* rr_get_type_name(enum rr_type type);

uint8_t MDNS_EXPORT *create_label(const char *txt);
uint8_t MDNS_EXPORT *create_nlabel(const char *name);
char MDNS_EXPORT *nlabel_to_str(const uint8_t *name);
uint8_t MDNS_EXPORT *dup_label(const uint8_t *label);
uint8_t MDNS_EXPORT *dup_nlabel(const uint8_t *n);
uint8_t MDNS_EXPORT *join_nlabel(const uint8_t *n1, const uint8_t *n2);

// compares 2 names
static MDNS_INLINE int cmp_nlabel(const uint8_t *L1, const uint8_t *L2) {
	return strcmp((const char *) L1, (const char *) L2);
}

#ifdef __cplusplus
}
#endif

#endif /*!__MDNS_H__*/
