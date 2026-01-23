/*
 *
 * Copyright (c) 2024 SearchLight Ltd, New Zealand.
 * All rights reserved.
 *
 * This file is part of OpenLI.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * OpenLI is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * OpenLI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */

#ifndef OPENLI_UTIL_H_
#define OPENLI_UTIL_H_

#include <math.h>
#include <sys/epoll.h>
#include <libtrace.h>
#include <uthash.h>

#include "coreserver.h"

#define TIMESTAMP_TO_TV(tv, floatts) \
    tv->tv_sec = (uint32_t)(floatts); \
    tv->tv_usec = (uint32_t)(((floatts - tv->tv_sec) * 1000000));


typedef struct string_set {
    char *term;
    int termlen;

    UT_hash_handle hh;
} string_set_t;

/** Loads the contents of a file into a null-terminated string.
 *
 *  If limit is set to a value other than 0, then this method will
 *  fail if the file size is greater than that number of bytes.
 *
 *  The returned string has been allocated using malloc, and will need
 *  to be freed when the caller has no more need of it.
 *
 *  @param filename     The path to the file to be loaded into a string
 *  @param limit        The maximum file size to accept in bytes. Set to 0
 *                      to have no limit on file size.
 *
 *  @return a string containing the entire contents of the file, or NULL
 *          if an error occurs or the file size exceeds the specified limit.
 */
char *load_file_into_string(const char *filename, size_t limit);

int connect_socket(char *ipstr, char *portstr, uint8_t isretry,
        uint8_t setkeepalive);
int epoll_add_timer(int epoll_fd, uint32_t secs, void *ptr);
int epoll_add_ms_timer(int epoll_fd, uint32_t msecs, void *ptr);
int create_listener(char *addr, char *port, const char *name);
char *sockaddr_to_string(struct sockaddr *sa, char *str, int len);
uint8_t *sockaddr_to_key(struct sockaddr *sa, int *socklen);
void convert_ipstr_to_sockaddr(char *knownip, struct sockaddr_storage **saddr,
        int *family);
int sockaddr_match(int family, struct sockaddr *a, struct sockaddr *b);
int extract_ip_addresses(libtrace_packet_t *pkt, uint8_t *srcip,
        uint8_t *destip, int *ipfamily);
struct addrinfo *populate_addrinfo(char *ipstr, char *portstr,
        int socktype);
void *get_udp_payload(libtrace_packet_t *packet, uint32_t *rem,
        uint16_t *sourceport, uint16_t *destport);
char *parse_iprange_string(char *ipr_str);
void openli_copy_ipcontent(libtrace_packet_t *pkt, uint8_t **ipc,
        uint16_t *iplen);
char *extract_liid_from_exported_msg(uint8_t *etsimsg,
        uint64_t msglen, unsigned char *space, int maxspace,
        uint16_t *liidlen);
libtrace_packet_t *openli_copy_packet(libtrace_packet_t *pkt);
size_t openli_convert_hexstring_to_binary(const char *src, uint8_t *space,
        size_t maxspace);

char *ltrim(char *s);
char *rtrim(char *s);

/* string set methods */
int remove_from_string_set(string_set_t **set, char *term);
void purge_string_set(string_set_t **set);
int search_string_set(string_set_t *set, char *term);
int add_to_string_set(string_set_t **set, char *term);

int hash_packet_info_fivetuple(packet_info_t *pinfo, int modulo);
uint32_t hash_liid(char *liid);
uint32_t hashlittle( const void *key, size_t length, uint32_t initval);
#endif
// vim: set sw=4 tabstop=4 softtabstop=4 expandtab :

