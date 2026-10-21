/*
 * This file is part of OpenLI.
 *
 * OpenLI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * OpenLI is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for details.
 *
 * You should have received a copy of the GNU General Public License along
 * with OpenLI. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef OPENLI_CISCO_REASSEMBLY_H
#define OPENLI_CISCO_REASSEMBLY_H
#include <stdint.h>
#include <stddef.h>
#include <sys/time.h>

#define CISCO_REASS_SLOTS 4096
#define CISCO_REASS_ACTIVE 64
#define CISCO_REASS_FRAGMENTS 128
#define CISCO_REASS_SECONDS 30
#define CISCO_REASS_CONTEXT 20

typedef struct cisco_reassembly cisco_reassembly_t;
cisco_reassembly_t *cisco_reassembly_create(void);
void cisco_reassembly_destroy(cisco_reassembly_t *cache);
void cisco_reassembly_expire(cisco_reassembly_t *cache, uint64_t now);
/* Thread safe. Input is IPv4, including header. Context distinguishes VLANs
 * within one input. now is monotonic seconds, stamp is capture time.
 * Returns 1 and an owned UDP datagram on completion, otherwise 0.
 * Completed/rejected keys remain quarantined until their original deadline.
 * Caller frees *udp. No packet buffer is retained. */
int cisco_reassembly_feed(cisco_reassembly_t *cache, const uint8_t *ip,
        size_t captured, const uint8_t context[CISCO_REASS_CONTEXT],
        uint64_t now, struct timeval stamp, uint8_t **udp, size_t *length,
        struct timeval *first_stamp);
#endif
