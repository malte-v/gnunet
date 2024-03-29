/*
     This file is part of GNUnet.
     Copyright (C) 2009-2020 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file gns/gnunet-service-gns_resolver.h
 * @brief GNUnet GNS service
 * @author Martin Schanzenbach
 */
#ifndef GNS_RESOLVER_H
#define GNS_RESOLVER_H
#include "gns.h"
#include "gnunet_dht_service.h"
#include "gnunet_gns_service.h"
#include "gnunet_namecache_service.h"

/**
 * Initialize the resolver subsystem.
 * MUST be called before #GNS_resolver_lookup.
 *
 * @param nc the namecache handle
 * @param dht handle to the dht
 * @param c configuration handle
 * @param max_bg_queries maximum amount of background queries
 */
void
GNS_resolver_init (struct GNUNET_NAMECACHE_Handle *nc,
                   struct GNUNET_DHT_Handle *dht,
                   const struct GNUNET_CONFIGURATION_Handle *c,
                   unsigned long long max_bg_queries);


/**
 * Cleanup resolver: Terminate pending lookups
 */
void
GNS_resolver_done (void);


/**
 * Handle for an active request.
 */
struct GNS_ResolverHandle;


/**
 * Function called with results for a GNS resolution.
 *
 * @param cls closure
 * @param rd_count number of records in @a rd
 * @param rd records returned for the lookup
 */
typedef void
(*GNS_ResultProcessor)(void *cls,
                       uint32_t rd_count,
                       const struct GNUNET_GNSRECORD_Data *rd);


/**
 * Lookup of a record in a specific zone
 * calls RecordLookupProcessor on result or timeout
 *
 * @param zone the zone to perform the lookup in
 * @param record_type the record type to look up
 * @param name the name to look up
 * @param options options set to control local lookup
 * @param recursion_depth_limit how many zones to traverse
 *        at most
 * @param proc the processor to call
 * @param proc_cls the closure to pass to @a proc
 * @return handle to cancel operation
 */
struct GNS_ResolverHandle *
GNS_resolver_lookup (const struct GNUNET_IDENTITY_PublicKey *zone,
                     uint32_t record_type,
                     const char *name,
                     enum GNUNET_GNS_LocalOptions options,
                     uint16_t recursion_depth_limit,
                     GNS_ResultProcessor proc,
                     void *proc_cls);


/**
 * Cancel active resolution (i.e. client disconnected).
 *
 * @param rh resolution to abort
 */
void
GNS_resolver_lookup_cancel (struct GNS_ResolverHandle *rh);

#endif
