/*
   This file is part of GNUnet.
   Copyright (C) 2020 GNUnet e.V.

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
 * @author Tobias Frisch
 * @file src/messenger/gnunet-service-messenger_util.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_UTIL_H
#define GNUNET_SERVICE_MESSENGER_UTIL_H

#include "platform.h"
#include "gnunet_cadet_service.h"
#include "gnunet_container_lib.h"
#include "gnunet_crypto_lib.h"

/**
 * Starts an urgent task to close a CADET channel asynchronously.
 *
 * @param channel Channel
 */
void
delayed_disconnect_channel (struct GNUNET_CADET_Channel *channel);

/**
 * Tries to generate an unused member id and store it into the <i>id</i> parameter. A map containing all currently
 * used member ids is used to check against.
 *
 * @param[out] id New member id
 * @param members Map of member ids
 * @return GNUNET_YES on success, GNUNET_NO on failure
 */
int
generate_free_member_id (struct GNUNET_ShortHashCode *id, const struct GNUNET_CONTAINER_MultiShortmap *members);

#endif //GNUNET_SERVICE_MESSENGER_UTIL_H
