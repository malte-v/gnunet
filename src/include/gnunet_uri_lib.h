/*
   This file is part of GNUnet
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
 * @file include/gnunet_uri_lib.h
 * @brief generic parser for URIs
 * @author Jonathan Buchanan
 */

#ifndef GNUNET_URI_LIB_H
#define GNUNET_URI_LIB_H

/**
 * A Universal Resource Identifier (URI).
 */
struct GNUNET_Uri
{
  /**
   * The scheme of the uri.
   */
  char *scheme;


  /**
   * The authority of the uri. If not present in the uri, NULL.
   */
  char *authority;


  /**
   * The list of path segments in the URI. Note that if the path ends with a
   * '/', then this array will end with an empty string to indicate the empty
   * segment following the '/'.
   */
  char **path_segments;


  /**
   * The length of @e path_segments.
   */
  unsigned int path_segments_count;


  /**
   * The query of the uri. If not present in the uri, NULL.
   */
  const char *query;


  /**
   * The fragment of the uri. If not present in the uri, NULL.
   */
  char *fragment;
};


/**
 * Parse a URI from a string into an internal representation.
 *
 * @param uri string to parse
 * @param emsg where to store the parser error message (if any)
 * @return handle to the internal representation of the URI, or NULL on error
 */
struct GNUNET_Uri *
GNUNET_uri_parse (const char *uri,
                  char **emsg);


/**
 * Free URI.
 *
 * @param uri uri to free
 */
void
GNUNET_uri_destroy (struct GNUNET_Uri *uri);


#endif /* GNUNET_URI_LIB_H */

/* end of include/gnunet_uri_lib.h */
