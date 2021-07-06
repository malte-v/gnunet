/*
     This file is part of GNUnet
     Copyright (C) 2021 GNUnet e.V.

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
 * @author Christian Grothoff
 *
 * @file plugin_dhtu_ip.c
 * @brief plain IP based DHT network underlay
 */
#include "platform.h"
#include "gnunet_dhtu_plugin.h"

#define SCAN_FREQ GNUNET_TIME_UNIT_MINUTES

/**
 * Opaque handle that the underlay offers for our address to be used when
 * sending messages to another peer.
 */
struct GNUNET_DHTU_Source
{

  /**
   * Kept in a DLL.
   */
  struct GNUNET_DHTU_Source *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_DHTU_Source *prev;

  /**
   * Application context for this source.
   */
  void *app_ctx;

  /**
   * Address in URL form ("ip+udp://$IP:$PORT")
   */
  char *address;
  
  /**
   * Hash of the IP address.
   */
  struct GNUNET_DHTU_Hash id;
  
  /**
   * My actual address.
   */
  struct sockaddr_storage addr;

  /**
   * Number of bytes in @a addr.
   */
  socklen_t addrlen;
  
  /**
   * Last generation this address was observed.
   */
  unsigned int scan_generation;
  
};


/**
 * Opaque handle that the underlay offers for the target peer when sending
 * messages to another peer.
 */
struct GNUNET_DHTU_Target
{
  
  /**
   * Application context for this target.
   */
  void *app_ctx;

  /**
   * Head of preferences expressed for this target.
   */
  struct GNUNET_DHTU_PreferenceHandle *ph_head;

  /**
   * Tail of preferences expressed for this target.
   */
  struct GNUNET_DHTU_PreferenceHandle *ph_tail;
  
  /**
   * Target IP address.
   */
  struct sockaddr_storage addr;

  /**
   * Number of bytes in @a addr.
   */
  socklen_t addrlen;
  
  /**
   * Preference counter, length of the @a ph_head DLL.
   */
  unsigned int ph_count;

};

/**
 * Opaque handle expressing a preference of the DHT to
 * keep a particular target connected.
 */
struct GNUNET_DHTU_PreferenceHandle
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_DHTU_PreferenceHandle *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_DHTU_PreferenceHandle *prev;

  /**
   * Target a preference was expressed for.
   */
  struct GNUNET_DHTU_Target *target;
};


/**
 * Closure for all plugin functions.
 */
struct Plugin
{
  /** 
   * Callbacks into the DHT.
   */
  struct GNUNET_DHTU_PluginEnvironment *env;

  /**
   * Head of sources where we receive traffic.
   */
  struct GNUNET_DHTU_Source *src_head;

  /**
   * Tail of sources where we receive traffic.
   */
  struct GNUNET_DHTU_Source *src_tail;

  /**
   * Task that scans for IP address changes.
   */
  struct GNUNET_SCHEDULER_Task *scan_task;

  /**
   * Port we bind to. FIXME: initialize...
   */
  char *my_port;

  /**
   * How often have we scanned for IPs?
   */
  unsigned int scan_generation;

  /**
   * My UDP socket.
   */
  int sock;
};


/**
 * Use our private key to sign a message.
 *
 * @param cls closure
 * @param pk our private key to sign with
 * @param purpose what to sign
 * @param[out] signature, allocated on heap and returned
 * @return -1 on error, otherwise number of bytes in @a sig
 */
static ssize_t
ip_sign (void *cls,
         const struct GNUNET_DHTU_PrivateKey *pk,
         const struct GNUNET_DHTU_SignaturePurpose *purpose,
         void **sig)
{
  return 0;
}


/**
 * Verify signature in @a sig over @a purpose.
 *
 * @param cls closure
 * @param pk public key to verify signature of
 * @param purpose what was being signed
 * @param sig signature data
 * @param sig_size number of bytes in @a sig
 * @return #GNUNET_OK if signature is valid
 *         #GNUNET_NO if signatures are not supported
 *         #GNUNET_SYSERR if signature is invalid
 */
static enum GNUNET_GenericReturnValue
ip_verify (void *cls,
           const struct GNUNET_DHTU_PublicKey *pk,
           const struct GNUNET_DHTU_SignaturePurpose *purpose,
           const void *sig,
           size_t sig_size)
{
  return GNUNET_NO;
}


/**
 * Request creation of a session with a peer at the given @a address.
 *
 * @param cls closure (internal context for the plugin)
 * @param address target address to connect to
 */
static void
ip_try_connect (void *cls,
                const char *address)
{
  struct Plugin *plugin = cls;
  char *colon;
  const char *port;
  char *addr;
  struct addrinfo hints = {
    .ai_flags = AI_NUMERICHOST | AI_NUMERICSERV
  };
  struct addrinfo *result = NULL;
  
  if (0 !=
      strncmp (address,
               "ip+",
               strlen ("ip+")))
  {
    GNUNET_break (0);
    return;
  }
  address += strlen ("ip+");
  if (0 !=
      strncmp (address,
               "udp://",
               strlen ("udp://")))
  {
    GNUNET_break (0);
    return;
  }
  address += strlen ("udp://");
  addr = GNUNET_strdup (address);
  colon = strchr (addr, ':');
  if (NULL == colon)
  {
    port = plugin->my_port;
  }
  else
  {
    *colon = '\0';
    port = colon + 1;
  }
  if (0 !=
      getaddrinfo (addr,
                   port,
                   &hints,
                   &result))
  {
    GNUNET_break (0);
    GNUNET_free (addr);
    return;
  }
  GNUNET_free (addr);
  (void) result->ai_addr; // FIXME: use!

  // FIXME: create target, etc.
  freeaddrinfo (result);
}


/**
 * Request underlay to keep the connection to @a target alive if possible.
 * Hold may be called multiple times to express a strong preference to
 * keep a connection, say because a @a target is in multiple tables.
 * 
 * @param cls closure
 * @param target connection to keep alive
 */
static struct GNUNET_DHTU_PreferenceHandle *
ip_hold (void *cls,
         struct GNUNET_DHTU_Target *target)
{
  struct GNUNET_DHTU_PreferenceHandle *ph;

  ph = GNUNET_new (struct GNUNET_DHTU_PreferenceHandle);
  ph->target = target;
  GNUNET_CONTAINER_DLL_insert (target->ph_head,
                               target->ph_tail,
                               ph);
  target->ph_count++;
  return ph;
}


/**
 * Do no long request underlay to keep the connection alive.
 * 
 * @param cls closure
 * @param target connection to keep alive
 */
static void
ip_drop (struct GNUNET_DHTU_PreferenceHandle *ph)
{
  struct GNUNET_DHTU_Target *target = ph->target;
  
  GNUNET_CONTAINER_DLL_remove (target->ph_head,
                               target->ph_tail,
                               ph);
  target->ph_count--;
  GNUNET_free (ph);
}


/**
 * Send message to some other participant over the network.  Note that
 * sending is not guaranteeing that the other peer actually received the
 * message.  For any given @a target, the DHT must wait for the @a
 * finished_cb to be called before calling send() again.
 *
 * @param cls closure (internal context for the plugin)
 * @param target receiver identification
 * @param msg message
 * @param msg_size number of bytes in @a msg
 * @param finished_cb function called once transmission is done
 *        (not called if @a target disconnects, then only the
 *         disconnect_cb is called). 
 * @param finished_cb_cls closure for @a finished_cb
 */
static void
ip_send (void *cls,
         struct GNUNET_DHTU_Target *target,
         const void *msg,
         size_t msg_size,
         GNUNET_SCHEDULER_TaskCallback finished_cb,
         void *finished_cb_cls)
{
  struct Plugin *plugin = cls;

  sendto (plugin->sock,
          msg,
          msg_size,
          0,
          (const struct sockaddr *) &target->addr,
          target->addrlen);
  finished_cb (finished_cb_cls);
}


/**
 * Callback function invoked for each interface found.
 *
 * @param cls closure
 * @param name name of the interface (can be NULL for unknown)
 * @param isDefault is this presumably the default interface
 * @param addr address of this interface (can be NULL for unknown or unassigned)
 * @param broadcast_addr the broadcast address (can be NULL for unknown or unassigned)
 * @param netmask the network mask (can be NULL for unknown or unassigned)
 * @param addrlen length of the address
 * @return #GNUNET_OK to continue iteration, #GNUNET_SYSERR to abort
 */
static int
process_ifcs (void *cls,
              const char *name,
              int isDefault,
              const struct sockaddr *addr,
              const struct sockaddr *broadcast_addr,
              const struct sockaddr *netmask,
              socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  struct GNUNET_DHTU_Source *src;

  for (src = plugin->src_head;
       NULL != src;
       src = src->next)
  {
    if ( (addrlen == src->addrlen) &&
         (0 == memcmp (addr,
                       &src->addr,
                       addrlen)) )
    {
      src->scan_generation = plugin->scan_generation;
      return GNUNET_OK;
    }
  }
  src = GNUNET_new (struct GNUNET_DHTU_Source);
  src->addrlen = addrlen;
  memcpy (&src->addr,
          addr,
          addrlen);
  src->scan_generation = plugin->scan_generation;
  switch (addr->sa_family)
  {
    case AF_INET:
      // hash v4 address
      // convert address to src->address
      break;
    case AF_INET6:
      // hash v6 address
      // convert address to src->address
      break;
    default:
      GNUNET_break (0);
      GNUNET_free (src);
      return GNUNET_OK;
  }
  GNUNET_CONTAINER_DLL_insert (plugin->src_head,
                               plugin->src_tail,
                               src);
  plugin->env->address_add_cb (plugin->env->cls,
                               &src->id,
                               NULL, /* no key */
                               src->address,
                               src,
                               &src->app_ctx);
  return GNUNET_OK;
}


/**
 * Scan network interfaces for IP address changes.
 *
 * @param cls a `struct Plugin`
 */
static void
scan (void *cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_DHTU_Source *next;

  plugin->scan_generation++;
  GNUNET_OS_network_interfaces_list (&process_ifcs,
                                     plugin);
  for (struct GNUNET_DHTU_Source *src = plugin->src_head;
       NULL != src;
       src = next)
  {
    next = src->next;
    if (src->scan_generation == plugin->scan_generation)
      continue;
    GNUNET_CONTAINER_DLL_remove (plugin->src_head,
                                 plugin->src_tail,
                                 src);
    plugin->env->address_del_cb (src->app_ctx);
    GNUNET_free (src->address);
    GNUNET_free (src);
  }
  plugin->scan_task = GNUNET_SCHEDULER_add_delayed (SCAN_FREQ,
                                                    &scan,
                                                    plugin);
}


/**
 * Entry point for the plugin.
 *
 * @param cls closure (the `struct GNUNET_DHTU_PluginEnvironment`)
 * @return the plugin's API
 */
void *
libgnunet_plugin_dhtu_ip_init (void *cls)
{
  struct GNUNET_DHTU_PluginEnvironment *env = cls;
  struct GNUNET_DHTU_PluginFunctions *api;
  struct Plugin *plugin;

  plugin = GNUNET_new (struct Plugin);
  plugin->env = env;
  // FIXME: get port configuration!
  plugin->scan_task = GNUNET_SCHEDULER_add_now (&scan,
                                                plugin);
  // FIXME: bind, start receive loop
  // FIXME: deal with NSE callback...
  api = GNUNET_new (struct GNUNET_DHTU_PluginFunctions);
  api->cls = plugin;
  api->sign = &ip_sign;
  api->verify = &ip_verify;
  api->try_connect = &ip_try_connect;
  api->hold = &ip_hold;
  api->drop = &ip_drop;
  api->send = &ip_send;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls closure (our `struct Plugin`)
 * @return NULL
 */
void *
libgnunet_plugin_dhtu_ip_done (void *cls)
{
  struct GNUNET_DHTU_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  GNUNET_SCHEDULER_cancel (plugin->scan_task);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}
