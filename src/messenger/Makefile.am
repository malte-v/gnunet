# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  messenger.conf

plugindir = $(libdir)/gnunet

AM_CLFAGS = -g

libexec_PROGRAMS = \
 gnunet-service-messenger \
 $(EXP_LIBEXEC)

bin_PROGRAMS = \
 gnunet-messenger

lib_LTLIBRARIES = \
  libgnunetmessenger_common.la \
  libgnunetmessenger.la \
  $(EXP_LIB)

libgnunetmessenger_common_la_SOURCES = \
  messenger_api_ego.h \
  messenger_api_message.c messenger_api_message.h \
  messenger_api_list_tunnels.c messenger_api_list_tunnels.h
libgnunetmessenger_common_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(XLIB) \
  $(LTLIBINTL)
libgnunetmessenger_common_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:0:0

libgnunetmessenger_la_SOURCES = \
  messenger_api.c \
  messenger_api_contact.c messenger_api_contact.h \
  messenger_api_handle.c messenger_api_handle.h \
  messenger_api_room.c messenger_api_room.h
libgnunetmessenger_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  libgnunetmessenger_common.la \
  $(XLIB) \
  $(LTLIBINTL)
libgnunetmessenger_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:0:0

gnunet_messenger_SOURCES = \
 gnunet-messenger.c
gnunet_messenger_LDADD = \
 libgnunetmessenger_common.la \
 libgnunetmessenger.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/identity/libgnunetidentity.la
gnunet_messenger_LDFLAGS = \
  $(GN_LIBINTL)

gnunet_service_messenger_SOURCES = \
  gnunet-service-messenger.c gnunet-service-messenger.h \
  gnunet-service-messenger_service.c gnunet-service-messenger_service.h \
  gnunet-service-messenger_list_handles.c gnunet-service-messenger_list_handles.h \
  gnunet-service-messenger_list_messages.c gnunet-service-messenger_list_messages.h \
  gnunet-service-messenger_message_handle.c gnunet-service-messenger_message_handle.h \
  gnunet-service-messenger_message_kind.c gnunet-service-messenger_message_kind.h \
  gnunet-service-messenger_message_recv.c gnunet-service-messenger_message_recv.h \
  gnunet-service-messenger_message_send.c gnunet-service-messenger_message_send.h \
  gnunet-service-messenger_message_store.c gnunet-service-messenger_message_store.h \
  gnunet-service-messenger_basement.c gnunet-service-messenger_basement.h \
  gnunet-service-messenger_contact.c gnunet-service-messenger_contact.h \
  gnunet-service-messenger_handle.c gnunet-service-messenger_handle.h \
  gnunet-service-messenger_room.c gnunet-service-messenger_room.h \
  gnunet-service-messenger_tunnel.c gnunet-service-messenger_tunnel.h \
  gnunet-service-messenger_util.c gnunet-service-messenger_util.h
gnunet_service_messenger_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/cadet/libgnunetcadet.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  libgnunetmessenger_common.la \
  libgnunetmessenger.la \
  $(GN_LIBINTL)

check_PROGRAMS = \
  test_messenger_api \
  test_messenger_anonymous \
  test_messenger_comm0

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = \
 $(check_PROGRAMS)
endif

test_messenger_api_SOURCES = \
  test_messenger.c
test_messenger_api_LDADD = \
  libgnunetmessenger_common.la \
  libgnunetmessenger.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_messenger_anonymous_SOURCES = \
  test_messenger_anonymous.c
test_messenger_anonymous_LDADD = \
  libgnunetmessenger_common.la \
  libgnunetmessenger.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_messenger_comm0_SOURCES = \
  test_messenger_comm0.c
test_messenger_comm0_LDADD = \
  libgnunetmessenger_common.la \
  libgnunetmessenger.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/testbed-logger/libgnunettestbedlogger.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la

EXTRA_DIST = \
  test_messenger_api.conf
