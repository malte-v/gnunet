# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  dht.conf

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = \
 libgnunetdht.la

libgnunetdht_la_SOURCES = \
  dht_api.c dht.h
libgnunetdht_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIB) \
  $(LTLIBINTL)
libgnunetdht_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 3:0:0


plugin_LTLIBRARIES = \
  libgnunet_plugin_block_dht.la

libgnunet_plugin_block_dht_la_SOURCES = \
  plugin_block_dht.c
libgnunet_plugin_block_dht_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/block/libgnunetblock.la \
  $(top_builddir)/src/block/libgnunetblockgroup.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_block_dht_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


libexec_PROGRAMS = \
 gnunet-service-dht

bin_PROGRAMS = \
 gnunet-dht-monitor \
 gnunet-dht-get \
 gnunet-dht-put

if HAVE_TESTING
noinst_PROGRAMS = \
 gnunet-dht-profiler
endif

gnunet_service_dht_SOURCES = \
 gnunet-service-dht.c gnunet-service-dht.h \
 gnunet-service-dht_datacache.c gnunet-service-dht_datacache.h \
 gnunet-service-dht_hello.c gnunet-service-dht_hello.h \
 gnunet-service-dht_nse.c gnunet-service-dht_nse.h \
 gnunet-service-dht_neighbours.c gnunet-service-dht_neighbours.h \
 gnunet-service-dht_routing.c gnunet-service-dht_routing.h
gnunet_service_dht_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/nse/libgnunetnse.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/block/libgnunetblock.la \
  $(top_builddir)/src/datacache/libgnunetdatacache.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lm
gnunet_service_dht_LDFLAGS = \
  $(GN_LIBINTL)

gnunet_dht_get_SOURCES = \
 gnunet-dht-get.c
gnunet_dht_get_LDADD = \
  libgnunetdht.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/util/libgnunetutil.la
gnunet_dht_get_LDFLAGS = \
  $(GN_LIBINTL)

gnunet_dht_put_SOURCES = \
 gnunet-dht-put.c
gnunet_dht_put_LDADD = \
  libgnunetdht.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/util/libgnunetutil.la
gnunet_dht_put_LDFLAGS = \
  $(GN_LIBINTL)

gnunet_dht_monitor_SOURCES = \
 gnunet-dht-monitor.c
gnunet_dht_monitor_LDADD = \
  libgnunetdht.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/util/libgnunetutil.la
gnunet_dht_monitor_LDFLAGS = \
  $(GN_LIBINTL)

gnunet_dht_profiler_SOURCES = \
  gnunet_dht_profiler.c
gnunet_dht_profiler_LDADD = \
  libgnunetdht.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la
gnunet_dht_profiler_LDFLAGS = \
  $(GN_LIBINTL)

if HAVE_TESTING
noinst_LIBRARIES = libgnunetdhttest.a
endif

libgnunetdhttest_a_SOURCES = \
  dht_test_lib.c dht_test_lib.h
libgnunetdhttest_a_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la \
 libgnunetdht.la

if HAVE_TESTING
check_PROGRAMS = \
 test_dht_api \
 test_dht_twopeer \
 test_dht_multipeer \
 test_dht_line \
 test_dht_2dtorus \
 test_dht_monitor
endif

if HAVE_EXPERIMENTAL
# These tests still do not work as testbed does
# not support the respective topology op
 NEW_TESTS = test_dht_2dtorus test_dht_multipeer
endif

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = test_dht_api $(check_SCRIPTS) \
 test_dht_twopeer \
 test_dht_line \
 test_dht_monitor \
 $(NEW_TESTS)
endif

test_dht_api_SOURCES = \
 test_dht_api.c
test_dht_api_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 libgnunetdht.la

test_dht_twopeer_SOURCES = \
 test_dht_topo.c
test_dht_twopeer_LDADD = \
 libgnunetdhttest.a \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunetdhttest.a \
 $(top_builddir)/src/testbed/libgnunettestbed.la \
 libgnunetdht.la

test_dht_2dtorus_SOURCES = \
 test_dht_topo.c
test_dht_2dtorus_LDADD = \
 libgnunetdhttest.a \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la \
 libgnunetdht.la

test_dht_line_SOURCES = \
 test_dht_topo.c
test_dht_line_LDADD = \
 libgnunetdhttest.a \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la \
 libgnunetdht.la

test_dht_multipeer_SOURCES = \
 test_dht_topo.c
test_dht_multipeer_LDADD = \
 libgnunetdhttest.a \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la \
 libgnunetdht.la

test_dht_monitor_SOURCES = \
  test_dht_monitor.c
test_dht_monitor_LDADD = \
 libgnunetdhttest.a \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la \
 libgnunetdht.la

EXTRA_DIST = \
  $(check_SCRIPTS) \
  gnunet-service-dht_clients.c \
  test_dht_api_data.conf \
  test_dht_api_peer1.conf \
  test_dht_monitor.conf \
  test_dht_multipeer.conf \
  test_dht_2dtorus.conf \
  test_dht_line.conf \
  test_dht_tools.conf \
  test_dht_tools.py.in \
  test_dht_multipeer_topology.dat

if HAVE_PYTHON
check_SCRIPTS = \
  test_dht_tools.py
endif

SUFFIXES = .py.in .py
.py.in.py:
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/$< > $@
	chmod +x $@
