# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  secretsharing.conf

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif


libexec_PROGRAMS = \
 gnunet-service-secretsharing

lib_LTLIBRARIES = \
  libgnunetsecretsharing.la


gnunet_secretsharing_profiler_SOURCES = \
 gnunet-secretsharing-profiler.c
gnunet_secretsharing_profiler_LDADD = \
  libgnunetsecretsharing.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_service_secretsharing_SOURCES = \
 gnunet-service-secretsharing.c \
 secretsharing_common.c \
 secretsharing_protocol.h
gnunet_service_secretsharing_CFLAGS = $(AM_CFLAGS)
gnunet_service_secretsharing_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/consensus/libgnunetconsensus.la \
  $(LIBGCRYPT_LIBS) \
  $(GN_LIBINTL)

libgnunetsecretsharing_la_SOURCES = \
  secretsharing_api.c \
  secretsharing_common.c \
  secretsharing.h
libgnunetsecretsharing_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LIBGCRYPT_LIBS) \
  $(LTLIBINTL)
libgnunetsecretsharing_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

if HAVE_TESTING
bin_PROGRAMS = \
 gnunet-secretsharing-profiler

check_PROGRAMS = \
 test_secretsharing_api

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif
endif

test_secretsharing_api_SOURCES = \
 test_secretsharing_api.c
test_secretsharing_api_LDADD = \
  libgnunetsecretsharing.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la

EXTRA_DIST = \
  test_secretsharing.conf
