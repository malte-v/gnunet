# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  revocation.conf

bin_PROGRAMS = \
 gnunet-revocation \
 gnunet-revocation-tvg


plugin_LTLIBRARIES = \
  libgnunet_plugin_block_revocation.la

libgnunet_plugin_block_revocation_la_SOURCES = \
  plugin_block_revocation.c
libgnunet_plugin_block_revocation_la_LIBADD = \
  libgnunetrevocation.la \
  $(top_builddir)/src/block/libgnunetblockgroup.la \
  $(top_builddir)/src/block/libgnunetblock.la \
  $(top_builddir)/src/util/libgnunetutil.la  \
  $(top_builddir)/src/identity/libgnunetidentity.la  \
  $(LTLIBINTL)
libgnunet_plugin_block_revocation_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


gnunet_revocation_SOURCES = \
 gnunet-revocation.c
gnunet_revocation_LDADD = \
  libgnunetrevocation.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_revocation_tvg_SOURCES = \
 gnunet-revocation-tvg.c
gnunet_revocation_tvg_LDADD = \
  libgnunetrevocation.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


lib_LTLIBRARIES = libgnunetrevocation.la

libgnunetrevocation_la_SOURCES = \
  revocation_api.c revocation.h
libgnunetrevocation_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(LIBGCRYPT_LIBS) \
  $(GN_LIBINTL) $(XLIB) -lgcrypt
libgnunetrevocation_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)   \
  -version-info 0:0:0

libexec_PROGRAMS = \
 gnunet-service-revocation


gnunet_service_revocation_SOURCES = \
 gnunet-service-revocation.c
gnunet_service_revocation_LDADD = \
  libgnunetrevocation.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/setu/libgnunetsetu.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/identity/libgnunetidentity.la  \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lm \
  $(GN_LIBINTL)

test_revocation_SOURCES = \
 test_revocation.c
test_revocation_LDADD = \
 $(top_builddir)/src/identity/libgnunetidentity.la \
 libgnunetrevocation.la \
 $(top_builddir)/src//core/libgnunetcore.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la

check_PROGRAMS = \
 test_revocation

check_SCRIPTS = \
  test_local_revocation.py

if ENABLE_TEST_RUN
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
 TESTS = \
 $(check_SCRIPTS) \
 $(check_PROGRAMS)
endif

test_local_revocation.py: test_local_revocation.py.in Makefile
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/test_local_revocation.py.in > test_local_revocation.py
	chmod +x test_local_revocation.py

EXTRA_DIST = test_revocation.conf \
	test_local_revocation.py.in
