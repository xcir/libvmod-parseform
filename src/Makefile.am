AM_CFLAGS = $(VARNISHAPI_CFLAGS) -Wall -Werror
AM_LDFLAGS = $(VARNISHAPI_LIBS) $(VMOD_LDFLAGS)

vmod_LTLIBRARIES = libvmod_parseform.la

libvmod_parseform_la_SOURCES = \
	vmod_parseform.c

nodist_libvmod_parseform_la_SOURCES = \
	vcc_parseform_if.c \
	vcc_parseform_if.h

dist_man_MANS = vmod_parseform.3

@BUILD_VMOD_PARSEFORM@

AM_TESTS_ENVIRONMENT = \
	PATH="$(VMOD_TEST_PATH)" \
	LD_LIBRARY_PATH="$(VARNISH_LIBRARY_PATH)"
TEST_EXTENSIONS = .vtc
VTC_LOG_COMPILER = varnishtest -v
AM_VTC_LOG_FLAGS = -Dvmod_parseform="$(VMOD_PARSEFORM)"

TESTS = @VMOD_TESTS@

EXTRA_DIST = \
	vmod_parseform.vcc \
	$(VMOD_TESTS)
