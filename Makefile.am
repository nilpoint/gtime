bin_PROGRAMS = gtime-test
gtime_test_SOURCES = gtime-test.c gt_http.c gt_http.h gt_asn1.h gt_publicationsfile.h hashchain.h gt_internal.h
bin_SCRIPTS = gtime-sign gtime-verify
man_MANS = doc/gtime-test.1 doc/gtime.1
docdir = $(datadir)/doc/@PACKAGE@
doc_DATA = README doc/TestData.txt doc/TestData.txt.gtts doc/run-tests.sh doc/tap-functions doc/trust.pem
EXTRA_DIST = $(man_MANS) $(doc_DATA) $(bin_SCRIPTS)

install-exec-hook:
	cd $(DESTDIR)$(bindir) && \
		${LN_S} -f  gtime-test$(EXEEXT) gtime$(EXEEXT)

uninstall-hook:
	cd $(DESTDIR)$(bindir) && \
		rm -f  gtime$(EXEEXT)
