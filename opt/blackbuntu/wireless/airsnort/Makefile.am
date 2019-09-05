## Process this file with automake to produce Makefile.in

SUBDIRS = src man

EXTRA_DIST = \
	airsnort.glade \
	airsnort.gladep \
	README.decrypt \
	README.win \
	bin/airsnort.exe \
	bin/airsnort.exe.asc \
	faq.txt \
	windows.mak \
	airsnort.dsw \
	airsnort.dsp

install-data-local:
	@$(NORMAL_INSTALL)
	if test -d $(srcdir)/pixmaps; then \
	  $(mkinstalldirs) $(DESTDIR)$(datadir)/pixmaps/$(PACKAGE); \
	  for pixmap in $(srcdir)/pixmaps/*; do \
	    if test -f $$pixmap; then \
	      $(INSTALL_DATA) $$pixmap $(DESTDIR)$(datadir)/pixmaps/$(PACKAGE); \
	    fi \
	  done \
	fi

dist-hook:
	if test -d pixmaps; then \
	  mkdir $(distdir)/pixmaps; \
	  for pixmap in pixmaps/*; do \
	    if test -f $$pixmap; then \
	      cp -p $$pixmap $(distdir)/pixmaps; \
	    fi \
	  done \
	fi

