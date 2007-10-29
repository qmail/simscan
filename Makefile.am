# $Id: Makefile.am,v 1.1 2007/10/29 16:59:34 xen0phage Exp $
@SET_MAKE@
SUBDIRS=cdb

CDB_LIBS=cdb/cdb.a cdb/buffer.a cdb/unix.a cdb/byte.a cdb/alloc.a

simscanbindir = @qmaildir@/bin
simscanbin_PROGRAMS = simscan simscanmk

simscan_SOURCES  = simscan.c 
simscan_LDADD  = $(CDB_LIBS) 

simscanmk_SOURCES = simscanmk.c 
simscanmk_LDADD =  $(CDB_LIBS)

install-simscanbinPROGRAMS:
	$(INSTALL) simscan @qmaildir@/bin/simscan
	$(INSTALL) simscanmk @qmaildir@/bin/simscanmk
	$(INSTALL) -m 750 -d @workdir@
	strip @qmaildir@/bin/simscan
	strip @qmaildir@/bin/simscanmk
	chown @ENABLE_USER@ @workdir@ @qmaildir@/bin/simscan
	chmod 4711 @qmaildir@/bin/simscan

AUTOMAKE_OPTIONS = foreign no-dependencies 

simscan.o: config.h
simscanmk.o: config.h
