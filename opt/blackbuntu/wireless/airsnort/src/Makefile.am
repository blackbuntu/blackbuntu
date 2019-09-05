## Process this file with automake to produce Makefile.in

INCLUDES = \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" \
	-DPACKAGE_LOCALE_DIR=\""$(prefix)/$(DATADIRNAME)/locale"\" \
	@PACKAGE_CFLAGS@

PTHREAD_LIB = -lpthread

bin_PROGRAMS = airsnort gencases decrypt orinoco_hopper

airsnort_SOURCES = \
	main.c \
	support.c support.h \
	interface.c interface.h \
	callbacks.c callbacks.h \
	crack.c crack.h \
	RC4.c RC4.h crc-32.c crc-32.h \
	capture.c capture.h \
	Packet.c Packet.h \
	bssidlist.c bssidlist.h \
	display.c display.h \
	PacketSource.c PacketSource.h \
	utils.c utils.h \
	korek.c korek.h \
	unistd.h

airsnort_LDADD = $(PTHREAD_LIB) -lpcap @PACKAGE_LIBS@

decrypt_SOURCES = \
	decrypt.c \
	RC4.c RC4.h \
	crc-32.h crc-32.c

decrypt_LDADD = -lpcap

gencases_SOURCES = \
	gencases.c \
	RC4.c RC4.h \
	crc-32.c crc-32.h
        
gencases_LDADD = -lpcap

orinoco_hopper_SOURCES = \
	orinoco_hopper.c

EXTRA_DIST = \
	iphlp.h \
	peek.h \
	winmonitor.c

