# Makefile for dd_rescue
# (c) garloff@suse.de, 99/10/09, GNU GPL
# (c) kurt@garloff.de, 2010 -- 2015, GNU GPL v2 or v3

VERSION = 1.99.8

DESTDIR = 
SRCDIR = .

CC = gcc
RPM_OPT_FLAGS = -Os -Wall -g -D_FORTIFY_SOURCE=2
CFLAGS = $(RPM_OPT_FLAGS) $(EXTRA_CFLAGS) -DHAVE_CONFIG_H -I .
CFLAGS_OPT = $(CFLAGS) -O3
INSTALL = install
INSTALLFLAGS = -s
prefix = $(DESTDIR)/usr
INSTALLDIR = $(prefix)/bin
#INSTALLDIR = $(DESTDIR)/bin
INSTALLLIBDIR = $(prefix)/$(LIB)
#INSTALLLIBDIR = $(DESTDIR)/$(LIBDIR)
MANDIR = $(prefix)/share/man
#MYDIR = dd_rescue-$(VERSION)
MYDIR = dd_rescue
BINTARGETS = dd_rescue 
LIBTARGETS = libddr_hash.so libddr_MD5.so libddr_null.so libddr_crypt.so
#TARGETS = libfalloc-dl
OTHTARGETS = find_nonzero fiemap file_zblock fmt_no md5 sha256 sha512 sha224 sha384 sha1 test_aes
OBJECTS = random.o frandom.o fmt_no.o find_nonzero.o 
FNZ_HEADERS = $(SRCDIR)/find_nonzero.h $(SRCDIR)/archdep.h $(SRCDIR)/ffs.h
DDR_HEADERS = config.h $(SRCDIR)/random.h $(SRCDIR)/frandom.h $(SRCDIR)/list.h $(SRCDIR)/fmt_no.h $(SRCDIR)/find_nonzero.h $(SRCDIR)/archdep.h $(SRCDIR)/ffs.h $(SRCDIR)/fstrim.h $(SRCDIR)/ddr_plugin.h $(SRCDIR)/ddr_ctrl.h $(SRCDIR)/splice.h $(SRCDIR)/fallocate64.h $(SRCDIR)/pread64.h
DOCDIR = $(prefix)/share/doc/packages
INSTASROOT = -o root -g root
LIB = lib
LIBDIR = /usr/$(LIB)
COMPILER = $(shell $(CC) --version | head -n1)
ID = $(shell git describe --tags || cat REL-ID)
DEFINES = -DVERSION=\"$(VERSION)\"  -D__COMPILER__="\"$(COMPILER)\"" -DID=\"$(ID)\" # -DPLUGSEARCH="\"$(LIBDIR)\""
OUT = -o dd_rescue
PIC = -fPIC
PIE = -fPIE
LDPIE = -pie
RDYNAMIC = -rdynamic
MAKE := $(MAKE) -f $(SRCDIR)/Makefile

LZOP = $(shell type -p lzop || type -P true)
HAVE_SHA256SUM = $(shell type -p sha256sum >/dev/null && echo 1 || echo 0)

ifeq ($(shell grep 'HAVE_LZO_LZO1X_H 1' config.h >/dev/null 2>&1 && echo 1), 1)
  LIBTARGETS += libddr_lzo.so
  OTHTARGETS += fuzz_lzo
  HAVE_LZO=1
else
  HAVE_LZO=0
endif

ifeq ($(shell grep 'HAVE_LIBCRYPTO 1' config.h >/dev/null 2>&1 && echo 1), 1)
  OTHTARGETS += pbkdf2
  AES_OSSL_PO = aes_ossl.po
  AES_OSSL_O = aes_ossl.o
  CRYPTOLIB = -lcrypto
  HAVE_OPENSSL=1
else
  HAVE_OPENSSL=0
endif

ifeq ($(CC),wcl386)
  CFLAGS = "-ox -wx $(EXTRA_CFLAGS)"
  DEFINES = -dMISS_STRSIGNAL -dMISS_PREAD -dVERSION=\"$(VERSION)\" -d__COMPILER__="\"$(COMPILER)\""
  OUT = ""
endif

MACH := $(shell uname -m | tr A-Z a-z | sed 's/i[3456]86/i386/')

ISX86 := 0
ifeq ($(MACH),i386)
  ISX86 := 1
endif
ifeq ($(MACH),x86_64)
  ISX86 := 1
  LIB = lib64
endif

ifeq ($(ISX86), 1)
HAVE_SSE42 := $(shell echo "" | $(CC) -msse4.2 -xc - 2>&1 | grep unrecognized || echo 1)
HAVE_AES := $(shell echo "" | $(CC) -maes -xc - 2>&1 | grep unrecognized || echo 1)
HAVE_AVX2 := $(shell echo "" | $(CC) -mavx2 -xc - 2>&1 | grep unrecognized || echo 1)
HAVE_RDRND := $(shell echo "" | $(CC) -mrdrnd -xc - 2>&1 | grep unrecognized || echo 1)
endif

ifneq ($(HAVE_RDRND),1)
	HAVE_RDRND = 0
endif
ifneq ($(HAVE_AES),1)
	HAVE_AES = 0
endif


ifeq ($(MACH),i386)
	SSE = "-msse2"
	#SSE = "-msse2 -funroll-loops"
	#SSE = "-msse2 -funroll-loops -ftree-vectorize"
	ARCHFLAGS +=  -msse2
endif

ifeq ($(ISX86),1)
	OBJECTS2 = find_nonzero_sse2.o

ifeq ($(HAVE_SSE42),1)
	OBJECTS2 += ffs_sse42.o
	#POBJECTS2 += ffs_sse42.po
	ARCHFLAGS +=  -msse4.2
else
	CFLAGS += -DNO_SSE42
endif
ifeq ($(HAVE_AES),1)
	AESNI_O = aesni.o
        AESNI_PO = aesni.po
	OBJECTS2 += rdrand.o
	#POBJECTS2 += rdrand.po find_nonzero.po ffs_sse42.po
        CFLAGS += -DHAVE_AESNI
	ARCHFLAGS += -maes
else
	CFLAGS += -DNO_AES
endif
ifeq ($(HAVE_AVX2),1)
	OBJECTS2 += find_nonzero_avx.o
	ARCHFLAGS +=  -mavx2
else
	CFLAGS += -DNO_AVX2
endif
ifeq ($(HAVE_RDRND),1)
	#OBJECTS2 += rdrand.o
	#POBJECTS2 += rdrand.po
	ARCHFLAGS +=  -mrdrnd
else
	CFLAGS += -DNO_RDRND 
endif
endif

MACH := $(shell uname -m |sed 's/armv[0-9a-z]*/arm/')
ifeq ($(MACH),arm)
	OBJECTS2 = find_nonzero_arm.o
	#POBJECTS2 = find_nonzero.po find_nonzero_arm.po
	AES_ARM64_O = aes_arm32.o
	AES_ARM64_PO = aes_arm32.po
	CFLAGS += -DHAVE_AES_ARM64
	ARCHFLAGS += -mfpu=crypto-neon-fp-armv8
endif
ifeq ($(MACH),aarch64)
	LIB = lib64
	OBJECTS2 = find_nonzero_arm64.o
	#POBJECTS2 = find_nonzero.po find_nonzero_arm64.po
	AES_ARM64_O = aes_arm64.o
	AES_ARM64_PO = aes_arm64.po
	CFLAGS += -DHAVE_AES_ARM64
	ARCHFLAGS += -march=armv8-a+crypto
endif

OS = $(shell uname)
ifeq ($(OS), Linux)
	OBJECTS += fstrim.o
endif

TARGETS = $(BINTARGETS) $(LIBTARGETS)

.PHONY: default all libfalloc libfalloc-static libfalloc-dl nolib nocolor static strip dep

default: $(TARGETS)

all: $(TARGETS) $(OTHTARGETS)

#Makefile:
#	test -e Makefile || ln -s $(SRCDIR)/Makefile .

config.h: $(SRCDIR)/configure $(SRCDIR)/config.h.in
	$(SRCDIR)/configure
	test -e test_crypt.sh || ln -s $(SRCDIR)/test_crypt.sh .
	test -e test_lzo_fuzz.sh || ln -s $(SRCDIR)/test_lzo_fuzz.sh .
	test -e calchmac.py || ln -s $(SRCDIR)/calchmac.py .

$(SRCDIR)/configure: $(SRCDIR)/configure.in
	cd $(SRCDIR) && autoconf

$(SRCDIR)/config.h.in: $(SRCDIR)/configure.in
	cd $(SRCDIR) && autoheader

# The headers for x86 intrinsics cause breakage while preprocessing 
# for dependency generation :-( Workaround ...
DEP_SSE = -D__AES__ -D__SSE4_1__ -D__SSSE3__ -D__SSE3__ -D__SSE2__ -D__SSE__ -D__MMX__

# Automated dependency generation
.dep: $(SRCDIR)/Makefile config.h $(SRCDIR)/*.h $(SRCDIR)/*.c
	#$(CC) $(CFLAGS) -DGEN_DEP $(ARCHFLAGS) -MM $(SRCDIR)/*.c >.dep
	$(CC) $(CFLAGS) -DGEN_DEP $(DEP_SSE) -I . -MM $(SRCDIR)/*.c >.dep
	sed 's/\.o:/\.po:/' <.dep >.dep2
	cat .dep2 >> .dep
	rm .dep2

include .dep

dep:
	rm -f .dep
	make .dep

# These need optimization
frandom.o: $(SRCDIR)/frandom.c config.h
	$(CC) $(CFLAGS_OPT) $(PIE) -c $<

fmt_no.o: $(SRCDIR)/fmt_no.c
	$(CC) $(CFLAGS_OPT) $(PIE) -c $<

md5.po: $(SRCDIR)/md5.c
	$(CC) $(CFLAGS_OPT) $(PIC) -o $@ -c $<

sha256.po: $(SRCDIR)/sha256.c
	$(CC) $(CFLAGS_OPT) $(PIC) -o $@ -c $<

sha512.po: $(SRCDIR)/sha512.c
	$(CC) $(CFLAGS_OPT) $(PIC) -o $@ -c $<

sha1.po: $(SRCDIR)/sha1.c
	$(CC) $(CFLAGS_OPT) $(PIC) -o $@ -c $<

# Default rules
%.o: $(SRCDIR)/%.c config.h
	$(CC) $(CFLAGS) $(DEFINES) $(PIE) -c $<

%.po: $(SRCDIR)/%.c config.h
	$(CC) $(CFLAGS) $(DEFINES) $(PIC) -o $@ -c $<

%.s: $(SRCDIR)/%.c config.h
	$(CC) $(CFLAGS) $(DEFINES) $(PIE) -S $<

# Use stack protector for libddr_lzo ...
libddr_lzo.po: $(SRCDIR)/libddr_lzo.c config.h
	$(CC) $(CFLAGS) $(PIC) -fstack-protector -o $@ -c $<

# The plugins
libddr_hash.so: libddr_hash.po md5.po sha256.po sha512.po sha1.po pbkdf2.po checksum_file.po
	$(CC) -shared -o $@ $^ $(EXTRA_LDFLAGS)

libddr_MD5.so: libddr_hash.so
	ln -sf $< $@

libddr_lzo.so: libddr_lzo.po
	$(CC) -shared -o $@ $^ -llzo2

libddr_null.so: libddr_null.po
	$(CC) -shared -o $@ $^

libddr_crypt.so: libddr_crypt.po aes.po aes_c.po $(AESNI_PO) $(AES_ARM64_PO) $(AES_OSSL_PO) pbkdf2.po sha256.po pbkdf_ossl.po md5.po checksum_file.po secmem.po random.po $(POBJECTS2)
	$(CC) -shared -o $@ $^ $(CRYPTOLIB) $(EXTRA_LDFLAGS)

# More special compiler flags
find_nonzero.o: $(SRCDIR)/find_nonzero.c
	$(CC) $(CFLAGS_OPT) $(PIE) -c $< $(SSE)

find_nonzero_avx.o: $(SRCDIR)/find_nonzero_avx.c
	$(CC) $(CFLAGS_OPT) $(PIE) -mavx2 -c $<

find_nonzero_sse2.o: $(SRCDIR)/find_nonzero_sse2.c
	$(CC) $(CFLAGS_OPT) $(PIE) -msse2 -c $<

find_nonzero_arm.o: $(SRCDIR)/find_nonzero_arm.c
	$(CC) $(CFLAGS_OPT) $(PIE) -c $<

find_nonzero_arm.po: $(SRCDIR)/find_nonzero_arm.c
	$(CC) $(CFLAGS_OPT) $(PIC) -o $@ -c $<

find_nonzero_arm64.o: $(SRCDIR)/find_nonzero_arm64.c
	$(CC) $(CFLAGS_OPT) -march=armv8-a+crypto $(PIE) -c $< 

find_nonzero_arm64.po: $(SRCDIR)/find_nonzero_arm64.c
	$(CC) $(CFLAGS_OPT) -march=armv8-a+crypto $(PIC) -o $@ -c $< 

find_nonzero_main.o: $(SRCDIR)/find_nonzero.c config.h $(FNZ_HEADERS)
	$(CC) $(CFLAGS_OPT) $(PIE) -o $@ -c $< -DTEST 

ffs_sse42.o: $(SRCDIR)/ffs_sse42.c
	$(CC) $(CFLAGS_OPT) $(PIE) -msse4.2 -c $<

ffs_sse42.po: $(SRCDIR)/ffs_sse42.c
	$(CC) $(CFLAGS_OPT) $(PIC) -msse4.2 -o $@ -c $<

ifeq ($(HAVE_RDRND),1)
rdrand.o: $(SRCDIR)/rdrand.c
	$(CC) $(CFLAGS) $(PIE) -mrdrnd -maes -c $<

rdrand.po: $(SRCDIR)/rdrand.c
	$(CC) $(CFLAGS) $(PIC) -mrdrnd -maes -o $@ -c $<
else
rdrand.o: $(SRCDIR)/rdrand.c
	$(CC) $(CFLAGS) $(PIE) -maes -c $<

rdrand.po: $(SRCDIR)/rdrand.c
	$(CC) $(CFLAGS) $(PIC) -maes -o $@ -c $<
endif

# TODO: Build binaries from .o file, so we can save some special rules ...
# Special dd_rescue variants
libfalloc: $(SRCDIR)/dd_rescue.c $(DDR_HEADERS) $(OBJECTS) $(OBJECTS2)
	$(CC) $(CFLAGS) $(PIE) $(LDPIE) -DNO_LIBDL $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2) -lfallocate $(EXTRA_LDFLAGS) $(RDYNAMIC)

libfalloc-static: $(SRCDIR)/dd_rescue.c $(DDR_HEADERS) $(OBJECTS) $(OBJECTS2)
	$(CC) $(CFLAGS) $(PIE) $(LDPIE) -DNO_LIBDL $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2) $(LIBDIR)/libfallocate.a $(EXTRA_LDFLAGS) $(RDYNAMIC)

# This is the default built
dd_rescue: $(SRCDIR)/dd_rescue.c $(DDR_HEADERS) $(OBJECTS) $(OBJECTS2)
	$(CC) $(CFLAGS) $(PIE) $(LDPIE) $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2) -ldl $(EXTRA_LDFLAGS) $(RDYNAMIC)

# Test programs 
md5: $(SRCDIR)/md5.c $(SRCDIR)/md5.h $(SRCDIR)/hash.h config.h
	$(CC) $(CFLAGS_OPT) $(PIE) $(LDPIE) -DMD5_MAIN -o $@ $<

sha256: $(SRCDIR)/sha256.c $(SRCDIR)/sha256.h $(SRCDIR)/hash.h config.h
	$(CC) $(CFLAGS_OPT) $(PIE) $(LDPIE) -DSHA256_MAIN -o $@ $<

sha224: sha256
	ln -sf sha256 sha224

sha512: $(SRCDIR)/sha512.c $(SRCDIR)/sha512.h $(SRCDIR)/hash.h config.h
	$(CC) $(CFLAGS_OPT) $(PIE) $(LDPIE) -DSHA512_MAIN -o $@ $<
	
sha384: sha512
	ln -sf sha512 sha384

sha1: $(SRCDIR)/sha1.c $(SRCDIR)/sha1.h $(SRCDIR)/hash.h config.h
	$(CC) $(CFLAGS_OPT) $(PIE) $(LDPIE) -DSHA1_MAIN -o $@ $<

fuzz_lzo: fuzz_lzo.o
	$(CC) -o $@ $(LDPIE) $^ -llzo2

# More dd_rescue variants
libfalloc-dl: dd_rescue

nolib: $(SRCDIR)/dd_rescue.c $(DDR_HEADERS) $(OBJECTS) $(OBJECTS2)
	$(CC) $(CFLAGS) -DNO_LIBDL -DNO_LIBFALLOCATE $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2)

nocolor: $(SRCDIR)/dd_rescue.c $(DDR_HEADERS) $(OBJECTS) $(OBJECTS2)
	$(CC) $(CFLAGS) -DNO_COLORS=1 $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2) $(EXTRA_LDFLAGS) $(RDYNAMIC)

static: $(SRCDIR)/dd_rescue.c $(DDR_HEADERS) $(OBJECTS)
	$(CC) $(CFLAGS) -DNO_LIBDL -DNO_LIBFALLOCATE -static $(DEFINES) $< $(OUT) $(OBJECTS) $(OBJECTS2) $(EXTRA_LDFLAGS)

# Special pseudo targets
strip: $(TARGETS) $(LIBTARGETS)
	strip -S $^

strip-all: $(OTHTARGETS)
	strip -S $^

clean:
	rm -f $(TARGETS) $(OTHTARGETS) $(OBJECTS) $(OBJECTS2) core test log *.o *.po *.cmp *.enc *.enc.old CHECKSUMS.* SALTS.* KEYS.* IVS.* .dep

# More test programs
find_nonzero: find_nonzero_main.o $(OBJECTS2)
	$(CC) $(CFLAGS_OPT) $(PIE) $(LDPIE) -o $@ $^ 

fmt_no: $(SRCDIR)/fmt_no.c $(SRCDIR)/fmt_no.h
	$(CC) $(CFLAGS) $(PIE) $(LDPIE) -o $@ $< -DTEST

file_zblock: $(SRCDIR)/file_zblock.c $(FNZ_HEADERS) config.h find_nonzero.o $(OBJECTS2)
	$(CC) $(CFLAGS) $(PIE) $(LDPIE) -o $@ $< find_nonzero.o $(OBJECTS2)

fiemap: $(SRCDIR)/fiemap.c $(SRCDIR)/fiemap.h $(SRCDIR)/fstrim.h config.h fstrim.o
	$(CC) $(CFLAGS) $(PIE) $(LDPIE) -DTEST_FIEMAP -o $@ $< fstrim.o

pbkdf2: $(SRCDIR)/ossl_pbkdf2.c
	$(CC) $(CFLAGS) $(PIE) $(LDPIE) -o $@ $< $(CRYPTOLIB)

test_aes: $(SRCDIR)/test_aes.c $(AESNI_O) $(AES_ARM64_O) aes_c.o secmem.o sha256.o find_nonzero.o $(AES_OSSL_O) aes.o $(SRCDIR)/aesni.h $(SRCDIR)/aes_arm64.h config.h
	$(CC) $(CFLAGS) $(PIE) $(LDPIE) $(DEF) -o $@ $< $(AESNI_O) $(AES_ARM64_O) aes_c.o secmem.o sha256.o $(AES_OSSL_O) aes.o find_nonzero.o $(OBJECTS2) $(CRYPTOLIB)

# Special optimized versions
aesni.o: $(SRCDIR)/aesni.c
	$(CC) $(CFLAGS) $(PIE) -O3 -maes -msse4.1 -c $<

aesni.po: $(SRCDIR)/aesni.c
	$(CC) $(CFLAGS) $(PIC) -O3 -maes -msse4.1 -c $< -o $@

aes_arm64.o: $(SRCDIR)/aes_arm64.c
	$(CC) $(CFLAGS) $(PIE) -O3 -march=armv8-a+crypto -c $<

aes_arm64.po: $(SRCDIR)/aes_arm64.c
	$(CC) $(CFLAGS) $(PIC) -O3 -march=armv8-a+crypto -c $< -o $@

aes_arm32.o: $(SRCDIR)/aes_arm32.c
	$(CC) $(CFLAGS) $(PIE) -O3 -march=armv7-a -mfpu=crypto-neon-fp-armv8 -c $<

aes_arm32.po: $(SRCDIR)/aes_arm32.c
	$(CC) $(CFLAGS) $(PIC) -O3 -march=armv7-a -mfpu=crypto-neon-fp-armv8 -c $< -o $@

aes_c.o: $(SRCDIR)/aes_c.c
	$(CC) $(CFLAGS) $(PIE) $(FULL_UNROLL) -O3 -c $<

aes_ossl.o: $(SRCDIR)/aes_ossl.c $(SRCDIR)/aes_ossl10.c $(SRCDIR)/aes_ossl11.c
	$(CC) $(CFLAGS) $(PIE) -O3 -c $<

distclean: clean
	rm -f *~ config.h $(SRCDIR)/config.h.in config.status config.log $(SRCDIR)/configure REL-ID
	rm -rf autom4te.cache
	rm -f *.cmp *.lzo test
	rm -f dd_rescue-?.??.tar.bz2

dist: distclean
	#tar cvzf ../dd_rescue-$(VERSION).tar.gz -C.. --exclude=$(MYDIR)/CV* --exclude $(MYDIR)/dd_rescue2* --exclude $(MYDIR)/.* --exclude $(MYDIR)/*.i --exclude $(MYDIR)/*~ --exclude $(MYDIR)*.S --exclude $(MYDIR)/*_32 --exclude $(MYDIR)/*_64 --exclude $(MYDIR)/*_android --exclude $(MYDIR)/*.o --exclude $(MYDIR)/*.po --exclude $(MYDaIR)/*.so $(MYDIR) 
	#cd .. && tar cvzf dd_rescue-$(VERSION).tar.gz $(MYDIR)/*.c $(MYDIR)/*.h $(MYDIR)/*.in $(MYDIR)/Makefile* $(MYDIR)/*.sh $(MYDIR)/*.1 $(MYDIR)/COPYING $(MYDIR)/README*
	mkdir dd_rescue-$(VERSION)
	git describe --tags > dd_rescue-$(VERSION)/REL-ID
	for name in `git ls-files`; do cp -p $$name dd_rescue-$(VERSION); done
	tar cvjf dd_rescue-$(VERSION).tar.bz2 dd_rescue-$(VERSION)
	rm -rf dd_rescue-$(VERSION)

install: $(TARGETS)
	mkdir -p $(INSTALLDIR)
	$(INSTALL) $(INSTALLFLAGS) $(INSTASROOT) -m 755 $(BINTARGETS) $(INSTALLDIR)
	#$(INSTALL) $(INSTASROOT) -m 755 -d $(DOCDIR)/dd_rescue
	#$(INSTALL) $(INSTASROOT) -g root -m 644 README.dd_rescue $(DOCDIR)/dd_rescue/
	mkdir -p $(INSTALLLIBDIR)
	$(INSTALL) $(INSTALLFLAGS) $(INSTASROOT) -m 755 $(LIBTARGETS) $(INSTALLLIBDIR)
	ln -sf libddr_hash.so $(INSTALLLIBDIR)/libddr_MD5.so
	mkdir -p $(MANDIR)/man1
	$(INSTALL) $(INSTASROOT) -m 644 dd_rescue.1 ddr_lzo.1 ddr_crypt.1 $(MANDIR)/man1/
	gzip -9f $(MANDIR)/man1/dd_rescue.1 $(MANDIR)/man1/ddr_lzo.1 $(MANDIR)/man1/ddr_crypt.1

check: $(TARGETS) find_nonzero md5 sha1 sha256 sha512 fmt_no
	@echo "make check ... Pass VG=\"valgrind --options\" to use with valgrind"
	$(VG) ./dd_rescue --version
	@echo "***** find_nonzero tests *****"
	$(VG) ./find_nonzero 2
	@echo "***** fmt_no tests *****"
	$(VG) ./fmt_no 1024200
	@echo "***** dd_rescue tests *****"
	@rm -f dd_rescue.copy dd_rescue.copy2
	$(VG) ./dd_rescue -apP dd_rescue dd_rescue.copy
	cmp dd_rescue dd_rescue.copy 
	@rm dd_rescue.copy
	$(VG) ./dd_rescue -b16k -B16k -a dd_rescue dd_rescue.copy
	cmp dd_rescue dd_rescue.copy
	@rm dd_rescue.copy
	$(VG) ./dd_rescue -r dd_rescue dd_rescue.copy
	cmp dd_rescue dd_rescue.copy
	$(VG) ./dd_rescue -x dd_rescue dd_rescue.copy
	cat dd_rescue dd_rescue > dd_rescue.copy2
	cmp dd_rescue.copy dd_rescue.copy2
	@rm dd_rescue.copy dd_rescue.copy2
	@rm -f zero zero2
	$(VG) ./dd_rescue -r -S 1M -m 4k /dev/null zero
	@rm -f zero
	@echo "***** dd_rescue sparse tests *****"
	$(VG) ./dd_rescue -a -m 261k /dev/zero zero
	du zero
	$(VG) ./dd_rescue -S 12k -m 4k -b 4k -Z 0 zero
	$(VG) ./dd_rescue -S 20k -m 4k -b 4k -Z 0 zero
	$(VG) ./dd_rescue -a -b 8k zero zero2
	du zero zero2
	cmp zero zero2
	@rm zero2
	$(VG) ./dd_rescue -a -b 16k zero zero2
	du zero zero2
	cmp zero zero2
	@rm zero zero2
	@rm -f TEST TEST2
	@echo "***** dd_rescue RND overwrite tests *****"
	$(VG) ./dd_rescue -m 97263283 /dev/zero TEST
	$(VG) ./dd_rescue -MA -Z 0 TEST
	$(VG) ./dd_rescue -MA -2 /dev/urandom TEST
	@rm TEST
	@echo "***** dd_rescue ratecontrol test *****"
	# Test system must be fast enough to achieve ~20MB/s ...
	OLDDT=`date +%s`; $(VG) ./dd_rescue -m 64M -C 20M /dev/zero /dev/null; DT=`date +%s`; ARCH=$$(uname -m); test $$(($$DT-$$OLDDT)) = 3 -o $$(($$DT-$$OLDDT)) = 4 || test $$(($$DT-$$OLDDT)) -ge 5 -a $${ARCH:0:3} = ppc
	@echo "***** dd_rescue MD5 plugin tests *****"
	$(VG) ./md5 /dev/null
	$(VG) ./md5 /dev/null | md5sum -c
	$(VG) ./dd_rescue -a -b 16k -l TEST.log -o BB.log -m 32k /dev/zero TEST
	$(VG) ./dd_rescue -a -b 16k -m 32k /dev/zero TEST
	$(VG) ./dd_rescue -x -a -b 16k -m32k dd_rescue TEST
	$(VG) ./dd_rescue -x -a -b 16k -m17k /dev/zero TEST
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_MD5.so=output TEST TEST2 >HASH.TEST
	md5sum -c HASH.TEST
	#MD5=$$(./dd_rescue -c0 -a -b16k -L ./libddr_MD5.so TEST TEST2 2>&1 | grep 'MD5(0)': | tail -n1 | sed 's/^dd_rescue: (info): MD5(0):[^:]*: //'); MD5S=$$(md5sum TEST | sed 's/ .*$$//'); echo $$MD5 $$MD5S; if test "$$MD5" != "$$MD5S"; then false; fi
	rm -f HASH.TEST
	$(VG) ./sha1 /dev/null
	$(VG) ./sha1 /dev/null | sha1sum -c
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_hash.so=outnm=HASH.TEST:alg=sha1 TEST TEST2
	sha1sum -c HASH.TEST
	if test $(HAVE_SHA256SUM) = 1; then $(MAKE) check_sha2; fi
	$(VG) ./sha256 /dev/null
	$(VG) ./sha512 /dev/null
	rm -f TEST TEST2 HASH.TEST BB.log TEST.log
	if test $(HAVE_LZO) = 1; then $(MAKE) check_lzo; fi
	if test $(HAVE_LZO) = 1; then $(MAKE) check_lzo_algos; fi
	#if test $(HAVE_LZO) = 1; then $(MAKE) check_lzo_test; fi
	if test $(HAVE_LZO) = 1; then $(MAKE) check_lzo_fuzz; fi
	# Tests for libddr_null
	$(VG) ./dd_rescue -L ./libddr_null.so=debug dd_rescue /dev/null
	# Tests with hash set_xattr and chk_xattr (with fallback as not all filesystems support xattrs ...)
	$(VG) ./dd_rescue -tL ./libddr_hash.so=sha256:set_xattr:fallback dd_rescue /tmp/dd_rescue
	$(VG) ./dd_rescue -L ./libddr_hash.so=sha256:chk_xattr:fallback /tmp/dd_rescue /dev/null
	rm -f /tmp/dd_rescue CHECKSUMS.sha256
	# Tests with prepend and append
	$(VG) ./dd_rescue -tL ./libddr_hash.so=sha512:set_xattr:fallback:prepend=abc:append=xyz dd_rescue /tmp/dd_rescue
	$(VG) ./dd_rescue  -L ./libddr_hash.so=sha512:chk_xattr:fallback /tmp/dd_rescue /dev/null && false || true
	$(VG) ./dd_rescue  -L ./libddr_hash.so=sha512:chk_xattr:fallback:prepend=abc:append=xyz /tmp/dd_rescue /dev/null
	# Extra xattrs (should be preserved)
	#make check_xattr_copy
	# Tests with HMAC
	echo "what do ya want for nothing?" > TEST
	echo "09d6428f7ebaf21a6b53d86c9699cca0 *TEST" > HMACS.md5
	if test `stat -c %s TEST` == 29; then $(VG) ./dd_rescue -L ./libddr_hash.so=md5:hmacpwd=Jefe:chknm= TEST /dev/null; else echo "WARN: TEST file has unexpected size, skipping HMAC test"; hexdump -C TEST; fi
	rm -f /tmp/dd_rescue CHECKSUMS.sha512 TEST HMACS.md5
	if ./calchmac.py sha1 pass dd_rescue; then $(MAKE) check_hmac; else echo "Sorry, no more HMAC test due to missing python-hashlib support"; true; fi
	$(MAKE) check_fault
	#$(MAKE) check_aes
	$(MAKE) check_crypt


# FIXME: This fails on filesystems without xattr support - disabled until we know how to handle this
check_xattr_copy: $(TARGETS)
	$(VG) ./dd_rescue -pt dd_rescue dd_rescue.cmp
	attr -s testattr -V testval dd_rescue.cmp
	attr -qg testattr dd_rescue.cmp > attr
	$(VG) ./dd_rescue -pt -L ./libddr_hash.so=sha256:set_xattr dd_rescue.cmp dd_rescue.cmp2
	attr -qg testattr dd_rescue.cmp2 > attr2
	cmp attr attr2
	rm attr attr2 dd_rescue.cmp dd_rescue.cmp2


check_hmac: $(TARGETS)
	FILES="$(SRCDIR)/*.c $(SRCDIR)/*.h *.po dd_rescue *.so"; \
	for alg in md5 sha1 sha256 sha384; do \
		./calchmac.py $$alg pass_$$alg $$FILES > HMACS.$$alg; \
	done
	for name in $(SRCDIR)/*.c $(SRCDIR)/*.h *.po dd_rescue *.so; do \
		for alg in md5 sha1 sha256 sha384; do \
			$(VG) ./dd_rescue -L ./libddr_hash.so=$$alg:hmacpwd=pass_$$alg:chknm= $$name /dev/null || exit 1; \
		done \
	done
	rm -f HMACS.md5 HMACS.sha1 HMACS.sha256 HMACS.sha384

	
check_sha2: $(TARGETS) sha224 sha384
	rm -f CHECKSUMS.sha256 CHECKSUMS.sha512
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_hash.so=output:alg=sha224 TEST TEST2 >HASH.TEST
	sha224sum -c HASH.TEST
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_hash.so=outnm=:alg=sha256 TEST TEST2 >HASH.TEST
	sha256sum -c CHECKSUMS.sha256
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_hash.so=output:alg=sha384 TEST TEST2 >HASH.TEST
	sha384sum -c HASH.TEST
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_hash.so=outnm=:alg=sha512 TEST TEST2
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_hash.so=outnm=:alg=sha512,./libddr_null.so=change dd_rescue /dev/null
	sha512sum -c CHECKSUMS.sha512
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_hash.so=sha512:chknm=CHECKSUMS.sha512 TEST2 /dev/null
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_hash.so=alg=sha512:chknm= dd_rescue /dev/null
	$(VG) ./dd_rescue -c0 -a -b16k -t -L ./libddr_hash.so=sha512:check dd_rescue /dev/null <CHECKSUMS.sha512
	$(VG) ./sha224 /dev/null | sha224sum -c
	$(VG) ./sha256 /dev/null | sha256sum -c
	$(VG) ./sha384 /dev/null | sha384sum -c
	$(VG) ./sha512 /dev/null | sha512sum -c
	rm -f HASH.TEST CHECKSUMS.sha256 CHECKSUMS.sha512 TEST2

check_lzo: $(TARGETS)
	@echo "***** dd_rescue lzo (and MD5) plugin tests *****"
	$(VG) ./dd_rescue -b32k -ATL ./libddr_lzo.so dd_rescue dd_rescue.ddr.lzo
	$(LZOP) -t dd_rescue.ddr.lzo
	@cp -p dd_rescue dd_rescue.ddr
	$(LZOP) -fd dd_rescue.ddr.lzo
	cmp dd_rescue dd_rescue.ddr
	@rm -f dd_rescue.ddr dd_rescue.ddr.lzo
	$(VG) ./dd_rescue -b256k -L ./libddr_MD5.so=output,./libddr_lzo.so=compress,./libddr_MD5.so=output dd_rescue dd_rescue.ddr.lzo > dd_rescue.ddr.MD5SUM
	md5sum -c dd_rescue.ddr.MD5SUM
	md5sum dd_rescue dd_rescue.ddr.lzo
	$(LZOP) -Nvl dd_rescue.ddr.lzo
	$(VG) ./dd_rescue -b256k -TL ./libddr_MD5.so=output,./libddr_lzo.so=compress,./libddr_MD5.so,./libddr_lzo.so=decompress,./libddr_MD5.so=outfd=1 dd_rescue dd_rescue.ddr > dd_rescue.ddr.MD5
	cmp dd_rescue dd_rescue.ddr
	md5sum -c dd_rescue.ddr.MD5
	$(VG) ./dd_rescue -b16k -TL ./libddr_MD5.so=output,./libddr_lzo.so=compress,./libddr_MD5.so,./libddr_lzo.so=decompress,./libddr_MD5.so=outfd=1 dd_rescue dd_rescue.ddr > dd_rescue.ddr.MD5
	cmp dd_rescue dd_rescue.ddr
	md5sum -c dd_rescue.ddr.MD5
	@cp -p dd_rescue.ddr.lzo dd_rescue.lzo
	@rm -f dd_rescue.ddr dd_rescue.ddr.lzo dd_rescue.ddr.MD5
	$(LZOP) -f dd_rescue
	$(VG) ./dd_rescue -b256k -TL ./libddr_lzo.so dd_rescue.lzo dd_rescue.cmp
	cmp dd_rescue dd_rescue.cmp
	@rm -f dd_rescue.cmp dd_rescue.lzo
	$(VG) ./dd_rescue -b16k -L ./libddr_MD5.so=output,./libddr_lzo.so,./libddr_MD5.so=output dd_rescue dd_rescue.lzo > MD5.1
	$(VG) ./dd_rescue -b 8k -L ./libddr_MD5.so=output,./libddr_lzo.so,./libddr_MD5.so=output dd_rescue.lzo dd_rescue.cmp > MD5.2
	cmp dd_rescue dd_rescue.cmp
	md5sum dd_rescue dd_rescue.lzo
	md5sum -c MD5.1
	md5sum -c MD5.2
	@rm -f dd_rescue.lzo dd_rescue.cmp MD5.1 MD5.2
	# Sparse testing and MULTIPART testing and extend
	$(VG) ./dd_rescue -ta -m 64k /dev/zero test
	$(VG) ./dd_rescue -ax dd_rescue test
	$(VG) ./dd_rescue -axm 128k /dev/zero test
	$(VG) ./dd_rescue -taL ./libddr_MD5.so test test2
	$(VG) ./dd_rescue -taL ./libddr_MD5.so=output,./libddr_lzo.so,./libddr_MD5.so=output test test.lzo > MD5
	md5sum -c MD5
	rm -f MD5 test2
	$(VG) ./dd_rescue -axL ./libddr_lzo.so,./libddr_MD5.so=output dd_rescue test.lzo > MD5
	#md5sum -c MD5
	$(LZOP) -Nvl test.lzo
	cat dd_rescue >> test
	$(VG) ./dd_rescue -aL ./libddr_lzo.so,./libddr_MD5.so=output test.lzo test.cmp > MD5
	md5sum -c MD5
	cmp test test.cmp
	rm -f MD5 test test.lzo test.cmp
	
check_lzo_algos: $(TARGETS)
	for alg in lzo1x_1 lzo1x_1_11 lzo1x_1_12 lzo1x_1_15 lzo1x_999 lzo1y_1 lzo1y_999 lzo1f_1 lzo1f_999 lzo1b_1 lzo1b_2 lzo1b_3 lzo1b_4 lzo1b_5 lzo1b_6 lzo1b_7 lzo1b_8 lzo1b_9 lzo1b_99 lzo1b_999 lzo2a_999; do ./dd_rescue -qATL ./libddr_lzo.so=algo=$$alg:benchmark dd_rescue dd_rescue.lzo || exit 1; $(LZOP) -lt dd_rescue.lzo; ./dd_rescue -qATL ./libddr_lzo.so=benchmark dd_rescue.lzo dd_rescue.cmp || exit 2; cmp dd_rescue dd_rescue.cmp || exit 3; done

check_lzo_test: $(TARGETS)
	find . -type f
	find . -type f | xargs ./test_lzo.sh

check_lzo_fuzz: $(TARGETS) fuzz_lzo
	# Do intelligent fuzzing before feeding to dd_rescue -L lzo=decompress
	# Intelligent fuzzing means starting from valid .lzo, and adding
	#  distortions, with and without fixing checksums ...
	./test_lzo_fuzz.sh


ALGS = AES128-ECB AES128-CBC AES128-CTR AES128+-ECB AES128+-CBC AES128+-CTR AES128x2-ECB AES128x2-CBC AES128x2-CTR \
	AES192-ECB AES192-CBC AES192-CTR AES192+-ECB AES192+-CBC AES192+-CTR AES192x2-ECB AES192x2-CBC AES192x2-CTR \
	AES256-ECB AES256-CBC AES256-CTR AES256+-ECB AES256+-CBC AES256+-CTR AES256x2-ECB AES256x2-CBC AES256x2-CTR 

check_aes: $(TARGETS) test_aes
	# FIXME: No AESNI detection here, currently :-(
	for alg in $(ALGS); do $(VG) ./test_aes $$alg 10000 || exit $$?; done

check_crypt: $(TARGETS) test_aes
	# TODO: Move previous cases into script ...
	HAVE_LZO=$(HAVE_LZO) HAVE_OPENSSL=$(HAVE_OPENSSL) HAVE_AES=$(HAVE_AES) ./test_crypt.sh
	# Holes (all)
	# Reverse (CTR, ECB)
	# Chain with lzo, hash (all)
	# Various ways to pass in keys/IVs
	# Padding variations
	# OpenSSL compatibility
	# Algs and Engines
	rm -f dd_rescue.enc dd_rescue.dec dd_rescue.enc.orig dd_rescue2 KEYS.* IVS.*

check_fault: $(TARGETS)
	# Test fault injection
	# Only one fault, should be handled by retrying.
	$(VG) ./dd_rescue -tpv -F 4r/1,6r/1,22r/1 dd_rescue dd_rescue.cmp || true
	cmp dd_rescue dd_rescue.cmp
	# Incremental
	$(VG) ./dd_rescue -tp -F 4r/0,20r/0 -l dd_r.log -o dd_r.bb dd_rescue dd_rescue.cmp || true
	$(VG) ./dd_rescue -tp -F 4r/0,20r/0 dd_rescue dd_rescue.cmp || true
	cmp dd_rescue dd_rescue.cmp || true
	$(VG) ./dd_rescue -p -F 6r/0 dd_rescue dd_rescue.cmp || true
	cmp dd_rescue dd_rescue.cmp
	# Write errors: We recover from one of them
	$(VG) ./dd_rescue -tp -F 4w/1,22w/1 dd_rescue dd_rescue.cmp || true
	#$(VG) ./dd_rescue -p -F 6w/1 dd_rescue dd_rescue.cmp || true
	cmp dd_rescue dd_rescue.cmp
	# Write errors: Fill in ...
	$(VG) ./dd_rescue -tp -b 16k -F 4w/2,22w/2 dd_rescue dd_rescue.cmp || true
	$(VG) ./dd_rescue -p -b 16k -F 12w/2 dd_rescue dd_rescue.cmp || true
	cmp dd_rescue dd_rescue.cmp
	# TODO: More fault injection tests!
	# Test reverse, holes, ... with faults
	#
	# TODO: Fault injection combined with
	# - encryption (check_crypt)
	# - compression
	# - checksums
	rm -f dd_rescue.cmp dd_r.log dd_r.bb


make_check_crypt: check_crypt
	$(VG) ./dd_rescue -tp -L ./libddr_crypt.so=enc:keygen:keysfile:ivgen:ivsfile:alg=AES192+-CTR dd_rescue dd_rescue.enc
	$(VG) ./dd_rescue -tp -L ./libddr_crypt.so=dec:keysfile:ivsfile:alg=AES192+-CTR dd_rescue.enc dd_rescue.dec
	cmp dd_rescue dd_rescue.dec
	# Reverse (CTR, ECB)
	cp -p dd_rescue.enc dd_rescue.enc.orig
	$(VG) ./dd_rescue -tpr -L ./libddr_crypt.so=enc:keysfile:ivsfile:alg=AES192+-CTR dd_rescue dd_rescue.enc
	cmp dd_rescue.enc.orig dd_rescue.enc
	$(VG) ./dd_rescue -tpr -L ./libddr_crypt.so=dec:keysfile:ivsfile:alg=AES192+-CTR dd_rescue.enc dd_rescue.dec
	cmp dd_rescue dd_rescue.dec
	# Appending (CTR)
	$(VG) ./dd_rescue -px -L ./libddr_crypt.so=enc:keysfile:ivsfile:alg=AES192+-CTR dd_rescue dd_rescue.enc
	$(VG) ./dd_rescue -tp -L ./libddr_crypt.so=dec:keysfile:ivsfile:alg=AES192+-CTR dd_rescue.enc dd_rescue.dec
	cat dd_rescue dd_rescue > dd_rescue2
	cmp dd_rescue2 dd_rescue.dec
	# Cleanup
	rm -f dd_rescue2 dd_rescue.dec dd_rescue.enc


