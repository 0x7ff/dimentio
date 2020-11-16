CC      ?= clang
CFLAGS  ?= -O2 -isysroot $$(xcrun -sdk iphoneos --show-sdk-path) -arch arm64 -mios-version-min=10.0 -Weverything
LDFLAGS ?=

LIBTOOL  ?= libtool
LDID     ?= ldid

SOVERSION := 1
LIBS      := -framework IOKit -framework CoreFoundation -lcompression

all: libdimentio.$(SOVERSION).dylib libdimentio.a dimentio dimentio-static

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ -x c $<

libdimentio.$(SOVERSION).dylib: libdimentio.o
	$(CC) $(CFLAGS) -dynamiclib -install_name "/usr/lib/$@" -o ./$@ ./libdimentio.o $(LDFLAGS) $(LIBS)
	$(LDID) -S ./$@

libdimentio.a: libdimentio.o
	$(LIBTOOL) -static -o ./$@ ./libdimentio.o

dimentio: dimentio.o libdimentio.$(SOVERSION).dylib
	$(CC) $(CFLAGS) -o $@ ./dimentio.o $(LDFLAGS) ./libdimentio.$(SOVERSION).dylib
	$(LDID) -Stfp0.plist ./$@
	chmod u+s ./$@

dimentio-static: dimentio.o libdimentio.a
	$(CC) $(CFLAGS) -o $@ ./dimentio.o $(LDFLAGS) ./libdimentio.a $(LIBS)
	$(LDID) -Stfp0.plist ./$@
	chmod u+s ./$@

clean:
	$(RM) dimentio{,-static} *.a *.o *.dylib

.PHONY: all clean