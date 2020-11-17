.PHONY: all clean

all:
	xcrun -sdk iphoneos clang -arch arm64 -arch arm64e -mios-version-min=10.0 -Weverything libdimentio.c dimentio.c -o dimentio -framework IOKit -framework CoreFoundation -lcompression -O2

clean:
	$(RM) dimentio
