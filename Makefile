.PHONY: all macos clean

all:
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything libdimentio.c dimentio.c -o dimentio -framework IOKit -framework CoreFoundation -lcompression -O2

macos:
	xcrun -sdk macosx clang -arch arm64 -Weverything libdimentio.c dimentio.c -o dimentio -framework IOKit -framework CoreFoundation -lcompression -O2

clean:
	$(RM) dimentio
