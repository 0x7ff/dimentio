.PHONY: all clean

all:
	xcrun -sdk iphoneos clang -arch arm64 -arch arm64e -Weverything dimentio.c -o dimentio -framework IOKit -framework CoreFoundation -O2

clean:
	$(RM) dimentio
