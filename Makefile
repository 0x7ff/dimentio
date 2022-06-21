.PHONY: all macos clean

all:
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything libdimentio.c dimentio.c -o dimentio -framework IOKit -framework CoreFoundation -Os

macos:
	xcrun -sdk macosx clang -arch arm64 -Weverything libdimentio.c dimentio.c -o dimentio -framework IOKit -framework CoreFoundation -Os

clean:
	$(RM) dimentio
