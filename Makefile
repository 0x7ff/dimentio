.PHONY: all macos clean

ROOTLESS 						:= 0
RPREFIX 	 					:= "/usr"
RLPREFIX 	 					:= "/var/jb/usr"

all:
ifeq ($(shell [ "$(ROOTLESS)" -gt 0 ] && echo 1),1)
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything libdimentio.c dimentio.c -o dimentio -DPREFIX=\"$(RLPREFIX)\" -framework IOKit -framework CoreFoundation -lcompression -Os
else
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=10.0 -Weverything libdimentio.c dimentio.c -o dimentio -DPREFIX=\"$(RPREFIX)\" -framework IOKit -framework CoreFoundation -lcompression -Os
endif

macos:
	xcrun -sdk macosx clang -arch arm64 -Weverything libdimentio.c dimentio.c -o dimentio -framework IOKit -framework CoreFoundation -lcompression -Os

clean:
	$(RM) dimentio
