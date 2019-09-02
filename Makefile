.PHONY: all clean

all:
	xcrun -sdk iphoneos clang -arch arm64 -Weverything dimentio.c -o dimentio -framework IOKit -framework CoreFoundation -O2
	codesign -s - --entitlements tfp0.plist dimentio
clean:
	$(RM) dimentio
