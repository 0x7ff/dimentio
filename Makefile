include $(THEOS)/makefiles/common.mk

ARCHS = arm64 arm64e

TOOL_NAME = dimentio
dimentio_FILES = dimentio.c
dimentio_CFLAGS = -D__arm64e__
dimentio_FRAMEWORKS = IOKit
dimentio_CODESIGN_FLAGS = -Stfp0.plist

include $(THEOS_MAKE_PATH)/tool.mk
