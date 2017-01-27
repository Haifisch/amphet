export THEOS_DEVICE_IP=10.0.1.5
TARGET=iphone::6.1
ARCHS=armv7 armv7s arm64
include $(THEOS)/makefiles/common.mk

TOOL_NAME = amphet
amphet_CFLAGS += -I./lib
amphet_FILES = libkern.c debug.c kernel_methods.c main.c 

include $(THEOS_MAKE_PATH)/tool.mk

before-package::
	ldid -Sent.plist $(THEOS_STAGING_DIR)/usr/bin/amphet