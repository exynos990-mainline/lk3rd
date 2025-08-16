LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SRCS += \
	$(LOCAL_DIR)/lib/adler32.c \
	$(LOCAL_DIR)/lib/crc32.c \
	$(LOCAL_DIR)/lib/deflate_compress.c \
	$(LOCAL_DIR)/lib/deflate_decompress.c \
	$(LOCAL_DIR)/lib/gzip_compress.c \
	$(LOCAL_DIR)/lib/gzip_decompress.c \
	$(LOCAL_DIR)/lib/utils.c \
	$(LOCAL_DIR)/lib/zlib_compress.c \
	$(LOCAL_DIR)/lib/zlib_decompress.c \
	$(LOCAL_DIR)/lib/arm/cpu_features.c \
	$(LOCAL_DIR)/lib/x86/cpu_features.c \

include make/module.mk
