LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SRCS += \
	$(LOCAL_DIR)/adler32.c \
	$(LOCAL_DIR)/crc32.c \
	$(LOCAL_DIR)/deflate_compress.c \
	$(LOCAL_DIR)/deflate_decompress.c \
	$(LOCAL_DIR)/gzip_compress.c \
	$(LOCAL_DIR)/gzip_decompress.c \
	$(LOCAL_DIR)/utils.c \
	$(LOCAL_DIR)/zlib_compress.c \
	$(LOCAL_DIR)/zlib_decompress.c \

include make/module.mk
