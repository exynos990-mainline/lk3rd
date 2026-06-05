LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SRCS += \
	$(LOCAL_DIR)/display.c \
	$(LOCAL_DIR)/fastboot_menu.c \
	$(LOCAL_DIR)/kaslr_status.c \
	$(LOCAL_DIR)/keys.c \
	$(LOCAL_DIR)/mainline_quirks.c \
	$(LOCAL_DIR)/persistent_storage.c \
	$(LOCAL_DIR)/gpt.c \
	$(LOCAL_DIR)/automatic_repartitioning.c

include make/module.mk
