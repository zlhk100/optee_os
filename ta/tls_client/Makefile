# The UUID for the Trusted Application
BINARY=03e24561-9c29-464f-947b-07bbe3a4306e

ifdef TA_CROSS_COMPILE
CROSS_COMPILE ?= $(TA_CROSS_COMPILE)
endif
export CROSS_COMPILE

CFG_TEE_TA_LOG_LEVEL ?= 2
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

CPPFLAGS += -DEXIT_SUCCESS=0
CPPFLAGS += -DEXIT_FAILURE=1

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
clean:
        @echo 'Note: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk not found, cannot clean TA'
        @echo 'Note: TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)'
endif
