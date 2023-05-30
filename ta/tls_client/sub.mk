global-incdirs-y += include
srcs-y += ta_entry.c
srcs-$(CFG_TA_MBEDTLS) += mbedtls_clnt.c

CRYPT_FILE_TO_C_SCRIPT = ../../scripts/file_to_c.py
CRYPT_CA_CRT = cert/ca.crt
CRYPT_MID_CRT = cert/mid.crt
CRYPT_MID_KEY = cert/mid.key

define crypt_embed_file
# 1 prefix/name
# 2 infile
gensrcs-y += embed-file-$(1)
produce-embed-file-$(1) = $(1).c
depends-embed-file-$(1) := $(FILE_TO_C_SCRIPT) $(2)
recipe-embed-file-$(1) := $(CRYPT_FILE_TO_C_SCRIPT) --inf $(2) --out $(sub-dir-out)/$(1).c --name $(1)
cleanfiles += $(sub-dir-out)/$(1).c
endef

$(eval $(call crypt_embed_file,ca_crt,./cert/ca.crt))
$(eval $(call crypt_embed_file,mid_crt,./cert/mid.crt))
$(eval $(call crypt_embed_file,mid_key,./cert/mid.key))
