global-incdirs-y += include
global-incdirs-y += .

srcs-y += ta_entry.c net_gpsockets.c
srcs-$(CFG_TA_MBEDTLS) += mbedtls_client.c

CRYPT_FILE_TO_C_SCRIPT = scripts/file_to_c.py

define crypt_embed_file
# 1 prefix/name
# 2 infile
gensrcs-y += $(1)
produce-$(1) = $(1).c
depends-$(1) = $(CRYPT_FILE_TO_C_SCRIPT) $(2)
recipe-$(1) = $(PYTHON3) $(CRYPT_FILE_TO_C_SCRIPT) --inf $(2) --out $(sub-dir-out)/$(1).c --name $(1)
cleanfiles += $(sub-dir-out)/$(1).c
endef

$(eval $(call crypt_embed_file,mid_crt,$(sub-dir)/cert/mid.crt))
$(eval $(call crypt_embed_file,ca_crt,$(sub-dir)/cert/ca.crt))
$(eval $(call crypt_embed_file,mid_key,$(sub-dir)/cert/mid.key))

$(info leizhou debugging is $(sub-dir-out) $(sub-dir))
# gensrcs-y += ca_crt
# produce-ca_crt = ca_crt.c
# depends-ca_crt = $(CRYPT_FILE_TO_C_SCRIPT)  
# recipe-ca_crt = $(PYTHON3) $(CRYPT_FILE_TO_C_SCRIPT) --inf $(sub-dir)/cert/ca.crt --out $(sub-dir-out)/ca_crt.c --name ca_crt

