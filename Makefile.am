
lib_LTLIBRARIES=libcryptoconditions.la
libcryptoconditions_la_SOURCES = src/cryptoconditions.c \
	src/utils.c \
	src/include/base58.c \
	src/include/cJSON.c \
	src/asn/Condition.c	\
	src/asn/SimpleSha256Condition.c	\
	src/asn/CompoundSha256Condition.c	\
	src/asn/ConditionTypes.c	\
	src/asn/Fulfillment.c	\
	src/asn/PreimageFulfillment.c	\
	src/asn/PrefixFulfillment.c	\
	src/asn/ThresholdFulfillment.c	\
	src/asn/RsaSha256Fulfillment.c	\
	src/asn/Ed25519Sha512Fulfillment.c	\
	src/asn/PrefixFingerprintContents.c	\
	src/asn/ThresholdFingerprintContents.c	\
	src/asn/RsaFingerprintContents.c	\
	src/asn/Ed25519FingerprintContents.c \
	src/asn/INTEGER.c \
	src/asn/NativeEnumerated.c \
	src/asn/NativeInteger.c \
	src/asn/asn_SET_OF.c \
	src/asn/constr_CHOICE.c \
	src/asn/constr_SEQUENCE.c \
	src/asn/constr_SET_OF.c \
	src/asn/OCTET_STRING.c \
	src/asn/BIT_STRING.c \
	src/asn/asn_codecs_prim.c \
	src/asn/ber_tlv_length.c \
	src/asn/ber_tlv_tag.c \
	src/asn/ber_decoder.c \
	src/asn/der_encoder.c \
	src/asn/constr_TYPE.c \
	src/asn/constraints.c \
	src/asn/xer_support.c \
	src/asn/xer_decoder.c \
	src/asn/xer_encoder.c \
	src/asn/per_support.c \
	src/asn/per_decoder.c \
	src/asn/per_encoder.c \
	src/asn/per_opentype.c
libcryptoconditions_la_LIBADD = -lsodium
AM_CFLAGS = -I$(top_srcdir)/src/asn -I$(top_srcdir)/include
