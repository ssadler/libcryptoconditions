/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Crypto-Conditions"
 * 	found in "../ext/crypto-conditions/src/asn1/CryptoConditions.asn"
 */

#ifndef	_RsaSha256Fulfillment_H_
#define	_RsaSha256Fulfillment_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RsaSha256Fulfillment */
typedef struct RsaSha256Fulfillment {
	OCTET_STRING_t	 modulus;
	OCTET_STRING_t	 signature;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RsaSha256Fulfillment_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RsaSha256Fulfillment;

#ifdef __cplusplus
}
#endif

#endif	/* _RsaSha256Fulfillment_H_ */
#include <asn_internal.h>
