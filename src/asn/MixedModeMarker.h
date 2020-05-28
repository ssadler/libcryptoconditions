/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Crypto-Conditions"
 * 	found in "CryptoConditions.asn"
 */

#ifndef	_MixedModeMarker_H_
#define	_MixedModeMarker_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MixedModeMarker */
typedef struct MixedModeMarker {
	long	 threshold;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MixedModeMarker_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MixedModeMarker;

#ifdef __cplusplus
}
#endif

#endif	/* _MixedModeMarker_H_ */
#include <asn_internal.h>
