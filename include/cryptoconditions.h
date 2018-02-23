#include <Condition.h>
#include <Fulfillment.h>
#include <cJSON.h>

#include "include/secp256k1/include/secp256k1.h"


#ifndef CRYPTOCONDITIONS_H
#define CRYPTOCONDITIONS_H


#ifdef __cplusplus
extern "C" {
#endif


struct CC;
struct CCType;

/*
 * Auxiliary verification callback
 */
typedef int (*VerifyAux)(struct CC *cond, void *context);


/*
 * Crypto Condition
 */
typedef struct CC {
    struct CCType *type;
    union {
        struct { unsigned char *publicKey, *signature; };
        struct { unsigned char *preimage; size_t preimageLength; };
        struct { long threshold; int size; struct CC **subconditions; };
        struct { unsigned char *prefix; size_t prefixLength; struct CC *subcondition;
                 unsigned long maxMessageLength; };
        struct { unsigned char fingerprint[32]; uint32_t subtypes; unsigned long cost; };
        struct { secp256k1_pubkey *secpPublicKey; secp256k1_ecdsa_signature *secpSignature; };
        struct { unsigned char method[64]; unsigned char *conditionAux; size_t conditionAuxLength; unsigned char *fulfillmentAux; size_t fulfillmentAuxLength; };
    };
} CC;



/*
 * Crypto Condition Visitor
 */
typedef struct CCVisitor {
    int (*visit)(struct CC *cond, struct CCVisitor visitor);
    unsigned char *msg;
    size_t msgLength;
    void *context;
} CCVisitor;


/*
 * Public methods
 */
int             cc_isFulfilled(struct CC *cond);
int             cc_verify(const struct CC *cond, const unsigned char *msg, size_t msgLength,
                        const unsigned char *condBin, size_t condBinLength,
                        VerifyAux verifyAux, void *auxContext);
int             cc_visit(struct CC *cond, struct CCVisitor visitor);
size_t          cc_conditionBinary(struct CC *cond, unsigned char *buf);
size_t          cc_fulfillmentBinary(struct CC *cond, unsigned char *buf, size_t bufLength);
static int      cc_signTreeEd25519(struct CC *cond, unsigned char *privateKey, unsigned char *msg,
                        size_t msgLength);
static int      cc_signTreeSecp256k1Msg32(struct CC *cond, unsigned char *privateKey, unsigned char *msg32);
static int      cc_secp256k1VerifyTreeMsg32(CC *cond, unsigned char *msg32);
struct CC*      cc_conditionFromJSON(cJSON *params, unsigned char *err);
struct CC*      cc_conditionFromJSONString(const unsigned char *json, unsigned char *err);
struct CC*      cc_readConditionBinary(unsigned char *cond_bin, size_t cond_bin_len);
struct CC*      cc_readFulfillmentBinary(unsigned char *ffill_bin, size_t ffill_bin_len);
struct cJSON*   cc_conditionToJSON(struct CC *cond);
unsigned char*  cc_conditionToJSONString(struct CC *cond);
unsigned char*  cc_conditionUri(struct CC *cond);
unsigned char*  cc_jsonRPC(unsigned char *request);
unsigned long   cc_getCost(struct CC *cond);
void            cc_free(struct CC *cond);


#ifdef __cplusplus
}
#endif

#endif  /* CRYPTOCONDITIONS_H */
