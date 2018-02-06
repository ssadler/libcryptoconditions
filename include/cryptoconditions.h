#include <stdio.h>
#include <stddef.h>
#include <Condition.h>
#include <Fulfillment.h>
#include <cJSON.h>


#ifndef CRYPTOCONDITIONS_H
#define CRYPTOCONDITIONS_H

#define BUF_SIZE 1024 * 1024


#ifdef __cplusplus
extern "C" {
#endif

struct CC;
struct CCVisitor;


/* Condition Type */
typedef struct CCType {
    uint8_t typeId;
    char name[100];
    Condition_PR asnType;
    int hasSubtypes;
    int (*visitChildren)(struct CC *cond, struct CCVisitor visitor);
    char *(*fingerprint)(struct CC *cond);
    unsigned long (*getCost)(struct CC *cond);
    uint32_t (*getSubtypes)(struct CC *cond);
    struct CC *(*fromJSON)(cJSON *params, char *err);
    void (*toJSON)(struct CC *cond, cJSON *params);
    void (*fromFulfillment)(Fulfillment_t *ffill, struct CC *cond);
    Fulfillment_t *(*toFulfillment)(struct CC *cond);
    int (*isFulfilled)(struct CC *cond);
    void (*free)(struct CC *cond);
} CCType;


/*
 * Crypto Condition
 */
typedef struct CC {
    CCType *type;
    union {
        struct { char *publicKey, *signature; };
        struct { char *preimage; size_t preimageLength; };
        struct { long threshold; int size; struct CC **subconditions; };
        struct { unsigned char *prefix; size_t prefixLength; struct CC *subcondition; unsigned long maxMessageLength; };
        struct { char fingerprint[32]; uint32_t subtypes; unsigned long cost; };
        struct { char method[64]; char *conditionAux; size_t conditionAuxLength; char *fulfillmentAux; size_t fulfillmentAuxLength; };
	};
} CC;


/*
 * Crypto Condition Visitor
 */
typedef struct CCVisitor {
    int (*visit)(struct CC *cond, struct CCVisitor visitor);
    char *msg;
    size_t msgLength;
    void *context;
} CCVisitor;


/*
 * Common API
 */
size_t cc_conditionBinary(struct CC *cond, char *buf);
size_t cc_fulfillmentBinary(struct CC *cond, char *buf);
int cc_readFulfillmentBinary(struct CC *cond, char *ffill_bin, size_t ffill_bin_len);
int cc_visit(struct CC *cond, struct CCVisitor visitor);
struct CC *cc_conditionFromJSON(cJSON *params, char *err);
struct CC *cc_conditionFromJSONString(const char *json, char *err);
struct cJSON *cc_conditionToJSON(struct CC *cond);
char *cc_conditionToJSONString(struct CC *cond);
unsigned long cc_getCost(struct CC *cond);
int cc_isFulfilled(struct CC *cond);
static void fulfillmentToCC(Fulfillment_t *ffill, CC *cond);
typedef int (*VerifyAux)(CC *cond, void *context);
int cc_verify(struct CC *cond, char *msg, size_t msgLength, char *condBin, size_t condBinLength,
        VerifyAux verifyAux, void *auxContext);
void cc_free(struct CC *cond);
int cc_verifyAux(CC *cond, VerifyAux fn, void *context);
static int cc_signTreeEd25519(struct CC *cond, char *privateKey, char *msg, size_t msgLength);


/*
 * Internal API
 */
static uint32_t fromAsnSubtypes(ConditionTypes_t types);
static void mkAnon(Condition_t *asnCond, CC *cond);
static void asnCondition(CC *cond, Condition_t *asn);
static Condition_t *asnConditionNew(CC *cond);
static Fulfillment_t *asnFulfillmentNew(CC *cond);
static cJSON *jsonEncodeCondition(cJSON *params, char *err);
static uint32_t getSubtypes(CC *cond);
static CCType *getTypeByAsnEnum(Condition_PR present);
static void fulfillmentToCC(Fulfillment_t *ffill, CC *cond);


/*
 * Return codes
 */
enum CCResult {
    CC_OK = 0,
    CC_Error = 1
};


#ifdef __cplusplus
}
#endif

#endif  /* CRYPTOCONDITIONS_H */
