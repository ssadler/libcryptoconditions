#include "cryptoconditions.h"

#ifndef INTERNAL_H
#define INTERNAL_H


#ifdef __cplusplus
extern "C" {
#endif


#define BUF_SIZE 1024 * 1024


/*
 * Crypto Condition
 */
typedef struct CC {
    struct CCType *type;
    union {
        struct { char *publicKey, *signature; };
        struct { char *preimage; size_t preimageLength; };
        struct { long threshold; int size; struct CC **subconditions; };
        struct { unsigned char *prefix; size_t prefixLength; struct CC *subcondition;
                 unsigned long maxMessageLength; };
        struct { char fingerprint[32]; uint32_t subtypes; unsigned long cost; };
        struct { char method[64]; char *conditionAux; size_t conditionAuxLength; char *fulfillmentAux; size_t fulfillmentAuxLength; };
    };
} CC;


/*
 * Condition Type */
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
    struct CC *(*fromFulfillment)(Fulfillment_t *ffill);
    Fulfillment_t *(*toFulfillment)(struct CC *cond);
    int (*isFulfilled)(struct CC *cond);
    void (*free)(struct CC *cond);
} CCType;



/*
 * Internal API
 */
static uint32_t fromAsnSubtypes(ConditionTypes_t types);
static CC *mkAnon(Condition_t *asnCond);
static void asnCondition(CC *cond, Condition_t *asn);
static Condition_t *asnConditionNew(CC *cond);
static Fulfillment_t *asnFulfillmentNew(CC *cond);
static uint32_t getSubtypes(CC *cond);
static cJSON *jsonEncodeCondition(cJSON *params, char *err);
static struct CC *fulfillmentToCC(Fulfillment_t *ffill);
static struct CCType *getTypeByAsnEnum(Condition_PR present);


static struct CCType *typeRegistry[];
static int typeRegistryLength;


#ifdef __cplusplus
}
#endif

#endif  /* INTERNAL_H */
