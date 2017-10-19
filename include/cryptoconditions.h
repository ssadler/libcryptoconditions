#include <stdio.h>
#include <stddef.h>
#include <Condition.h>
#include <Fulfillment.h>
#include <cJSON.h>


#ifndef	CRYPTOCONDITIONS_H
#define	CRYPTOCONDITIONS_H

#define BUF_SIZE 1024 * 1024


#ifdef __cplusplus
extern "C" {
#endif

struct CC;


/* Condition Type */
typedef struct CCType {
    uint8_t typeId;
    char name[100];
    Condition_PR asnType;
    int hasSubtypes;
    int (*verifyMessage)(struct CC *cond, char *msg, size_t msgLength);
    char *(*fingerprint)(struct CC *cond);
    unsigned long (*getCost)(struct CC *cond);
    uint32_t (*getSubtypes)(struct CC *cond);
    struct CC *(*fromJSON)(cJSON *params, char *err);
    void (*fulfillmentToCC)(Fulfillment_t *ffill, struct CC *cond);
    void (*free)(struct CC *cond);
} CCType;


/* Condition */
typedef struct CC {
	CCType *type;
	union {
        struct { char *publicKey, *signature; };
        struct { char *preimage; size_t preimageLength; };
        struct { long threshold; int size; struct CC **subconditions; };
        struct { unsigned char *prefix; size_t prefixLength; struct CC *subcondition; unsigned long maxMessageLength; };
        struct { char fingerprint[32]; uint32_t subtypes; unsigned long cost; };
	};
} CC;

struct CCType cc_ed25519Type;
struct CCType cc_anonType;
struct CCType cc_prefixType;
struct CCType cc_preimageType;
struct CCType cc_thresholdType;


/*
 * Common API
 */
int cc_readFulfillmentBinary(struct CC *cond, char *ffill_bin, size_t ffill_bin_len);
int cc_verify(struct CC *cond, char *msg, size_t msgLength, char *condBin, size_t condBinLength);
int cc_verifyMessage(struct CC *cond, char *msg, size_t length);
void cc_free(struct CC *cond);
CCType *getTypeByAsnEnum(Condition_PR present);
int cc_verifyMessage(struct CC *cond, char *msg, size_t length);
struct CC *cc_conditionFromJSON(cJSON *params, char *err);


/*
 * Internal API
 */
static uint32_t fromAsnSubtypes(ConditionTypes_t types);
static void mkAnon(Condition_t *asnCond, CC *cond);
static void asnCondition(CC *cond, Condition_t *asn);
static uint32_t getSubtypes(CC *cond);
static cJSON *jsonMakeCondition(cJSON *params, char *err);
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
