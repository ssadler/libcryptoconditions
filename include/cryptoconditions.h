#include <stdio.h>
#include <stddef.h>


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
    int (*verify)(struct CC *cond, char *msg, size_t msgLength);
    char *(*fingerprint)(struct CC *cond);
    unsigned long (*getCost)(struct CC *cond);
    uint32_t (*getSubtypes)(struct CC *cond);
    struct CC *(*fromJSON)(cJSON *params, char *err);
    void (*ffillToCC)(Fulfillment_t *ffill, struct CC *cond);
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
int cc_readFulfillment(struct CC *cond, char *ffill_bin, size_t ffill_bin_len);
void cc_freeCondition(CC *cond);
void cc_ffillToCC(Fulfillment_t *ffill, CC *cond);
CCType *getTypeByAsnEnum(Condition_PR present);
static uint32_t fromAsnSubtypes(ConditionTypes_t types);

/*
 * Internal API
 */

static void mkAnon(Condition_t *asnCond, CC *cond);
static Condition_t *asnCondition(CC *cond);
static uint32_t getSubtypes(CC *cond);
static CC *conditionFromJSON(cJSON *params, char *err);



#ifdef __cplusplus
}
#endif

#endif  /* CRYPTOCONDITIONS_H */
