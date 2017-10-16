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
    int (*verify)(struct CC *cond, char *msg);
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

struct CCType ed25519Type;
struct CCType anonType;
struct CCType prefixType;
struct CCType preimageType;
struct CCType thresholdType;

int readFulfillment(struct CC *cond, char *ffill_bin, size_t ffill_bin_len);

/*
 * Registry
 */
struct CCType *typeRegistry[32];
int typeRegistryLength;

void freeCondition(CC *cond);
Condition_t *asnCondition(CC *cond);
void ffillToCC(Fulfillment_t *ffill, CC *cond);
void mkAnon(Condition_t *asnCond, CC *cond);
CCType *getTypeByAsnEnum(Condition_PR present);



#ifdef __cplusplus
}
#endif

#endif  /* CRYPTOCONDITIONS_H */
