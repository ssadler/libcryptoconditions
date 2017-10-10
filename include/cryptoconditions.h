#include <stdio.h>
#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif

struct CC;


/* Condition Type */
typedef struct CCType {
    uint8_t typeId;
    char name[100];
    Condition_PR asnType;
    int (*verify)(struct CC *cond, char *msg);
    char *(*fingerprint)(struct CC *cond);
    unsigned long (*getCost)(struct CC *cond);
    Condition_t *(*asAsn)(struct CC *cond);
    uint32_t (*getSubtypes)(struct CC *cond);
} CCType;


/* Condition */
typedef struct CC {
	CCType type;
	union {
        struct { char *publicKey, *signature; };
        struct { char *preimage; size_t preimageLen; };
        struct { long threshold; int size; struct CC **subconditions; };
	};
} CC;


int readFulfillment(struct CC *cond, char *ffill_bin, size_t ffill_bin_len);
Condition_t *simpleAsnCondition(CC *cond);


/*
 * preimage Condition Type
 */
int preimageVerify(struct CC *cond, char *msg);
char *preimageFingerprint(struct CC *cond);
unsigned long preimageCost(struct CC *cond);

struct CCType preimageType = { 0, "preimage-sha-256", Condition_PR_preimageSha256, &preimageVerify, &preimageFingerprint, &preimageCost, &simpleAsnCondition, NULL };


/*
 * threshold Condition type
 */
int thresholdVerify(struct CC *cond, char *msg);
char *thresholdFingerprint(struct CC *cond);
unsigned long thresholdCost(struct CC *cond);
Condition_t *thresholdAsAsn(struct CC *cond);
uint32_t thresholdSubtypes(struct CC *cond);

struct CCType thresholdType = { 2, "threshold-sha-256", Condition_PR_thresholdSha256, &thresholdVerify, &thresholdFingerprint, &thresholdCost, &thresholdAsAsn, &thresholdSubtypes };


/*
 * ed25519 Condition Type
 */
int ed25519Verify(struct CC *cond, char *msg);
char *ed25519Fingerprint(struct CC *cond);
unsigned long ed25519Cost(struct CC *cond);
Condition_t *ed25519AsnCondition(struct CC *cond);

struct CCType ed25519Type = { 4, "ed25519-sha-256", Condition_PR_ed25519Sha256, &ed25519Verify, &ed25519Fingerprint, &ed25519Cost, &simpleAsnCondition, NULL };


struct CCType *typeRegistry[] = { &preimageType, NULL, &thresholdType, NULL, &ed25519Type };

void freeCondition(CC *cond);

#ifdef __cplusplus
}
#endif


