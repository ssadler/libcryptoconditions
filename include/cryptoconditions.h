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
    struct CC *(*fromJSON)(cJSON *params, char *err);
} CCType;


/* Condition */
typedef struct CC {
	CCType type;
	union {
        struct { char *publicKey, *signature; };
        struct { char *preimage; size_t preimageLength; };
        struct { long threshold; int size; struct CC **subconditions; };
        struct { unsigned char *prefix; int prefixLength; struct CC *subcondition; unsigned long maxMessageLength; };
	};
} CC;


int readFulfillment(struct CC *cond, char *ffill_bin, size_t ffill_bin_len);
Condition_t *simpleAsnCondition(CC *cond);


/*
 * preimage Condition Type (0)
 */
int preimageVerify(struct CC *cond, char *msg);
char *preimageFingerprint(struct CC *cond);
unsigned long preimageCost(struct CC *cond);
CC *preimageFromJSON(cJSON *params, char *err);

struct CCType preimageType = { 0, "preimage-sha-256", Condition_PR_preimageSha256, &preimageVerify, &preimageFingerprint, &preimageCost, &simpleAsnCondition, NULL, &preimageFromJSON };


/*
 * prefix Condition type (1)
 */
int prefixVerify(struct CC *cond, char *msg);
char *prefixFingerprint(struct CC *cond);
unsigned long prefixCost(struct CC *cond);
Condition_t *prefixAsAsn(struct CC *cond);
uint32_t prefixSubtypes(struct CC *cond);
CC *prefixFromJSON(cJSON *params, char *err);

struct CCType prefixType = { 1, "prefix-sha-256", Condition_PR_prefixSha256, &prefixVerify, &prefixFingerprint, &prefixCost, &prefixAsAsn, &prefixSubtypes, &prefixFromJSON };


/*
 * threshold Condition type (2)
 */
int thresholdVerify(struct CC *cond, char *msg);
char *thresholdFingerprint(struct CC *cond);
unsigned long thresholdCost(struct CC *cond);
Condition_t *thresholdAsAsn(struct CC *cond);
uint32_t thresholdSubtypes(struct CC *cond);
CC *thresholdFromJSON(cJSON *params, char *err);

struct CCType thresholdType = { 2, "threshold-sha-256", Condition_PR_thresholdSha256, &thresholdVerify, &thresholdFingerprint, &thresholdCost, &thresholdAsAsn, &thresholdSubtypes, &thresholdFromJSON };


/*
 * ed25519 Condition Type (4)
 */
int ed25519Verify(struct CC *cond, char *msg);
char *ed25519Fingerprint(struct CC *cond);
unsigned long ed25519Cost(struct CC *cond);
Condition_t *ed25519AsnCondition(struct CC *cond);
CC *ed25519FromJSON(cJSON *params, char *err);

struct CCType ed25519Type = { 4, "ed25519-sha-256", Condition_PR_ed25519Sha256, &ed25519Verify, &ed25519Fingerprint, &ed25519Cost, &simpleAsnCondition, NULL, &ed25519FromJSON };


/*
 * Registry
 */
struct CCType *typeRegistry[] = { &preimageType, &prefixType, &thresholdType, NULL, &ed25519Type };
int typeRegistryLen = 5;

void freeCondition(CC *cond);

#ifdef __cplusplus
}
#endif


