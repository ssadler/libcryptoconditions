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


int readFulfillment(struct CC *cond, char *ffill_bin, size_t ffill_bin_len);


/*
 * preimage Condition Type (0)
 */
int preimageVerify(struct CC *cond, char *msg);
char *preimageFingerprint(struct CC *cond);
unsigned long preimageCost(struct CC *cond);
CC *preimageFromJSON(cJSON *params, char *err);
void preimageFfillToCC(Fulfillment_t *ffill, CC *cond);

struct CCType preimageType = { 0, "preimage-sha-256", Condition_PR_preimageSha256, 0, &preimageVerify, &preimageFingerprint, &preimageCost, NULL, &preimageFromJSON, &preimageFfillToCC };


/*
 * prefix Condition type (1)
 */
int prefixVerify(struct CC *cond, char *msg);
char *prefixFingerprint(struct CC *cond);
unsigned long prefixCost(struct CC *cond);
uint32_t prefixSubtypes(struct CC *cond);
CC *prefixFromJSON(cJSON *params, char *err);
void prefixFfillToCC(Fulfillment_t *ffill, CC *cond);

struct CCType prefixType = { 1, "prefix-sha-256", Condition_PR_prefixSha256, 1, &prefixVerify, &prefixFingerprint, &prefixCost, &prefixSubtypes, &prefixFromJSON, &prefixFfillToCC };


/*
 * threshold Condition type (2)
 */
int thresholdVerify(struct CC *cond, char *msg);
char *thresholdFingerprint(struct CC *cond);
unsigned long thresholdCost(struct CC *cond);
uint32_t thresholdSubtypes(struct CC *cond);
CC *thresholdFromJSON(cJSON *params, char *err);
void thresholdFfillToCC(Fulfillment_t *ffill, CC *cond);

struct CCType thresholdType = { 2, "threshold-sha-256", Condition_PR_thresholdSha256, 1, &thresholdVerify, &thresholdFingerprint, &thresholdCost, &thresholdSubtypes, &thresholdFromJSON, &thresholdFfillToCC };


/*
 * ed25519 Condition Type (4)
 */
int ed25519Verify(struct CC *cond, char *msg);
char *ed25519Fingerprint(struct CC *cond);
unsigned long ed25519Cost(struct CC *cond);
CC *ed25519FromJSON(cJSON *params, char *err);
void ed25519FfillToCC(Fulfillment_t *ffill, CC *cond);

struct CCType ed25519Type = { 4, "ed25519-sha-256", Condition_PR_ed25519Sha256, 0, &ed25519Verify, &ed25519Fingerprint, &ed25519Cost, NULL, &ed25519FromJSON, &ed25519FfillToCC };


/*
 * Anon Type (Condition with no fulfillment details, ie a decoded condition URI)
 */

int anonVerify(struct CC *cond, char *msg);
char *anonFingerprint(struct CC *cond);
unsigned long anonCost(struct CC *cond);
uint32_t anonSubtypes(struct CC *cond);

struct CCType anonType = { -1, "anon                           ", Condition_PR_NOTHING, 0, &anonVerify, &anonFingerprint, &anonCost, &anonSubtypes, NULL, NULL };

/*
 * Registry
 */
struct CCType *typeRegistry[] = { &preimageType, &prefixType, &thresholdType, NULL, &ed25519Type };
int typeRegistryLength = 5;

void freeCondition(CC *cond);
Condition_t *asnCondition(CC *cond);
void ffillToCC(Fulfillment_t *ffill, CC *cond);
void mkAnon(Condition_t *asnCond, CC *cond);


#ifdef __cplusplus
}
#endif


