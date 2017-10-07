#include <stdio.h>
#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif

struct CC;


typedef struct CCType {
    int typeId;
    char name[100];
    int (*verify)(struct CC *cond, char *msg);
    char *(*fingerprint)(struct CC *cond);
    int (*getCost)(struct CC *cond);
} CCType;


/* Condition */
typedef struct CC {
	CCType type;
	union {
        struct { char *publicKey, *signature; };
        struct { char *preimage; size_t preimageLen };
	};
} CC;


int readFulfillment(struct CC *cond, char *ffill_bin, size_t ffill_bin_len);


/*
 * preimage Condition Type
 */
int preimageVerify(struct CC *cond, char *msg);
char *preimageFingerprint(struct CC *cond);
int preimageCost(struct CC *cond);
struct CCType preimageType = { 0, "preimage-sha-256", &preimageVerify, &preimageFingerprint, &preimageCost };


/*
 * ed25519 Condition Type
 */
int ed25519Verify(struct CC *cond, char *msg);
char *ed25519Fingerprint(struct CC *cond);
int ed25519Cost(struct CC *cond);
struct CCType ed25519Type = { 4, "ed25519-sha-256", &ed25519Verify, &ed25519Fingerprint, &ed25519Cost };


struct CCType *typeRegistry[] = { &preimageType, NULL, NULL, NULL, &ed25519Type };

void freeCondition(CC *cond);

#ifdef __cplusplus
}
#endif


