#include "include/cJSON.h"
#include "asn/asn_application.h"
#include "cryptoconditions.h"

#ifndef INTERNAL_H
#define INTERNAL_H


#ifdef __cplusplus
extern "C" {
#endif


#define BUF_SIZE 1024 * 1024


/*
 * Condition Type */
typedef struct CCType {
    uint8_t typeId;
    unsigned char name[100];
    Condition_PR asnType;
    int hasSubtypes;
    int (*visitChildren)(struct CC *cond, struct CCVisitor visitor);
    unsigned char *(*fingerprint)(struct CC *cond);
    unsigned long (*getCost)(struct CC *cond);
    uint32_t (*getSubtypes)(struct CC *cond);
    struct CC *(*fromJSON)(cJSON *params, unsigned char *err);
    void (*toJSON)(struct CC *cond, cJSON *params);
    struct CC *(*fromFulfillment)(Fulfillment_t *ffill);
    Fulfillment_t *(*toFulfillment)(struct CC *cond);
    int (*isFulfilled)(struct CC *cond);
    void (*free)(struct CC *cond);
} CCType;


/*
 * Globals
 */
static struct CCType *typeRegistry[];
static int typeRegistryLength;


/*
 * Internal API
 */
static uint32_t fromAsnSubtypes(ConditionTypes_t types);
static CC *mkAnon(Condition_t *asnCond);
static void asnCondition(CC *cond, Condition_t *asn);
static Condition_t *asnConditionNew(CC *cond);
static Fulfillment_t *asnFulfillmentNew(CC *cond);
static uint32_t getSubtypes(CC *cond);
static cJSON *jsonEncodeCondition(cJSON *params, unsigned char *err);
static struct CC *fulfillmentToCC(Fulfillment_t *ffill);
static struct CCType *getTypeByAsnEnum(Condition_PR present);


/*
 * Utility functions
 */
unsigned char *base64_encode(const unsigned char *data, size_t input_length);
unsigned char *base64_decode(const unsigned char *data_, size_t *output_length);
void dumpStr(unsigned char *str, size_t len);
int checkString(cJSON *value, unsigned char *key, unsigned char *err);
int checkDecodeBase64(cJSON *value, unsigned char *key, unsigned char *err, unsigned char **data, size_t *size);
int jsonGetBase64(cJSON *params, unsigned char *key, unsigned char *err, unsigned char **data, size_t *size);
unsigned char *hashFingerprintContents(asn_TYPE_descriptor_t *asnType, void *fp);


#ifdef __cplusplus
}
#endif

#endif  /* INTERNAL_H */
