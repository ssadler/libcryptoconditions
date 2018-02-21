#include <Condition.h>
#include <Fulfillment.h>
#include <cJSON.h>


#ifndef CRYPTOCONDITIONS_H
#define CRYPTOCONDITIONS_H


#ifdef __cplusplus
extern "C" {
#endif


struct CC;
struct CCType;

/*
 * Auxiliary verification callback
 */
typedef int (*VerifyAux)(struct CC *cond, void *context);


/*
 * Crypto Condition Visitor
 */
typedef struct CCVisitor {
    int (*visit)(struct CC *cond, struct CCVisitor visitor);
    char *msg;
    size_t msgLength;
    void *context;
} CCVisitor;

char*         cc_conditionToJSONString(struct CC *cond);
char*         cc_conditionUri(struct CC *cond);
char*         cc_jsonRPC(char *request);
int           cc_isFulfilled(struct CC *cond);
int           cc_verify(struct CC *cond, char *msg, size_t msgLength, char *condBin, size_t condBinLength,
                        VerifyAux verifyAux, void *auxContext);
int           cc_verifyAux(struct CC *cond, VerifyAux fn, void *context);
int           cc_visit(struct CC *cond, struct CCVisitor visitor);
size_t        cc_conditionBinary(struct CC *cond, char *buf);
size_t        cc_fulfillmentBinary(struct CC *cond, char *buf, size_t bufLength);
static int    cc_signTreeEd25519(struct CC *cond, char *privateKey, char *msg, size_t msgLength);
struct CC*    cc_conditionFromJSON(cJSON *params, char *err);
struct CC*    cc_conditionFromJSONString(const char *json, char *err);
struct CC*    cc_readConditionBinary(char *cond_bin, size_t cond_bin_len);
struct CC*    cc_readFulfillmentBinary(char *ffill_bin, size_t ffill_bin_len);
struct cJSON* cc_conditionToJSON(struct CC *cond);
unsigned long cc_getCost(struct CC *cond);
void          cc_free(struct CC *cond);


#ifdef __cplusplus
}
#endif

#endif  /* CRYPTOCONDITIONS_H */
