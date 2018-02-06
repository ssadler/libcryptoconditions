
#include "asn/Condition.h"
#include "asn/Fulfillment.h"
#include "asn/OCTET_STRING.h"
#include "include/cJSON.h"
#include "cryptoconditions.h"


struct CCType cc_preimageType;


static CC *preimageFromJSON(cJSON *params, char *err) {
    cJSON *preimage_item = cJSON_GetObjectItem(params, "preimage");
    if (!cJSON_IsString(preimage_item)) {
        strcpy(err, "preimage must be a string");
        return NULL;
    }
    char *preimage_b64 = preimage_item->valuestring;

    CC *cond = calloc(1, sizeof(CC));
    cond->type = &cc_preimageType;
    cond->preimage = base64_decode(preimage_b64, &cond->preimageLength);
    return cond;
}


static void preimageToJSON(CC *cond, cJSON *params) {
    char *encoded = base64_encode(cond->preimage, cond->preimageLength);
    cJSON_AddStringToObject(params, "preimage", encoded);
    free(encoded);
}


static unsigned long preimageCost(CC *cond) {
    return (unsigned long) cond->preimageLength;
}


static char *preimageFingerprint(CC *cond) {
    char *hash = calloc(1, 32);
    crypto_hash_sha256(hash, cond->preimage, cond->preimageLength);
    return hash;
}


static void preimageFromFulfillment(Fulfillment_t *ffill, CC *cond) {
    cond->type = &cc_preimageType;
    PreimageFulfillment_t p = ffill->choice.preimageSha256;
    cond->preimage = calloc(1, p.preimage.size);
    memcpy(cond->preimage, p.preimage.buf, p.preimage.size);
    cond->preimageLength = p.preimage.size;
}


static Fulfillment_t *preimageToFulfillment(CC *cond) {
    Fulfillment_t *ffill = calloc(1, sizeof(Fulfillment_t));
    ffill->present = Fulfillment_PR_preimageSha256;
    PreimageFulfillment_t *pf = &ffill->choice.preimageSha256;
    OCTET_STRING_fromBuf(&pf->preimage, cond->preimage, cond->preimageLength);
    return ffill;
}


int preimageIsFulfilled(CC *cond) {
    return 1;
}


static void preimageFree(CC *cond) {
    free(cond->preimage);
    free(cond);
}


static uint32_t preimageSubtypes(CC *cond) {
    return 0;
}


struct CCType cc_preimageType = { 0, "preimage-sha-256", Condition_PR_preimageSha256, 0, 0, &preimageFingerprint, &preimageCost, &preimageSubtypes, &preimageFromJSON, &preimageToJSON, &preimageFromFulfillment, &preimageToFulfillment, &preimageIsFulfilled, &preimageFree };
