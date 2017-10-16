
#include "asn/Condition.h"
#include "asn/Fulfillment.h"
#include "asn/OCTET_STRING.h"
#include "include/cJSON.h"
#include "cryptoconditions.h"


static CC *preimageFromJSON(cJSON *params, char *err) {
    cJSON *preimage_item = cJSON_GetObjectItem(params, "preimage");
    if (!cJSON_IsString(preimage_item)) {
        strcpy(err, "preimage must be a string");
        return NULL;
    }
    char *preimage_b64 = preimage_item->valuestring;

    CC *cond = malloc(sizeof(CC));
    cond->type = &cc_preimageType;
    cond->preimage = base64_decode(preimage_b64, strlen(preimage_b64), &cond->preimageLength);
    return cond;
}


static int preimageVerify(CC *cond, char *msg, size_t length) {
    return 1; // no message to verify
}


static unsigned long preimageCost(CC *cond) {
    return (unsigned long) cond->preimageLength;
}


static char *preimageFingerprint(CC *cond) {
    char *hash = malloc(32); // TODO: need to allocate here?
    crypto_hash_sha256(hash, cond->preimage, cond->preimageLength);
    return hash;
}


static void preimageFfillToCC(Fulfillment_t *ffill, CC *cond) {
    cond->type = &cc_preimageType;
    PreimageFulfillment_t p = ffill->choice.preimageSha256;
    cond->preimage = malloc(p.preimage.size);
    memcpy(cond->preimage, p.preimage.buf, p.preimage.size);
    cond->preimageLength = p.preimage.size;
}


struct CCType cc_preimageType = { 0, "preimage-sha-256", Condition_PR_preimageSha256, 0, &preimageVerify, &preimageFingerprint, &preimageCost, NULL, &preimageFromJSON, &preimageFfillToCC };
