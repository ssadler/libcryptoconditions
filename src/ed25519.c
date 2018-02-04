
#include "asn/Condition.h"
#include "asn/Fulfillment.h"
#include "asn/Ed25519FingerprintContents.h"
#include "asn/OCTET_STRING.h"
#include "include/cJSON.h"
#include "cryptoconditions.h"


#define emptySig "0000000000000000000000000000000000000000000000000000000000000000"


struct CCType cc_ed25519Type;


static char *ed25519Fingerprint(CC *cond) {
    Ed25519FingerprintContents_t *fp = calloc(1, sizeof(Ed25519FingerprintContents_t));
    OCTET_STRING_fromBuf(&fp->publicKey, cond->publicKey, 32);
    
    char out[BUF_SIZE];
    asn_enc_rval_t rc = der_encode_to_buffer(&asn_DEF_Ed25519FingerprintContents, fp, out, BUF_SIZE);
    ASN_STRUCT_FREE(asn_DEF_Ed25519FingerprintContents, fp);

    if (rc.encoded == -1) {
        return NULL; // TODO assert
    }
    char *hash = calloc(1, 32);
    crypto_hash_sha256(hash, out, rc.encoded);
    return hash;
}


static int ed25519VerifyMessage(CC *cond, char *msg, size_t length) {
    int rc = crypto_sign_verify_detached(cond->signature, msg, length, cond->publicKey);
    return rc == 0;
}


static unsigned long ed25519Cost(CC *cond) {
    return 131072;
}


static CC *ed25519FromJSON(cJSON *params, char *err) {
    size_t binsz;

    cJSON *pk_item = cJSON_GetObjectItem(params, "publicKey");
    if (!cJSON_IsString(pk_item)) {
        strcpy(err, "publicKey must be a string");
        return NULL;
    }
    char *pk = base64_decode(pk_item->valuestring, &binsz);
    if (32 != binsz) {
        strcpy(err, "publicKey has incorrect length");
        free(pk);
        return NULL;
    }

    cJSON *signature_item = cJSON_GetObjectItem(params, "signature");
    char *sig = NULL;
    if (!cJSON_IsNull(signature_item)) {
        if (!cJSON_IsString(signature_item)) {
            strcpy(err, "signature must be null or a string");
            return NULL;
        }
        sig = base64_decode(signature_item->valuestring, &binsz);
        if (64 != binsz) {
            strcpy(err, "signature has incorrect length");
            free(sig);
            return NULL;
        }
    }

    CC *cond = calloc(1, sizeof(CC));
    cond->type = &cc_ed25519Type;
    cond->publicKey = pk;
    cond->signature = sig;
    return cond;
}


static void ed25519ToJSON(CC *cond, cJSON *params) {
    char *b64 = base64_encode(cond->publicKey, 32);
    cJSON_AddItemToObject(params, "publicKey", cJSON_CreateString(b64));
    free(b64);
    if (cond->signature) {
        b64 = base64_encode(cond->signature, 64);
        cJSON_AddItemToObject(params, "signature", cJSON_CreateString(b64));
        free(b64);
    }
}


static void ed25519FromFulfillment(Fulfillment_t *ffill, CC *cond) {
    cond->type = &cc_ed25519Type;
    cond->publicKey = malloc(32);
    memcpy(cond->publicKey, ffill->choice.ed25519Sha256.publicKey.buf, 32);
    cond->signature = malloc(64);
    memcpy(cond->signature, ffill->choice.ed25519Sha256.signature.buf, 64);
}


static Fulfillment_t *ed25519ToFulfillment(CC *cond) {
    if (!cond->signature) {
        return NULL;
    }
    Fulfillment_t *ffill = calloc(1, sizeof(Fulfillment_t));
    ffill->present = Fulfillment_PR_ed25519Sha256;
    Ed25519Sha512Fulfillment_t *ed2 = &ffill->choice.ed25519Sha256;
    OCTET_STRING_fromBuf(&ed2->publicKey, cond->publicKey, 32);
    OCTET_STRING_fromBuf(&ed2->signature, cond->signature, 64);
    return ffill;
}


int ed25519IsFulfilled(CC *cond) {
    return cond->signature > 0;
}


static void ed25519Free(CC *cond) {
    free(cond->publicKey);
    if (cond->signature) {
        free(cond->signature);
    }
    free(cond);
}


static uint32_t ed25519Subtypes(CC *cond) {
    return 0;
}


struct CCType cc_ed25519Type = { 4, "ed25519-sha-256", Condition_PR_ed25519Sha256, 0, &ed25519VerifyMessage, &ed25519Fingerprint, &ed25519Cost, &ed25519Subtypes, &ed25519FromJSON, &ed25519ToJSON, &ed25519FromFulfillment, &ed25519ToFulfillment, &ed25519IsFulfilled, &ed25519Free };
