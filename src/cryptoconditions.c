
#include "asn/Condition.h"
#include "asn/Fulfillment.h"
#include "asn/Ed25519FingerprintContents.h"
#include "asn/OCTET_STRING.h"
#include "include/cJSON.h"
#include "cryptoconditions.h"
#include "utils.h"
#include <sodium.h>


#define streq(a, b) strcmp(a, b) == 0


char *ed25519Fingerprint(CC *cond) {
    Ed25519FingerprintContents_t fp;
    fp.publicKey =* OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, cond->publicKey, 32);
    char *out = malloc(100);
    char *hash = malloc(32);

    der_encode_to_buffer(&asn_DEF_Ed25519FingerprintContents, &fp, out, 100);
    crypto_hash_sha256(hash, out, 36); // TODO: Why is it neccesary to hardcode
                                       // 36 here? strlen says 38
    //asn_DEF_OCTET_STRING.free_struct(&asn_DEF_OCTET_STRING, &(fp.publicKey), 0);
    free(out);
    return hash;
}


char *fingerprintTypes(int mask) {
    char *out = malloc(1000);
    int append = 0;
    for (int i=0; i<5; i++) {
        if (mask & 1 << i) {
            fprintf(stderr, "%i\n", i);
            if (append) {
                strcat(out, ",");
                strcat(out, typeRegistry[i]->name);
            } else strcpy(out, typeRegistry[i]->name);
            append = 1;
        }
    }
    return out;
}


char *conditionUri(CC *cond) {
    char *fp = cond->type.fingerprint(cond);
    size_t len;
    char *encoded = base64_encode(fp, 32, &len);
    int cost = cond->type.getCost(cond);

    char *out = malloc(1000);
    sprintf(out, "ni:///sha-256;%s?fpt=%s&cost=%i", encoded, cond->type.name, cost);

    free(fp);
    free(encoded);

    return out;
}

int subtypes(CC *cond) {
    if (cond->type.typeId == ed25519Type.typeId) {
        return 1 << ed25519Type.typeId;
    } else if (cond->type.typeId == preimageType.typeId) {
        return 1 << preimageType.typeId;
    }
    return 0;
}


cJSON *jsonCondition(CC *cond) {
    char *uri = conditionUri(cond);
    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "uri", cJSON_CreateString(uri));
    free(uri);
    return root;
}


int ed25519Verify(CC *cond, char *msg) {
    int rc = crypto_sign_verify_detached(cond->signature, msg, strlen(msg), cond->publicKey);
    return rc == 0;
}

int ed25519Cost(CC *cond) {
    return 131072;
}


CC *ed25519Condition(cJSON *params, char *err) {
    cJSON *pk_item = cJSON_GetObjectItem(params, "public_key");
    if (!cJSON_IsString(pk_item)) {
        err = "public_key must be a string";
        return NULL;
    }
    char *pk_b64 = pk_item->valuestring;
    size_t binsz;

    CC *cond = malloc(sizeof(CC));
    cond->type = ed25519Type;
    cond->publicKey = base64_decode(pk_b64, strlen(pk_b64), &binsz);
    cond->signature = NULL;
    return cond;
}


CC *preimageCondition(cJSON *params, char *err) {
    cJSON *preimage_item = cJSON_GetObjectItem(params, "preimage");
    if (!cJSON_IsString(preimage_item)) {
        err = "preimage must be a string";
        return NULL;
    }
    char *preimage_b64 = preimage_item->valuestring;

    CC *cond = malloc(sizeof(CC));
    cond->type = preimageType;
    cond->preimage = base64_decode(preimage_b64, strlen(preimage_b64), &cond->preimageLen);
    return cond;
}


int preimageVerify(CC *cond, char *msg) {
    return 1; // no message to verify
}

int preimageCost(CC *cond) {
    return (int) cond->preimageLen;
}


char *preimageFingerprint(CC *cond) {
    char *hash = malloc(32); // TODO: need to allocate here?
    crypto_hash_sha256(hash, cond->preimage, cond->preimageLen);
    return hash;
}


cJSON *makeCondition(cJSON *params, char **err) {
    CC *cond;
    if (cJSON_HasObjectItem(params, "public_key")) {
        cond = ed25519Condition(params, err);
    } else if (cJSON_HasObjectItem(params, "preimage")) {
        cond = preimageCondition(params, err);
    } else {
        *err = "cannot detect type of condition";
        return NULL;
    }
    return jsonCondition(cond); // TODO: free(cond);
}


void ffill_to_cc(Fulfillment_t *ffill, CC *cond) {
    if (ffill->present == Fulfillment_PR_ed25519Sha256) {
        cond->type = ed25519Type;
        cond->publicKey = malloc(32);
        memcpy(cond->publicKey, ffill->choice.ed25519Sha256.publicKey.buf, 32);
        cond->signature = malloc(64);
        memcpy(cond->signature, ffill->choice.ed25519Sha256.signature.buf, 64);
    }
    else {
        // TODO
        fprintf(stderr, "Unknown fulfillment type\n");
    }
}


int readFulfillment(struct CC *cond, char *ffill_bin, size_t ffill_bin_len) {
    Fulfillment_t *ffill = 0;
    asn_dec_rval_t rval;
    rval = ber_decode(0, &asn_DEF_Fulfillment, (void **)&ffill, ffill_bin, ffill_bin_len);
    if (rval.code == RC_OK) {
        ffill_to_cc(ffill, cond);
    }
    asn_DEF_Fulfillment.free_struct(&asn_DEF_Fulfillment, ffill, 0);
    if (rval.code == RC_OK) return 0;
    return 1;
}


cJSON *jsonVerifyFulfillment(cJSON *params) {
    cJSON *uri_item = cJSON_GetObjectItem(params, "uri");
    if (!cJSON_IsString(uri_item)) {
        return "uri must be a string";
    }

    cJSON *msg_item = cJSON_GetObjectItem(params, "message");
    if (!cJSON_IsString(msg_item)) {
        return "message must be a string";
    }

    cJSON *ffill_b64_item = cJSON_GetObjectItem(params, "fulfillment");
    if (!cJSON_IsString(ffill_b64_item)) {
        return "fulfillment must be a string";
    }

    size_t ffill_bin_len;
    char *ffill_bin = base64_decode(ffill_b64_item->valuestring,
            strlen(ffill_b64_item->valuestring), &ffill_bin_len);

    CC *cond = malloc(sizeof(CC));

    int rc = readFulfillment(cond, ffill_bin, ffill_bin_len);
    if (rc != 0) return "Invalid fulfillment payload";

    cJSON *out = cJSON_CreateObject();
    int valid = verifyFulfillment(cond, msg_item->valuestring);
    cJSON_AddItemToObject(out, "valid", cJSON_CreateBool(valid));
    return out;
}


int verifyFulfillment(CC *cond, char *msg) {
    return cond->type.verify(cond, msg);
}


cJSON *decodeFulfillment(cJSON *params) {
    cJSON *ffill_b64_item = cJSON_GetObjectItem(params, "fulfillment");
    if (!cJSON_IsString(ffill_b64_item)) {
        return "fulfillment must be a string";
    }

    size_t ffill_bin_len;
    char *ffill_bin = base64_decode(ffill_b64_item->valuestring,
            strlen(ffill_b64_item->valuestring), &ffill_bin_len);

    CC *cond = malloc(sizeof(CC));
    int rc = readFulfillment(cond, ffill_bin, ffill_bin_len);
    if (rc != 0) return "Invalid fulfillment payload";

    return jsonCondition(cond);
}


char *jsonRPC(char* input) {
    // TODO: Return proper errors
    // cJSON free structures? (everywhere)
    cJSON *root = cJSON_Parse(input);
    cJSON *method_item = cJSON_GetObjectItem(root, "method");
    if (!cJSON_IsString(method_item)) {
        return "malformed method";
    }
    char *method = method_item->valuestring;
    cJSON *params = cJSON_GetObjectItem(root, "params");
    if (!cJSON_IsObject(params)) {
        return "params is not an object";
    }

    cJSON *out;
    char *err = NULL;

    if (streq(method, "makeCondition")) {
        out = makeCondition(params, &err);
        if (out == NULL) {
            out = cJSON_CreateObject();
            cJSON_AddItemToObject(out, "error", cJSON_CreateString(err));
        }
    }

    else if (streq(method, "decodeFulfillment")) {
        out = decodeFulfillment(params);
    }

    else if (streq(method, "verifyFulfillment")) {
        out = jsonVerifyFulfillment(params);
    }

    else {
        out = cJSON_CreateObject();
        cJSON_AddItemToObject(out, "error", cJSON_CreateString("invalid method"));
    }    
    
    char *res = cJSON_Print(out);
    cJSON_Delete(out);
    return res;
}



void dumpCondition(CC *cond) {
    size_t olen;
    char *str;

    fprintf(stderr, "COND:");
    if (cond->type.typeId == ed25519Type.typeId) {
        str = base64_encode(cond->publicKey, 32, &olen);
        fprintf(stderr, "%s", str);
        free(str);
    } else {
    }
    fprintf(stderr, "\n");
}


