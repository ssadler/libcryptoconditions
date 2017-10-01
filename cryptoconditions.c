
#include "src/models/Condition.h"
#include "src/models/Fulfillment.h"
#include "src/models/Ed25519FingerprintContents.h"
#include "src/models/OCTET_STRING.h"
#include "include/cJSON.h"
#include "src/condition.c"
#include "src/utils.h"


#define streq(a, b) strcmp(a, b) == 0


char *getFingerprint(CC *cond) {
    Ed25519FingerprintContents_t fp;
    fp.publicKey =* OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, cond->publicKey, 32);
    char *out = malloc(100);
    char *hash = malloc(32);

    der_encode_to_buffer(&asn_DEF_Ed25519FingerprintContents, &fp, out, 100);
    crypto_hash_sha256(hash, out, 36); // TODO: Why is it neccesary to hardcode
                                       // 36 here? strlen says 38???
    //asn_DEF_OCTET_STRING.free_struct(&asn_DEF_OCTET_STRING, &(fp.publicKey), 0);
    free(out);
    return hash;
}


char *conditionUri(CC *cond) {
    char *out = malloc(1000);
    strcpy(out, "ni:///sha-256;");

    char *fp = getFingerprint(cond);
    size_t len;
    char *encoded = base64_encode(fp, 32, &len);

    strcat(out, encoded);
    strcat(out, "?fpt=ed25519-sha-256&cost=131072");
    return out;

    //"ni:///sha-256;eZI5q6j8T_fqv7xMROaei9_tmTMk4S7WR5Kr4onPHV8?fpt=ed25519-sha-256&cost=131072"
}


char *jsonCondition(CC *cond) {
    return conditionUri(cond);
}


char *makeEd25119Condition(cJSON *params) {
    cJSON *pk_item = cJSON_GetObjectItem(params, "public_key");
    if (!cJSON_IsString(pk_item)) {
        return "public_key must be a string";
    }
    char *pk_b64 = pk_item->valuestring;
    size_t binsz;

    CC *cond = malloc(sizeof(CC));
    cond->publicKey = base64_decode(pk_b64, strlen(pk_b64), &binsz);
    return jsonCondition(cond); // TODO: free(cond);
}


void ffill_to_cc(Fulfillment_t *ffill, CC *cond) {
    if (ffill->present == Fulfillment_PR_ed25519Sha256) {
        cond->type = ed25519Type;
        cond->publicKey = malloc(32);
        strcpy(cond->publicKey, ffill->choice.ed25519Sha256.publicKey.buf);
    }
    else {
        // TODO
        fprintf(stderr, "Unknown fulfillment type\n");
    }
}


int readFulfillment(CC *cond, char *ffill_bin) {
    Fulfillment_t *ffill = 0;
    asn_dec_rval_t rval;
    rval = ber_decode(0, &asn_DEF_Fulfillment, (void **)&ffill, ffill_bin, -1);
    if (rval.code == RC_OK) {
        ffill_to_cc(ffill, cond);
    }
    asn_DEF_Fulfillment.free_struct(&asn_DEF_Fulfillment, ffill, 0);
    if (rval.code == RC_OK) return 0;
    return 1;
}


char *verifyFulfillment(cJSON *params) {
    cJSON *uri_item = cJSON_GetObjectItem(params, "conditionUri");
    if (!cJSON_IsString(uri_item)) {
        return "conditionUri must be a string";
    }

    cJSON *ffill_b64_item = cJSON_GetObjectItem(params, "fulfillment");
    if (!cJSON_IsString(ffill_b64_item)) {
        return "fulfillment must be a string";
    }

    cJSON *msg_item = cJSON_GetObjectItem(params, "message");
    if (!cJSON_IsString(msg_item)) {
        return "message must be a string";
    }

    size_t ffill_bin_len;
    char *ffill_bin = base64_decode(ffill_b64_item->valuestring,
            strlen(ffill_b64_item->valuestring), &ffill_bin_len);


    CC *cond = malloc(sizeof(CC));
    int rc = readFulfillment(cond, ffill_bin);
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

    if (streq(method, "makeEd25519Condition")) {
        return makeEd25119Condition(params);
    }

    else if (streq(method, "verifyFulfillment")) {
        return verifyFulfillment(params);
    }

    return "a"; // todo: memory leak?
}
