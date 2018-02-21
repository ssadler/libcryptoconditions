#include "cryptoconditions.h"
#include "internal.h"
#include <cJSON.h>
#include <malloc.h>


static cJSON *jsonCondition(CC *cond) {
    char buf[1000];
    size_t conditionBinLength = cc_conditionBinary(cond, buf);

    cJSON *root = cJSON_CreateObject();
    char *uri = cc_conditionUri(cond);
    cJSON_AddItemToObject(root, "uri", cJSON_CreateString(uri));
    free(uri);

    char *b64 = base64_encode(buf, conditionBinLength);
    cJSON_AddItemToObject(root, "bin", cJSON_CreateString(b64));
    free(b64);

    return root;
}


static cJSON *jsonFulfillment(CC *cond) {
    char buf[1000000];
    size_t fulfillmentBinLength = cc_fulfillmentBinary(cond, buf, 1000000);

    cJSON *root = cJSON_CreateObject();
    char *b64 = base64_encode(buf, fulfillmentBinLength);
    cJSON_AddItemToObject(root, "fulfillment", cJSON_CreateString(b64));
    free(b64);

    return root;
}


int jsonGet(cJSON *object, char *name, char *target) {
    cJSON *item = cJSON_GetObjectItem(object, name);
    if (!cJSON_IsString(item)) {
        return 1;
    } else if (strlen(item->valuestring) > malloc_usable_size(target)) {
        return 2;
    }
    strcpy(target, item->valuestring);
    return 0;
}


CC *cc_conditionFromJSON(cJSON *params, char *err) {
    if (!cJSON_IsObject(params)) {
        strcpy(err, "Condition params must be an object");
        return NULL;
    }
    char typeName[100];
    if (0 != jsonGet(params, "type", typeName)) {
        strcpy(err, "\"type\" not valid");
        return NULL;
    }
    for (int i=0; i<typeRegistryLength; i++) {
        if (typeRegistry[i] != NULL) {
            if (0 == strcmp(typeName, typeRegistry[i]->name)) {
                return typeRegistry[i]->fromJSON(params, err);
            }
        }
    }
    strcpy(err, "cannot detect type of condition");
    return NULL;
}


CC *cc_conditionFromJSONString(const char *data, char *err) {
    cJSON *params = cJSON_Parse(data);
    CC *out = cc_conditionFromJSON(params, err);
    cJSON_Delete(params);
    return out;
}


static cJSON *jsonEncodeCondition(cJSON *params, char *err) {
    CC *cond = cc_conditionFromJSON(params, err);
    cJSON *out = NULL;
    if (cond != NULL) {
        out = jsonCondition(cond);
        cc_free(cond);
    }
    return out;
}


static cJSON *jsonEncodeFulfillment(cJSON *params, char *err) {
    CC *cond = cc_conditionFromJSON(params, err);
    cJSON *out = NULL;
    if (cond != NULL) {
        out = jsonFulfillment(cond);
        cc_free(cond);
    }
    return out;
}


static cJSON *jsonErr(char *err) {
    cJSON *out = cJSON_CreateObject();
    cJSON_AddItemToObject(out, "error", cJSON_CreateString(err));
    return out;
}


static cJSON *jsonVerifyFulfillment(cJSON *params, char *err) {
    char *ffill_bin = 0, *msg = 0, *cond_bin = 0;
    size_t ffill_bin_len, msg_len, cond_bin_len;
    cJSON *out = 0;


    if (!(jsonGetBase64(params, "fulfillment", err, &ffill_bin, &ffill_bin_len) &&
          jsonGetBase64(params, "message", err, &msg, &msg_len) &&
          jsonGetBase64(params, "condition", err, &cond_bin, &cond_bin_len)))
        goto END;

    CC *cond = cc_readFulfillmentBinary(ffill_bin, ffill_bin_len);

    if (!cond) {
        strcpy(err, "Invalid fulfillment payload");
        goto END;
    }

    int valid = cc_verify(cond, msg, msg_len, cond_bin, cond_bin_len);
    cc_free(cond);
    out = cJSON_CreateObject();
    cJSON_AddItemToObject(out, "valid", cJSON_CreateBool(valid));

END:
    free(ffill_bin); free(msg); free(cond_bin);
    return out;
}


static cJSON *jsonDecodeFulfillment(cJSON *params, char *err) {
    size_t ffill_bin_len;
    char *ffill_bin;
    if (!jsonGetBase64(params, "fulfillment", err, &ffill_bin, &ffill_bin_len))
        return NULL;

    CC *cond = cc_readFulfillmentBinary(ffill_bin, ffill_bin_len);
    free(ffill_bin);
    if (!cond) {
        strcpy(err, "Invalid fulfillment payload");
        return NULL;
    }
    cJSON *out = jsonCondition(cond);
    cc_free(cond);
    return out;
}


static cJSON *jsonDecodeCondition(cJSON *params, char *err) {
    size_t cond_bin_len;
    char *cond_bin;
    if (!jsonGetBase64(params, "bin", err, &cond_bin, &cond_bin_len))
        return NULL;

    CC *cond = cc_readConditionBinary(cond_bin, cond_bin_len);
    free(cond_bin);

    if (!cond) {
        strcpy(err, "Invalid condition payload");
        return NULL;
    }

    cJSON *out = jsonCondition(cond);
    cJSON_AddItemToObject(out, "condition", cc_conditionToJSON(cond));
    cc_free(cond);
    return out;
}


static cJSON *jsonSignTreeEd25519(cJSON *params, char *err) {
    cJSON *condition_item = cJSON_GetObjectItem(params, "condition");
    CC *cond = cc_conditionFromJSON(condition_item, err);
    if (cond == NULL) {
        return NULL;
    }

    cJSON *sk_b64_item = cJSON_GetObjectItem(params, "privateKey");
    cJSON *msg_b64_item = cJSON_GetObjectItem(params, "message");

    if (!cJSON_IsString(sk_b64_item)) {
        strcpy(err, "privateKey must be a string");
        return NULL;
    }
    if (!cJSON_IsString(msg_b64_item)) {
        strcpy(err, "message must be a string");
        return NULL;
    }

    size_t msg_len;
    char *msg = base64_decode(msg_b64_item->valuestring, &msg_len);
    if (!msg) {
        strcpy(err, "message is not valid b64");
        return 0;
    }

    size_t sk_len;
    char *privateKey = base64_decode(sk_b64_item->valuestring, &sk_len);
    if (!privateKey) {
        strcpy(err, "privateKey is not valid b64");
        return 0;
    }

    int nSigned = cc_signTreeEd25519(cond, privateKey, msg, msg_len);

    cJSON *out = cJSON_CreateObject();
    cJSON_AddItemToObject(out, "num_signed", cJSON_CreateNumber(nSigned));
    cJSON_AddItemToObject(out, "condition", cc_conditionToJSON(cond));

    cc_free(cond);
    free(msg);
    free(privateKey);

    return out;
}


cJSON *cc_conditionToJSON(CC *cond) {
    cJSON *params = cJSON_CreateObject();
    cJSON_AddItemToObject(params, "type", cJSON_CreateString(cond->type->name));
    cond->type->toJSON(cond, params);
    return params;
}


char *cc_conditionToJSONString(CC *cond) {
    cJSON *params = cc_conditionToJSON(cond);
    char *out = cJSON_Print(params);
    cJSON_Delete(params);
    return out;
}


static cJSON *jsonListMethods(cJSON *params, char *err);


typedef struct JsonMethod {
    char *name;
    cJSON* (*method)(cJSON *params, char *err);
    char *description;
} JsonMethod;


static JsonMethod cc_jsonMethods[] = {
    {"encodeCondition", &jsonEncodeCondition, "Encode a JSON condition to binary"},
    {"decodeCondition", &jsonDecodeCondition, "Decode a binary condition"},
    {"encodeFulfillment", &jsonEncodeFulfillment, "Encode a JSON condition to a fulfillment"},
    {"decodeFulfillment", &jsonDecodeFulfillment, "Decode a binary fulfillment"},
    {"verifyFulfillment", &jsonVerifyFulfillment, "Verify a fulfillment"},
    {"signTreeEd25519", &jsonSignTreeEd25519, "Sign ed25519 condition nodes"},
    {"listMethods", &jsonListMethods, "List available methods"}
};


static int nJsonMethods = sizeof(cc_jsonMethods) / sizeof(*cc_jsonMethods);


static cJSON *jsonListMethods(cJSON *params, char *err) {
    cJSON *list = cJSON_CreateArray();
    for (int i=0; i<nJsonMethods; i++) {
        JsonMethod method = cc_jsonMethods[i];
        cJSON *item = cJSON_CreateObject();
        cJSON_AddItemToObject(item, "name", cJSON_CreateString(method.name));
        cJSON_AddItemToObject(item, "description", cJSON_CreateString(method.description));
        cJSON_AddItemToArray(list, item);
    }
    cJSON *out = cJSON_CreateObject();
    cJSON_AddItemToObject(out, "methods", list);
    return out;
}


static cJSON* execJsonRPC(cJSON *root, char *err) {
    cJSON *method_item = cJSON_GetObjectItem(root, "method");

    if (!cJSON_IsString(method_item)) {
        return jsonErr("malformed method");
    }

    cJSON *params = cJSON_GetObjectItem(root, "params");
    if (!cJSON_IsObject(params)) {
        return jsonErr("params is not an object");
    }

    for (int i=0; i<nJsonMethods; i++) {
        JsonMethod method = cc_jsonMethods[i];
        if (0 == strcmp(method.name, method_item->valuestring)) {
            return method.method(params, err);
        }
    }

    return jsonErr("invalid method");
}


char *cc_jsonRPC(char* input) {
    cJSON *root = cJSON_Parse(input);
    char err[1000] = "\0";
    cJSON *out = execJsonRPC(root, err);
    if (NULL == out) out = jsonErr(err);
    char *res = cJSON_Print(out);
    cJSON_Delete(out);
    cJSON_Delete(root);
    return res;
}
