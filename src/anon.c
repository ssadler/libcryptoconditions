/******************************************************************************
 * Copyright © 2014-2019 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#include "asn/Condition.h"
#include "asn/Fulfillment.h"
#include "asn/PrefixFingerprintContents.h"
#include "asn/OCTET_STRING.h"
#include "../include/cryptoconditions.h"


struct CCType CC_AnonType;


CC* cc_anon(const CC *cond) {
    CC *out = cc_new(CC_Anon);
    out->conditionType = cond->type;
    out->cost = cc_getCost(cond);
    out->subtypes = cond->type->getSubtypes(cond);

    unsigned char *fp = cond->type->fingerprint(cond);
    memcpy(out->fingerprint, fp, 32);
    free(fp);
    return out;
}


CC *mkAnon(const Condition_t *asnCond) {

    CCType *realType = getTypeByAsnEnum(asnCond->present);
    if (!realType) {
        fprintf(stderr, "Unknown ASN type: %i", asnCond->present);
        return 0;
    }
    CC *cond = cc_new(CC_Anon);
    cond->conditionType = realType;
    const CompoundSha256Condition_t *deets = &asnCond->choice.thresholdSha256;
    memcpy(cond->fingerprint, deets->fingerprint.buf, 32);
    cond->cost = deets->cost;
    if (realType->getSubtypes) {
        cond->subtypes = fromAsnSubtypes(deets->subtypes);
    }
    return cond;
}

static CC* anonFromJSON(const cJSON *params, char *err) {
    CC* cond = cc_new(CC_Anon);
    cJSON *item = cJSON_GetObjectItem(params, "realtype");
    if (!checkString(item, "realtype", err)) {
        return NULL;
    }
    cond->conditionType = getTypeByName(item->valuestring);
    if (!cond->conditionType) {
        strcpy(err, "Unknown type of anon");
    }
    size_t len;
    uint8_t *fpbuf;
    if (!jsonGetBase64(params, "fingerprint", err, &fpbuf, &len) || len != 32) {
        strcpy(err, "invalid fingerprint in anon");
        goto error;
    }
    memcpy(cond->fingerprint, fpbuf, 32);
    cJSON *cost_item = cJSON_GetObjectItem(params, "cost");
    if (!cJSON_IsNumber(cost_item)) {
        strcpy(err, "cost must be a number");
        goto error;
    }
    cond->cost = cost_item->valueint;
    cJSON *subtypes_item = cJSON_GetObjectItem(params, "subtypes");
    if (!cJSON_IsNumber(subtypes_item)) {
        strcpy(err, "subtypes must be a number");
        goto error;
    }
    cond->subtypes = subtypes_item->valueint;
    return cond;
error:
    free(cond);
    return NULL;
}

static void anonToJSON(const CC *cond, cJSON *params) {
    unsigned char *b64 = base64_encode(cond->fingerprint, 32);
    cJSON_AddItemToObject(params, "fingerprint", cJSON_CreateString(b64));
    free(b64);
    cJSON_AddItemToObject(params, "cost", cJSON_CreateNumber(cond->cost));
    cJSON_AddItemToObject(params, "subtypes", cJSON_CreateNumber(cond->subtypes));
    cJSON_AddItemToObject(params, "realtype", cJSON_CreateString(cond->conditionType->name));
}


static unsigned char *anonFingerprint(const CC *cond) {
    unsigned char *out = calloc(1, 32);
    //fprintf(stderr,"anon fingerprint %p %p\n",out,cond->fingerprint);
    memcpy(out, cond->fingerprint, 32);
    return out;
}


static unsigned long anonCost(const CC *cond) {
    return cond->cost;
}


static uint32_t anonSubtypes(const CC *cond) {
    return cond->subtypes;
}


static Fulfillment_t *anonFulfillment(const CC *cond, FulfillmentFlags _flags) {
    return NULL;
}


static void anonFree(CC *cond) {
}


static int anonIsFulfilled(const CC *cond) {
    return 0;
}


struct CCType CC_AnonType = { -1, "(anon)", Condition_PR_NOTHING, NULL, &anonFingerprint, &anonCost, &anonSubtypes, &anonFromJSON, &anonToJSON, NULL, &anonFulfillment, &anonIsFulfilled, &anonFree };
