#include "include/cJSON.h"
#include "asn/asn_application.h"


char *base64_encode(const unsigned char *data, size_t input_length);

unsigned char *base64_decode(const char *data_, size_t *output_length);

void dumpStr(char *str, size_t len);

int checkString(cJSON *value, char *key, char *err);

int checkDecodeBase64(cJSON *value, char *key, char *err, char **data, size_t *size);

int *jsonGetBase64(cJSON *params, char *key, char *err, char **data, size_t *size);

char *hashFingerprintContents(asn_TYPE_descriptor_t *asnType, void *fp);
