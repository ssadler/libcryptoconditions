

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length);


unsigned char *base64_decode(const char *data_,
                             size_t input_length,
                             size_t *output_length);


void dumpStr(char *str, size_t len);
