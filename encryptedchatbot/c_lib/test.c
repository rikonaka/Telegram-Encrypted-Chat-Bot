#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "libtecb.h"

int main(int argc, char *argv[])
{
    // Main function.

    char test_str[100] = "0123456789abcdef";
    char *input = test_str;
    char *encode_output;
    char *decode_output;
    encode_output = encode_c(input);
    //int len = strlen(output);
    //printf("%d", len);
    printf("%s\n", encode_output);
    decode_output = decode_c(encode_output);
    //printf("detect result: %d\n", detect_c(output));
    printf("%s\n", decode_output);
    free(encode_output);
    free(decode_output);
    return 0;
}