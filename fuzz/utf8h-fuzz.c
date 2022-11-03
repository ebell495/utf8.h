#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../utf8.h"

uint8_t tmpBuffer[8196];

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size > 0) {
        uint8_t* in_data = (uint8_t*) malloc(Size - 1);
        memcpy(in_data, Data + 1, Size - 1);
        if (Data[0] % 5 == 0) {
            utf8cat(tmpBuffer, in_data);
        } else if (Data[0] % 5 == 1) {
            utf8cpy(tmpBuffer, in_data);
        } else if (Data[0] % 5 == 2) {
            utf8len(in_data);
        } else if (Data[0] % 5 == 3) {
            utf8size(in_data);
        } else {
            utf8valid(in_data);
        }
        free(in_data);
    }
    return 0;
}