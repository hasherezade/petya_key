#pragma once

#include <stdio.h>

#ifdef _MSC_VER
    #include <stdint.h>
#else
    #include <inttypes.h>
#endif


size_t decode_base58(const char *str, size_t str_size, uint8_t *out_buf, size_t out_buf_size);
