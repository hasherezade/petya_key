#include "base58.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

static const int8_t b58_ascii_to_val[] = {
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
	-1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
	22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
	-1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
	47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};

const uint8_t BASE = 58;

size_t decode_base58(const char *str, size_t str_size, uint8_t *out_buf, size_t out_buf_size)
{
	if (out_buf == NULL || str == NULL) {
		return 0;
	}
	BIGNUM *output = BN_new();
	BIGNUM *base = BN_new();
	BIGNUM *op = BN_new();

	BN_CTX *ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	
	BN_bin2bn(&BASE, 1, base);

	for (size_t i = 0; i < str_size; i++) {
		uint8_t c = str[i];
		c = b58_ascii_to_val[c];
		if (c == -1) {
			break; //invalid character		
		}
		BN_bin2bn(&c, 1, op);
		BN_mul(output, output, base, ctx);
		BN_add(output, output, op);
	}
	size_t res = BN_bn2bin(output, out_buf);
	//cleanup
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	BN_clear_free(output);
	BN_clear_free(base);
	BN_clear_free(op);
	return res;
}

