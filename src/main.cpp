#include <stdio.h>
#include <string.h>

#include "ec.h"
#include "common.h"

//the private key published by Janus:
uint8_t priv_bytes[] = {
	0x38, 0xdd, 0x46, 0x80, 0x1c, 0xe6, 0x18, 0x83, 0x43, 0x30, 0x48, 0xd6, 0xd8, 0xc6, 0xab,
	0x8b, 0xe1, 0x86, 0x54, 0xa2, 0x69, 0x5b, 0x47, 0x23
};

//the public key dumped from Petya:
uint8_t pub_dumped_bytes[] = {
	0x04, 0xc4, 0x80, 0xaf, 0x98, 0x2b, 0x11, 0x26, 0x9c, 0xb4, 0x38, 0xa0, 0x1c, 0x46, 0x79,
	0xa8, 0x32, 0x9b, 0x5a, 0x5f, 0x4e, 0x80, 0x0c, 0x86, 0x9e, 0xa3, 0xd5, 0x26, 0x77, 0xf3,
	0x26, 0x1e, 0xc8, 0x8d, 0xd1, 0x71, 0xec, 0xa5, 0xa9, 0x06, 0x6f, 0x4d, 0x8f, 0x26, 0xdc,
	0xa6, 0x48, 0xfe, 0xf9
};

int main()
{    
    uint8_t priv[PRIV_KEY_SIZE];
    //create a keypair basing on the private key:
    EC_KEY *key = bbp_ec_new_keypair(priv_bytes);
    if (!key) {
        puts("Unable to create keypair");
        return -1;
    }

    const BIGNUM *priv_bn = EC_KEY_get0_private_key(key);
    if (!priv_bn) {
        puts("Unable to decode private key");
        return -1;
    }
    BN_bn2bin(priv_bn, priv);
    bbp_print_hex("priv:        ", priv, sizeof(priv));

    //public key:
    size_t pub_len = i2o_ECPublicKey(key, NULL);
    uint8_t *pub = (uint8_t*)calloc(pub_len, sizeof(uint8_t));

    //fetch the public key in uncompressed form:
    EC_KEY_set_conv_form(key, POINT_CONVERSION_UNCOMPRESSED);

    // pub_copy is needed because i2o_ECPublicKey alters the input pointer   
    uint8_t *pub_copy = pub;
    if (i2o_ECPublicKey(key, &pub_copy) != pub_len) {
        puts("Unable to decode public key");
        return -1;
    }

    bbp_print_hex("derived pub  ", pub, pub_len);
    bbp_print_hex("dumped pub   ", pub_dumped_bytes, sizeof(pub_dumped_bytes));

    int res = memcmp(pub, pub_dumped_bytes, sizeof(pub_dumped_bytes));
    if (res == 0) {
        printf("[+] Test passed!\n[+] The public key dumped from the malware was derived from the published private key!\n");
    } else {
        printf("[-] Test failed!\n");
    }
    free(pub);

    /* release keypair */
    EC_KEY_free(key);

    return res;
}

