/***
* Petya key decoder
* CC-BY: hasherezade
**/

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <openssl/evp.h>
#include <openssl/ecdh.h>
#include <openssl/sha.h>

#include "ec.h"
#include "common.h"
#include "aes256.h"
#include "base58.h"

#define PUBLIC_KEY_LEN 49
#define AES_CHUNK_LEN 16
#define AES_KEY_LEN 32

typedef enum Petyas { PETYA_RED = 0, PETYA_GREEN = 1, PETYA_GOLDEN = 2, PETYA_UNK = -1} Petya_t;

//the private key published by Janus:
uint8_t priv_bytes[] = {
    0x38, 0xdd, 0x46, 0x80, 0x1c, 0xe6, 0x18, 0x83, 0x43, 0x30, 0x48, 0xd6, 0xd8, 0xc6, 0xab,
    0x8b, 0xe1, 0x86, 0x54, 0xa2, 0x69, 0x5b, 0x47, 0x23
};

bool test_janus_privkey(EC_KEY *key)
{
    //the public key dumped from Petya:
    const uint8_t pub_dumped_bytes[] = {
        0x04, 0xc4, 0x80, 0xaf, 0x98, 0x2b, 0x11, 0x26, 0x9c, 0xb4, 0x38, 0xa0, 0x1c, 0x46, 0x79,
        0xa8, 0x32, 0x9b, 0x5a, 0x5f, 0x4e, 0x80, 0x0c, 0x86, 0x9e, 0xa3, 0xd5, 0x26, 0x77, 0xf3,
        0x26, 0x1e, 0xc8, 0x8d, 0xd1, 0x71, 0xec, 0xa5, 0xa9, 0x06, 0x6f, 0x4d, 0x8f, 0x26, 0xdc,
        0xa6, 0x48, 0xfe, 0xf9
    };
    //public key:
    size_t pub_len = i2o_ECPublicKey(key, NULL);
    uint8_t *pub = (uint8_t*)calloc(pub_len, sizeof(uint8_t));

    // fetch the public key in uncompressed form:
    EC_KEY_set_conv_form(key, POINT_CONVERSION_UNCOMPRESSED);

    // pub_copy is needed because i2o_ECPublicKey alters the input pointer   
    uint8_t *pub_copy = pub;
    if (i2o_ECPublicKey(key, &pub_copy) != pub_len) {
        puts("Unable to decode public key");
        return -1;
    }

    bbp_print_hex("derived pub  ", pub, pub_len);
    bbp_print_hex("dumped pub   ", pub_dumped_bytes, sizeof(pub_dumped_bytes));
    bool is_ok = false;
    int res = memcmp(pub, pub_dumped_bytes, sizeof(pub_dumped_bytes));
    if (res == 0) {
        is_ok = true;
        printf("[+] Test passed!\n[+] The public key dumped from the malware was derived from the published private key!\n");
    } else {
        printf("[-] Test failed!\n");
    }
    free(pub);
    return is_ok;
}


void aes_decrypt_chunk(uint8_t enc_buf[AES_CHUNK_LEN], uint8_t *key)
{
    aes256_context ctx;
    memset(&ctx, 0, sizeof(ctx));

    aes256_init(&ctx, key);
    aes256_decrypt_ecb(&ctx, enc_buf);
    aes256_done(&ctx);
}

void xor_buffer(uint8_t *buffer, size_t buffer_size, uint8_t *key, size_t key_size)
{
    for (size_t i = 0; i < buffer_size && i < key_size; i++) {
        buffer[i] ^= key[i];
    }
}

size_t truncated_size(const char *str)
{
    size_t len = strlen(str);
    size_t out_size = len;
    for (size_t i = len - 1; i >= 0; i--) {
        if (isalnum(str[i])) break;
        out_size--;
    }
    return out_size;
}

bool load_victim_data(const char* victim_file, uint8_t victim_pub_key[PUBLIC_KEY_LEN], uint8_t enc_buf[AES_CHUNK_LEN], Petya_t &my_petya)
{
    FILE *fp = fopen(victim_file, "rb");
    if (!fp) {
        printf("Cannot open victim's file: %s\n", victim_file);
        return false;
    }
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
#ifdef DEBUG
    printf("---\n");
    printf("file_size: %d = %#x\n", file_size, file_size);
#endif
    fseek(fp, 0, SEEK_SET);

    const size_t max_line = 0x100;
    char line[max_line] = { 0 };
    fgets(line, max_line, fp);
    fclose(fp);

    char* b58_str = line;
    if (my_petya == PETYA_RED || my_petya == PETYA_GREEN) {
        b58_str += 2; //ommit the first two characters
    }
    size_t b58_len = truncated_size(b58_str);
    if (my_petya == PETYA_GREEN) {
       b58_len -= 6; //ommit 6 last characters
    }

    const size_t max_decoded = 0x100;
    uint8_t decoded[max_decoded] = { 0 };

    size_t out_len = decode_base58(b58_str, b58_len, decoded, max_decoded);
#ifdef DEBUG
    bbp_print_hex("converted  ", decoded, out_len);
    printf("---\n");
#endif
    if (out_len < PUBLIC_KEY_LEN + AES_CHUNK_LEN) {
        printf("Decoded content is too short!\n");
        return false;
    }

    memcpy(victim_pub_key, decoded, PUBLIC_KEY_LEN);
    memcpy(enc_buf, decoded + PUBLIC_KEY_LEN, AES_CHUNK_LEN);
    return true;
}

void sha512(uint8_t *in_buffer, size_t in_buffer_len, uint8_t out_hash[SHA512_DIGEST_LENGTH])
{
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, in_buffer, in_buffer_len);
    SHA512_Final(out_hash, &sha512);
}


const EC_KEY* load_session_key(uint8_t session_pub[PUBLIC_KEY_LEN])
{
// load victim's public key:
#ifdef DEBUG
    bbp_print_hex("victim pub:  ", session_pub, PUBLIC_KEY_LEN);
#endif
    // init empty OpenSSL EC keypair
    EC_KEY *session_key = EC_KEY_new_by_curve_name(NID_secp192k1);
    if (!session_key) {
        puts("Unable to create session keypair");
        return NULL;
    }

    // set the public key in uncompressed form:
    EC_KEY_set_conv_form(session_key, POINT_CONVERSION_UNCOMPRESSED);

    const unsigned char* victim_pub_key = session_pub;
    EC_KEY *pkey = o2i_ECPublicKey(&session_key, &victim_pub_key, PUBLIC_KEY_LEN);

    //TEST:
    //try to fetch it back:
    uint8_t *pub = (uint8_t*)calloc(PUBLIC_KEY_LEN, sizeof(uint8_t));

    // pub_copy is needed because i2o_ECPublicKey alters the input pointer   
    uint8_t *pub_copy = pub;
    if (i2o_ECPublicKey(session_key, &pub_copy) != PUBLIC_KEY_LEN) {
        puts("Unable to decode public key");
        return NULL;
    }
    return session_key;
}

size_t get_expanded_size(uint8_t *secret, size_t secret_len)
{
    uint32_t first_dword = 0;
    memcpy(&first_dword, secret, sizeof(uint32_t));
    first_dword = bbp_swap32(first_dword);

    uint32_t counter = 0x20;
    uint32_t curr = 0;
    size_t dif = 0;
    do {
        curr = first_dword;
        curr >>= (counter - 1);
        if (curr & 1) {
            break;
        }
        counter--;
        dif++;
    } while (counter);

    return (secret_len * 8) - dif;
}

uint8_t *expand_secret(uint8_t* secret, size_t out_secret_len)
{
    const size_t secret_data_size = get_expanded_size(secret, out_secret_len);
    uint8_t *secret_data = (uint8_t *)OPENSSL_malloc(secret_data_size);
    memset(secret_data, 0, secret_data_size);
#ifdef DEBUG
    printf("secret size: %d\n", secret_data_size);
#endif
    size_t secret_offset = secret_data_size - out_secret_len;

    memcpy(secret_data + secret_offset, secret, out_secret_len);
#ifdef DEBUG
    bbp_print_hex("secret buffer:        ", secret_data, secret_data_size);
#endif
    return secret_data;
}

bool derive_secret_hash(const EC_POINT *pub_key, EC_KEY *key, uint8_t out_buffer[SHA512_DIGEST_LENGTH])
{
    // allocate the memory for the shared secret
    const size_t secret_len = 0x40;
    uint8_t *secret = (uint8_t *)OPENSSL_malloc(secret_len);
    memset(secret, 0, secret_len);
    if (!secret) {
        printf("Failed to allocate memory for the secret!\n");
        return false;
    }

    // derive the shared secret:
    size_t out_secret_len = ECDH_compute_key(secret, secret_len, pub_key, key, NULL);
#ifdef DEBUG
    printf("Got secret len: %d = %#x\n", out_secret_len, out_secret_len);
    bbp_print_hex("secret:        ", secret, out_secret_len);
#endif
    // expand the secret:
    uint8_t *to_hash = expand_secret(secret, out_secret_len);
    size_t to_hash_size = get_expanded_size(secret, out_secret_len);
    
    sha512(to_hash, to_hash_size, out_buffer);
#ifdef DEBUG
    bbp_print_hex("SHA512:        ", out_buffer, SHA512_DIGEST_LENGTH);
    printf("---\n");
#endif
    OPENSSL_free(secret);
    OPENSSL_free(to_hash);
    return true;
}

Petya_t choose_variant()
{
    printf("Choose one of the supported variants:\nr - Red Petya\ng - Green Petya or Mischa\nd - Goldeneye\n");
    printf("[*] My petya is: ");
    char code = getchar();
    Petya_t type = PETYA_UNK;
    switch (code) {
       case 'r': type = PETYA_RED; break;
       case 'g': type = PETYA_GREEN; break;
       case 'd': type = PETYA_GOLDEN; break;
       default: type = PETYA_UNK; break;
    };
    return type;
}

int main(int argc, char* argv[])
{
    Petya_t my_petya = PETYA_UNK;
    bool make_test = (argc >= 2) ? false : true;

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

    if (make_test) {
        test_janus_privkey(key);
    }

    uint8_t session_pub[PUBLIC_KEY_LEN] = { 0 };
    uint8_t salsa_key[AES_CHUNK_LEN] = { 0 };
    
    char *victim_file = NULL;
    if (argc >= 2) {
        victim_file = argv[1];
        printf("Victim file: %s\n", victim_file);
    } else {
        printf("[-] Parameter missing! Supply a file containing the ID from the victim\n");
        return -1;
    }
    my_petya = choose_variant();
    if (my_petya == PETYA_UNK) {
       printf("Invalid param!\n");
       return -1;
    }
    if (!load_victim_data(victim_file, session_pub, salsa_key, my_petya)) {
        printf("Failed loading victim's data!\n");
        return -1;
    }

    const EC_KEY *session_key = load_session_key(session_pub);
    if (session_key == NULL) {
        printf("Cannot load victim's public key!\n");
        return -1;
    }
    const EC_POINT *pub_key = EC_KEY_get0_public_key(session_key);
    if (pub_key == NULL) {
        printf("Cannot fetch victim's public key!\n");
        return -1;
    }
//-----
#ifdef DEBUG
    bbp_print_hex("enc. Salsa:    ", salsa_key, AES_CHUNK_LEN);
#endif
    uint8_t sha512_buffer[SHA512_DIGEST_LENGTH] = {0};
    if (!derive_secret_hash(pub_key, key, sha512_buffer)) {
        printf("Cannot derive the secret!\n");
        return -1;
    }

    aes_decrypt_chunk(salsa_key, sha512_buffer);
#ifdef DEBUG
    bbp_print_hex("de-AES Salsa:  ", salsa_key, AES_CHUNK_LEN);
#endif
    printf("---\n");
    int res = -1;
    if (my_petya == PETYA_GOLDEN) {
        bbp_print_hex("[+] Your key   ", salsa_key, AES_CHUNK_LEN);
        res = 0; //success
    }
    else if (my_petya == PETYA_RED || my_petya == PETYA_GREEN) {
        xor_buffer(salsa_key, AES_CHUNK_LEN, session_pub, PUBLIC_KEY_LEN);
#ifdef DEBUG
        bbp_print_hex("de-XOR Salsa:  ", salsa_key, AES_CHUNK_LEN);
#endif
        printf("[+] Your key   : %.16s\n", salsa_key);
        res = 0; //success
    }
//-----
    //cleanup:
    // release keypair
    EC_KEY_free(key);
    return res;
}

