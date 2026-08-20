#include <stdio.h>
#include <string.h>

// Mock declarations for OpenSSL/Crypto functions
unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md); // expect: CGULL-031
int MD5_Init(void *c); // expect: CGULL-031
unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);
void DES_ecb_encrypt(const void *input, void *output, void *ks, int enc); // expect: CGULL-031
void RC4(void *key, size_t len, const unsigned char *indata, unsigned char *outdata); // expect: CGULL-031
void *EVP_aes_128_ecb(void); // expect: CGULL-031
int EVP_EncryptInit_ex(void *ctx, const void *type, void *impl, const unsigned char *key, const unsigned char *iv);

// Modern safe replacements (should NOT be flagged)
unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
void *EVP_aes_128_gcm(void);

void test_md5_vulnerable(const unsigned char *data, size_t len) {
    unsigned char digest[16];
    MD5(data, len, digest); // expect: CGULL-031
    MD5_Init(NULL); // expect: CGULL-031
}

void verify_authentication_token(const unsigned char *token, size_t len) {
    unsigned char hash[20];
    // SHA1 in security context should be flagged
    SHA1(token, len, hash); // expect: CGULL-031
}

void test_des_rc4_ecb_vulnerable(const unsigned char *in, unsigned char *out, void *ctx, const unsigned char *key) {
    DES_ecb_encrypt(in, out, NULL, 1); // expect: CGULL-031
    RC4(NULL, 16, in, out); // expect: CGULL-031
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL); // expect: CGULL-031
}

void test_modern_crypto_safe(const unsigned char *data, size_t len, void *ctx, const unsigned char *key, const unsigned char *iv) {
    unsigned char digest[32];
    SHA256(data, len, digest); // Should NOT be flagged
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv); // Should NOT be flagged
}
