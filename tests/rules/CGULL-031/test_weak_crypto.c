#include <stdio.h>
#include <string.h>

#define MD5(x, y, z) do_nothing()
#define DES_ecb_encrypt(a, b, c, d) do_nothing()

// Function prototypes/declarations should NOT trigger findings
unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md);
int MD5_Init(void *c);
unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);
void DES_ecb_encrypt(const void *input, void *output, void *ks, int enc);
void RC4(void *key, size_t len, const unsigned char *indata, unsigned char *outdata);
void *EVP_aes_128_ecb(void);
int EVP_EncryptInit_ex(void *ctx, const void *type, void *impl, const unsigned char *key, const unsigned char *iv);
int EVP_DigestInit_ex(void *ctx, const void *type, void *impl);
void *EVP_md5(void);
void *EVP_sha1(void);

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
    EVP_DigestInit_ex(NULL, EVP_sha1(), NULL); // expect: CGULL-031
}

void test_evp_md5_vulnerable(void *ctx) {
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL); // expect: CGULL-031
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
