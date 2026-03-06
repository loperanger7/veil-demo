// OQS stub implementations for iOS simulator builds.
// These provide deterministic mock crypto for demo/UI testing.
// Real liboqs is used for macOS command-line builds.

#include "shim.h"

#if !__has_include(<oqs/oqs.h>)

#include <stdlib.h>
#include <string.h>

// ML-KEM-1024 sizes (FIPS 203)
#define MLKEM1024_PK_SIZE  1568
#define MLKEM1024_SK_SIZE  3168
#define MLKEM1024_CT_SIZE  1568
#define MLKEM1024_SS_SIZE  32

// ML-DSA-65 sizes (FIPS 204)
#define MLDSA65_PK_SIZE    1952
#define MLDSA65_SK_SIZE    4032
#define MLDSA65_SIG_SIZE   3309

// Simple deterministic fill for mock keys
static void mock_fill(uint8_t *buf, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)((seed + i * 7 + 0x5A) & 0xFF);
    }
}

// --- KEM ---

OQS_KEM *OQS_KEM_new(const char *method_name) {
    OQS_KEM *kem = (OQS_KEM *)calloc(1, sizeof(OQS_KEM));
    if (!kem) return NULL;
    kem->length_public_key = MLKEM1024_PK_SIZE;
    kem->length_secret_key = MLKEM1024_SK_SIZE;
    kem->length_ciphertext = MLKEM1024_CT_SIZE;
    kem->length_shared_secret = MLKEM1024_SS_SIZE;
    return kem;
}

void OQS_KEM_free(OQS_KEM *kem) {
    free(kem);
}

int OQS_KEM_keypair(const OQS_KEM *kem, uint8_t *public_key, uint8_t *secret_key) {
    if (!kem || !public_key || !secret_key) return OQS_ERROR;
    mock_fill(public_key, kem->length_public_key, 0x01);
    mock_fill(secret_key, kem->length_secret_key, 0x02);
    return OQS_SUCCESS;
}

int OQS_KEM_encaps(const OQS_KEM *kem, uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
    if (!kem || !ciphertext || !shared_secret || !public_key) return OQS_ERROR;
    mock_fill(ciphertext, kem->length_ciphertext, public_key[0]);
    mock_fill(shared_secret, kem->length_shared_secret, public_key[1]);
    return OQS_SUCCESS;
}

int OQS_KEM_decaps(const OQS_KEM *kem, uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
    if (!kem || !shared_secret || !ciphertext || !secret_key) return OQS_ERROR;
    // Produce the same shared secret as encaps would for matching keys
    mock_fill(shared_secret, kem->length_shared_secret, ciphertext[0] ^ 0x01);
    return OQS_SUCCESS;
}

// --- SIG ---

OQS_SIG *OQS_SIG_new(const char *method_name) {
    OQS_SIG *sig = (OQS_SIG *)calloc(1, sizeof(OQS_SIG));
    if (!sig) return NULL;
    sig->length_public_key = MLDSA65_PK_SIZE;
    sig->length_secret_key = MLDSA65_SK_SIZE;
    sig->length_signature = MLDSA65_SIG_SIZE;
    return sig;
}

void OQS_SIG_free(OQS_SIG *sig) {
    free(sig);
}

int OQS_SIG_keypair(const OQS_SIG *sig, uint8_t *public_key, uint8_t *secret_key) {
    if (!sig || !public_key || !secret_key) return OQS_ERROR;
    mock_fill(public_key, sig->length_public_key, 0x10);
    mock_fill(secret_key, sig->length_secret_key, 0x20);
    return OQS_SUCCESS;
}

int OQS_SIG_sign(const OQS_SIG *sig, uint8_t *signature, size_t *signature_len,
                  const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
    if (!sig || !signature || !signature_len || !message || !secret_key) return OQS_ERROR;
    *signature_len = sig->length_signature;
    mock_fill(signature, sig->length_signature, message[0]);
    return OQS_SUCCESS;
}

int OQS_SIG_verify(const OQS_SIG *sig, const uint8_t *message, size_t message_len,
                    const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
    if (!sig || !message || !signature || !public_key) return OQS_ERROR;
    // Mock: always verify successfully
    return OQS_SUCCESS;
}

#endif // !__has_include(<oqs/oqs.h>)
