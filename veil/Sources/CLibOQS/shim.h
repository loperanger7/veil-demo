// CLibOQS shim header — bridges liboqs C API into Swift
// When building for iOS simulator (where system liboqs is unavailable),
// this header provides the type definitions and function declarations
// with stub implementations in oqs_stubs.c.
#ifndef CLIBOQS_SHIM_H
#define CLIBOQS_SHIM_H

#if __has_include(<oqs/oqs.h>)
// Real liboqs available (macOS command-line builds)
#include <oqs/oqs.h>
#else
// Stub definitions for iOS simulator builds
#include <stddef.h>
#include <stdint.h>

#define OQS_SUCCESS 0
#define OQS_ERROR -1

// Algorithm name constants
#define OQS_KEM_alg_ml_kem_1024 "ML-KEM-1024"
#define OQS_SIG_alg_ml_dsa_65 "ML-DSA-65"

// KEM structure
typedef struct OQS_KEM {
    size_t length_public_key;
    size_t length_secret_key;
    size_t length_ciphertext;
    size_t length_shared_secret;
} OQS_KEM;

// SIG structure
typedef struct OQS_SIG {
    size_t length_public_key;
    size_t length_secret_key;
    size_t length_signature;
} OQS_SIG;

// KEM functions
OQS_KEM *OQS_KEM_new(const char *method_name);
void OQS_KEM_free(OQS_KEM *kem);
int OQS_KEM_keypair(const OQS_KEM *kem, uint8_t *public_key, uint8_t *secret_key);
int OQS_KEM_encaps(const OQS_KEM *kem, uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
int OQS_KEM_decaps(const OQS_KEM *kem, uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);

// SIG functions
OQS_SIG *OQS_SIG_new(const char *method_name);
void OQS_SIG_free(OQS_SIG *sig);
int OQS_SIG_keypair(const OQS_SIG *sig, uint8_t *public_key, uint8_t *secret_key);
int OQS_SIG_sign(const OQS_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
int OQS_SIG_verify(const OQS_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

#endif // __has_include(<oqs/oqs.h>)
#endif /* CLIBOQS_SHIM_H */
