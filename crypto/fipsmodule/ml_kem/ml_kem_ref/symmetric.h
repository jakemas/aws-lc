#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

// below we comment out all the old calls to the fips202.h and kyber implementations of sha3/shake
// so that the ML-KEM implementation is completely independent of the old fips202.c file.

//#include "../../../kyber/pqcrystals_kyber_ref_common/fips202.h"

//typedef keccak_state xof_state;

//#define kyber_shake128_absorb KYBER_NAMESPACE(kyber_shake128_absorb)
//void kyber_shake128_absorb(keccak_state *s,
//                           const uint8_t seed[KYBER_SYMBYTES],
//                           uint8_t x,
//                           uint8_t y);

//#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
//#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
//#define xof_absorb(STATE, SEED, X, Y) kyber_shake128_absorb(STATE, SEED, X, Y)
//#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)

#define kyber_shake128_absorb KYBER_NAMESPACE(kyber_shake128_absorb)
void kyber_shake128_absorb(KECCAK1600_CTX *ctx,
                           const uint8_t seed[KYBER_SYMBYTES],
                           uint8_t x,
                           uint8_t y);

#define kyber_shake256_prf KYBER_NAMESPACE(kyber_shake256_prf)
void kyber_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

#define kyber_shake256_rkprf KYBER_NAMESPACE(kyber_shake256_rkprf)
void kyber_shake256_rkprf(ml_kem_params *params, uint8_t out[KYBER_SSBYTES], const uint8_t key[KYBER_SYMBYTES], const uint8_t *input);

void shake128_squeezeblocks(uint8_t *out, size_t nblocks, KECCAK1600_CTX *ctx);

#define XOF_BLOCKBYTES SHAKE128_RATE

#define hash_h(OUT, IN, INBYTES) SHA3_256(IN, INBYTES, OUT)
#define hash_g(OUT, IN, INBYTES) SHA3_512(IN, INBYTES, OUT)
#define xof_absorb(STATE, SEED, X, Y) kyber_shake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
// the above line could be replaced with
//#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) ossl_sha3_squeeze(ctx, out, nblocks * SHAKE128_RATE);
#define prf(OUT, OUTBYTES, KEY, NONCE) kyber_shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(PARAMS, OUT, KEY, INPUT) kyber_shake256_rkprf(PARAMS, OUT, KEY, INPUT)

#endif /* SYMMETRIC_H */
