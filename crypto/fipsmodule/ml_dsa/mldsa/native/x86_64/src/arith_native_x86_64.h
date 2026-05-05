/*
 * Copyright (c) The mlkem-native project authors
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#ifndef MLD_NATIVE_X86_64_SRC_ARITH_NATIVE_X86_64_H
#define MLD_NATIVE_X86_64_SRC_ARITH_NATIVE_X86_64_H
#include "../../../common.h"

#include "consts.h"

#define mld_ntt_avx2 MLD_NAMESPACE(ntt_avx2)
void mld_ntt_avx2(int32_t *r, const int32_t *qdata);

#define mld_invntt_avx2 MLD_NAMESPACE(invntt_avx2)
void mld_invntt_avx2(int32_t *r, const int32_t *qdata)
/* This must be kept in sync with the HOL-Light specification
 * in proofs/hol_light/x86_64/proofs/mldsa_intt.ml */
__contract__(
  requires(memory_no_alias(r, sizeof(int32_t) * MLDSA_N))
  requires(array_abs_bound(r, 0, MLDSA_N, 8380417))
  requires(qdata == mld_qdata)
  assigns(memory_slice(r, sizeof(int32_t) * MLDSA_N))
  /* check-magic: off */
  ensures(array_abs_bound(r, 0, MLDSA_N, 6285313))
  /* check-magic: on */
);

#define mld_nttunpack_avx2 MLD_NAMESPACE(nttunpack_avx2)
/* This must be kept in sync with the HOL-Light specification
 * in proofs/hol_light/x86_64/proofs/mldsa_nttunpack.ml */
void mld_nttunpack_avx2(int32_t *r)
__contract__(
  requires(memory_no_alias(r, sizeof(int32_t) * MLDSA_N))
  requires(array_abs_bound(r, 0, MLDSA_N, 8380417))
  assigns(memory_slice(r, sizeof(int32_t) * MLDSA_N))
  /* Output is a permutation of input: every output coefficient
   * is some input coefficient */
  ensures(forall(i, 0, MLDSA_N, exists(j, 0, MLDSA_N,
    r[i] == old(*(int32_t (*)[MLDSA_N])r)[j])))
);

#define mld_pointwise_avx2 MLD_NAMESPACE(pointwise_avx2)
void mld_pointwise_avx2(int32_t *a, const int32_t *b, const int32_t *qdata)
/* This must be kept in sync with the HOL-Light specification
 * in proofs/hol_light/x86_64/proofs/mldsa_pointwise.ml */
__contract__(
  requires(memory_no_alias(a, sizeof(int32_t) * MLDSA_N))
  requires(memory_no_alias(b, sizeof(int32_t) * MLDSA_N))
  /* check-magic: off */
  requires(array_abs_bound(a, 0, MLDSA_N, 75423753))
  requires(array_abs_bound(b, 0, MLDSA_N, 75423753))
  requires(qdata == mld_qdata)
  assigns(memory_slice(a, sizeof(int32_t) * MLDSA_N))
  ensures(array_abs_bound(a, 0, MLDSA_N, 8380417))
  /* check-magic: on */
);

#define mld_pointwise_acc_l4_avx2 MLD_NAMESPACE(pointwise_acc_l4_avx2)
void mld_pointwise_acc_l4_avx2(int32_t c[MLDSA_N], const int32_t a[4][MLDSA_N],
                               const int32_t b[4][MLDSA_N],
                               const int32_t *qdata)
/* This must be kept in sync with the HOL-Light specification
 * in proofs/hol_light/x86_64/proofs/mldsa_pointwise_acc_l4.ml */
__contract__(
  requires(memory_no_alias(c, sizeof(int32_t) * MLDSA_N))
  requires(memory_no_alias(a, sizeof(int32_t) * 4 * MLDSA_N))
  requires(memory_no_alias(b, sizeof(int32_t) * 4 * MLDSA_N))
  /* check-magic: off */
  requires(forall(l0, 0, 4, array_abs_bound(a[l0], 0, MLDSA_N, 8380417)))
  requires(forall(l1, 0, 4, array_abs_bound(b[l1], 0, MLDSA_N, 75423753)))
  requires(qdata == mld_qdata)
  assigns(memory_slice(c, sizeof(int32_t) * MLDSA_N))
  ensures(array_abs_bound(c, 0, MLDSA_N, 8380417))
  /* check-magic: on */
);

#define mld_pointwise_acc_l5_avx2 MLD_NAMESPACE(pointwise_acc_l5_avx2)
void mld_pointwise_acc_l5_avx2(int32_t c[MLDSA_N], const int32_t a[5][MLDSA_N],
                               const int32_t b[5][MLDSA_N],
                               const int32_t *qdata)
/* This must be kept in sync with the HOL-Light specification
 * in proofs/hol_light/x86_64/proofs/mldsa_pointwise_acc_l5.ml */
__contract__(
  requires(memory_no_alias(c, sizeof(int32_t) * MLDSA_N))
  requires(memory_no_alias(a, sizeof(int32_t) * 5 * MLDSA_N))
  requires(memory_no_alias(b, sizeof(int32_t) * 5 * MLDSA_N))
  /* check-magic: off */
  requires(forall(l0, 0, 5, array_abs_bound(a[l0], 0, MLDSA_N, 8380417)))
  requires(forall(l1, 0, 5, array_abs_bound(b[l1], 0, MLDSA_N, 75423753)))
  requires(qdata == mld_qdata)
  assigns(memory_slice(c, sizeof(int32_t) * MLDSA_N))
  ensures(array_abs_bound(c, 0, MLDSA_N, 8380417))
  /* check-magic: on */
);

#define mld_pointwise_acc_l7_avx2 MLD_NAMESPACE(pointwise_acc_l7_avx2)
void mld_pointwise_acc_l7_avx2(int32_t c[MLDSA_N], const int32_t a[7][MLDSA_N],
                               const int32_t b[7][MLDSA_N],
                               const int32_t *qdata)
/* This must be kept in sync with the HOL-Light specification
 * in proofs/hol_light/x86_64/proofs/mldsa_pointwise_acc_l7.ml */
__contract__(
  requires(memory_no_alias(c, sizeof(int32_t) * MLDSA_N))
  requires(memory_no_alias(a, sizeof(int32_t) * 7 * MLDSA_N))
  requires(memory_no_alias(b, sizeof(int32_t) * 7 * MLDSA_N))
  /* check-magic: off */
  requires(forall(l0, 0, 7, array_abs_bound(a[l0], 0, MLDSA_N, 8380417)))
  requires(forall(l1, 0, 7, array_abs_bound(b[l1], 0, MLDSA_N, 75423753)))
  requires(qdata == mld_qdata)
  assigns(memory_slice(c, sizeof(int32_t) * MLDSA_N))
  ensures(array_abs_bound(c, 0, MLDSA_N, 8380417))
  /* check-magic: on */
);

#endif /* !MLD_NATIVE_X86_64_SRC_ARITH_NATIVE_X86_64_H */
