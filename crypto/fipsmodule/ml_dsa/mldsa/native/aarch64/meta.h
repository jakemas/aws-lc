/*
 * Copyright (c) The mlkem-native project authors
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

#ifndef MLD_NATIVE_AARCH64_META_H
#define MLD_NATIVE_AARCH64_META_H

/* Set of primitives that this backend replaces */
#define MLD_USE_NATIVE_POLY_DECOMPOSE_32
#define MLD_USE_NATIVE_POLY_DECOMPOSE_88
#define MLD_USE_NATIVE_POLY_CADDQ
#define MLD_USE_NATIVE_POLY_USE_HINT_32
#define MLD_USE_NATIVE_POLY_USE_HINT_88
#define MLD_USE_NATIVE_POLY_CHKNORM
#define MLD_USE_NATIVE_POINTWISE_MONTGOMERY
#define MLD_USE_NATIVE_POLYVECL_POINTWISE_ACC_MONTGOMERY_L4
#define MLD_USE_NATIVE_POLYVECL_POINTWISE_ACC_MONTGOMERY_L5
#define MLD_USE_NATIVE_POLYVECL_POINTWISE_ACC_MONTGOMERY_L7

/* Identifier for this backend so that source and assembly files
 * in the build can be appropriately guarded. */
#define MLD_ARITH_BACKEND_AARCH64
#if !defined(__ASSEMBLER__)
#include "../api.h"
#include "src/arith_native_aarch64.h"
#if !defined(MLD_CONFIG_NO_SIGN_API)
#if defined(MLD_CONFIG_MULTILEVEL_WITH_SHARED) || \
    (MLD_CONFIG_PARAMETER_SET == 65 || MLD_CONFIG_PARAMETER_SET == 87)
MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE int mld_poly_decompose_32_native(int32_t *a1, int32_t *a0)
{
  mld_poly_decompose_32_asm(a1, a0);
  return MLD_NATIVE_FUNC_SUCCESS;
}
#endif /* MLD_CONFIG_MULTILEVEL_WITH_SHARED || MLD_CONFIG_PARAMETER_SET == 65 \
          || MLD_CONFIG_PARAMETER_SET == 87 */

#if defined(MLD_CONFIG_MULTILEVEL_WITH_SHARED) || MLD_CONFIG_PARAMETER_SET == 44
MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE int mld_poly_decompose_88_native(int32_t *a1, int32_t *a0)
{
  mld_poly_decompose_88_asm(a1, a0);
  return MLD_NATIVE_FUNC_SUCCESS;
}
#endif /* MLD_CONFIG_MULTILEVEL_WITH_SHARED || MLD_CONFIG_PARAMETER_SET == 44 \
        */
#endif /* !MLD_CONFIG_NO_SIGN_API */

MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE int mld_poly_caddq_native(int32_t a[MLDSA_N])
{
  mld_poly_caddq_asm(a);
  return MLD_NATIVE_FUNC_SUCCESS;
}

#if !defined(MLD_CONFIG_NO_VERIFY_API)
#if defined(MLD_CONFIG_MULTILEVEL_WITH_SHARED) || \
    (MLD_CONFIG_PARAMETER_SET == 65 || MLD_CONFIG_PARAMETER_SET == 87)
MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE int mld_poly_use_hint_32_native(int32_t *a, const int32_t *h)
{
  mld_poly_use_hint_32_asm(a, h);
  return MLD_NATIVE_FUNC_SUCCESS;
}
#endif /* MLD_CONFIG_MULTILEVEL_WITH_SHARED || MLD_CONFIG_PARAMETER_SET == 65 \
          || MLD_CONFIG_PARAMETER_SET == 87 */

#if defined(MLD_CONFIG_MULTILEVEL_WITH_SHARED) || MLD_CONFIG_PARAMETER_SET == 44
MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE int mld_poly_use_hint_88_native(int32_t *a, const int32_t *h)
{
  mld_poly_use_hint_88_asm(a, h);
  return MLD_NATIVE_FUNC_SUCCESS;
}
#endif /* MLD_CONFIG_MULTILEVEL_WITH_SHARED || MLD_CONFIG_PARAMETER_SET == 44 \
        */
#endif /* !MLD_CONFIG_NO_VERIFY_API */

MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE int mld_poly_chknorm_native(const int32_t *a, int32_t B)
{
  return mld_poly_chknorm_asm(a, B);
}
#if !defined(MLD_CONFIG_NO_SIGN_API) || !defined(MLD_CONFIG_NO_VERIFY_API) || \
    defined(MLD_CONFIG_REDUCE_RAM) || defined(MLD_UNIT_TEST)
MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE int mld_poly_pointwise_montgomery_native(
    int32_t a[MLDSA_N], const int32_t b[MLDSA_N])
{
  mld_poly_pointwise_montgomery_asm(a, b);
  return MLD_NATIVE_FUNC_SUCCESS;
}
#endif /* !MLD_CONFIG_NO_SIGN_API || !MLD_CONFIG_NO_VERIFY_API || \
          MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST */

#if defined(MLD_CONFIG_MULTILEVEL_WITH_SHARED) || MLDSA_L == 4
MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE int mld_polyvecl_pointwise_acc_montgomery_l4_native(
    int32_t w[MLDSA_N], const int32_t u[4][MLDSA_N],
    const int32_t v[4][MLDSA_N])
{
  mld_polyvecl_pointwise_acc_montgomery_l4_asm(w, u, v);
  return MLD_NATIVE_FUNC_SUCCESS;
}
#endif /* MLD_CONFIG_MULTILEVEL_WITH_SHARED || MLDSA_L == 4 */

#if defined(MLD_CONFIG_MULTILEVEL_WITH_SHARED) || MLDSA_L == 5
MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE int mld_polyvecl_pointwise_acc_montgomery_l5_native(
    int32_t w[MLDSA_N], const int32_t u[5][MLDSA_N],
    const int32_t v[5][MLDSA_N])
{
  mld_polyvecl_pointwise_acc_montgomery_l5_asm(w, u, v);
  return MLD_NATIVE_FUNC_SUCCESS;
}
#endif /* MLD_CONFIG_MULTILEVEL_WITH_SHARED || MLDSA_L == 5 */

#if defined(MLD_CONFIG_MULTILEVEL_WITH_SHARED) || MLDSA_L == 7
MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE int mld_polyvecl_pointwise_acc_montgomery_l7_native(
    int32_t w[MLDSA_N], const int32_t u[7][MLDSA_N],
    const int32_t v[7][MLDSA_N])
{
  mld_polyvecl_pointwise_acc_montgomery_l7_asm(w, u, v);
  return MLD_NATIVE_FUNC_SUCCESS;
}
#endif /* MLD_CONFIG_MULTILEVEL_WITH_SHARED || MLDSA_L == 7 */

#endif /* !__ASSEMBLER__ */
#endif /* !MLD_NATIVE_AARCH64_META_H */
