#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR ISC

#
# mldsa-native -> AWS-LC importer script
#
# This script imports a version of mldsa-native into AWS-LC.
# It is meant to do all import work and leave AWS-LC in a fully
# working state.
#
# Usage:
#
# ```
# rm -rf ./mldsa # Remove any previous import
# ./importer.sh
# ```
#
# This imports github.com/pq-code-package/mldsa-native/main and
# and leaves commit hash and timestamp in META.yml.
#
# If you want to import a specific commit, and/or change the
# upstream repository (for example, to your fork of mldsa-native), use
#
# ```
# GITHUB_REPOSITORY={YOUR REPOSITORY} GITHUB_SHA={COMMIT_HASH} ./importer.sh [--force]
# ```
#

# Dependencies:
# - unifdef

GITHUB_SERVER_URL=https://github.com/
GITHUB_REPOSITORY=${GITHUB_REPOSITORY:=pq-code-package/mldsa-native.git}
GITHUB_SHA=${GITHUB_SHA:=main}

SRC=mldsa
TMP=$(mktemp -d) || exit 1
echo "Temporary working directory: $TMP"

# Check if necessary tools are installed
if !(which unifdef >/dev/null 2>&1); then
    echo "You need to install 'unifdef' to run the importer script."
    exit 1
fi

# Check if source directory already exists
if [ -d "$SRC" ]; then
    if [[ "$1" == "--force" ]]; then
        echo "Removing previous source directory $SRC as requested by --force"
        rm -rf $SRC
    else
        echo "Source directory $SRC does already exist -- please remove it before re-running the importer or pass --force to force removal"
        exit 1
    fi
fi

# Work in temporary directory
pushd $TMP

# Fetch repository
echo "Fetching repository ..."
git init >/dev/null
git remote add origin $GITHUB_SERVER_URL/$GITHUB_REPOSITORY >/dev/null
git fetch origin --depth 1 $GITHUB_SHA >/dev/null
git checkout FETCH_HEAD >/dev/null
GITHUB_COMMIT=$(git rev-parse FETCH_HEAD)

# Get back to AWS-LC
popd

echo "Pull source code from remote repository..."

# Copy mldsa-native source tree -- C source
mkdir $SRC
# Copy only files (not subdirectories like native/ and fips202/)
find $TMP/mldsa/src -maxdepth 1 -type f -exec cp {} $SRC \;

# Backend API and specification assumed by mldsa-native frontend
mkdir -p $SRC/native
cp $TMP/mldsa/src/native/api.h $SRC/native

# Copy x86_64 backend
mkdir -p $SRC/native/x86_64/src
# Copy x86_64 backend implementation
cp $TMP/mldsa/src/native/x86_64/meta.h $SRC/native/x86_64
# Copy only assembly-backed source files (skip C intrinsics)
cp $TMP/mldsa/src/native/x86_64/src/arith_native_x86_64.h $SRC/native/x86_64/src
cp $TMP/mldsa/src/native/x86_64/src/consts.h $SRC/native/x86_64/src
cp $TMP/mldsa/src/native/x86_64/src/consts.c $SRC/native/x86_64/src
cp $TMP/mldsa/src/native/x86_64/src/*.S $SRC/native/x86_64/src
# Exclude x86_64 assembly files that do not (yet) have HOL-Light proofs
# (see proofs/hol_light/README.md in mldsa-native). poly_caddq_avx2 was
# previously a C intrinsic and only recently switched to pure assembly
# upstream, but without a proof.
rm -f $SRC/native/x86_64/src/poly_caddq_avx2.S

# Rename assembly files with mldsa_ prefix to avoid basename collisions
# with ML-KEM assembly files (e.g., ntt.S exists in both). This matters
# because s2n-tls's libcrypto interning uses `ar x` which extracts into
# a flat directory and would overwrite files with the same basename.
for file in $SRC/native/x86_64/src/*.S; do
  base=$(basename "$file")
  case "$base" in
    mldsa_*) ;; # already prefixed
    *) mv "$file" "$SRC/native/x86_64/src/mldsa_$base" ;;
  esac
done

# Copy AArch64 backend
#
# Only the assembly files with completed HOL-Light functional correctness
# proofs in mldsa-native are imported. At time of writing (see
# proofs/hol_light/README.md in mldsa-native) that is:
#   - poly_caddq
#   - poly_chknorm
#   - poly_decompose (l=5,7 and l=4)
#   - poly_use_hint  (l=5,7 and l=4)
#   - pointwise multiplication
#   - polyvecl_pointwise_acc_montgomery for L=4, 5, 7
# NTT/INTT, rej_uniform*, and polyz_unpack* are intentionally excluded on
# AArch64 because they do not yet have HOL-Light proofs; the C reference
# implementation is used on those paths instead.
mkdir -p $SRC/native/aarch64/src
cp $TMP/mldsa/src/native/aarch64/meta.h $SRC/native/aarch64
cp $TMP/mldsa/src/native/aarch64/src/arith_native_aarch64.h $SRC/native/aarch64/src

# Copy only the HOL-Light-proved assembly files
cp $TMP/mldsa/src/native/aarch64/src/poly_caddq_asm.S              $SRC/native/aarch64/src
cp $TMP/mldsa/src/native/aarch64/src/poly_chknorm_asm.S            $SRC/native/aarch64/src
cp $TMP/mldsa/src/native/aarch64/src/poly_decompose_32_asm.S       $SRC/native/aarch64/src
cp $TMP/mldsa/src/native/aarch64/src/poly_decompose_88_asm.S       $SRC/native/aarch64/src
cp $TMP/mldsa/src/native/aarch64/src/poly_use_hint_32_asm.S        $SRC/native/aarch64/src
cp $TMP/mldsa/src/native/aarch64/src/poly_use_hint_88_asm.S        $SRC/native/aarch64/src
cp $TMP/mldsa/src/native/aarch64/src/pointwise_montgomery.S        $SRC/native/aarch64/src
cp $TMP/mldsa/src/native/aarch64/src/mld_polyvecl_pointwise_acc_montgomery_l4.S $SRC/native/aarch64/src
cp $TMP/mldsa/src/native/aarch64/src/mld_polyvecl_pointwise_acc_montgomery_l5.S $SRC/native/aarch64/src
cp $TMP/mldsa/src/native/aarch64/src/mld_polyvecl_pointwise_acc_montgomery_l7.S $SRC/native/aarch64/src

# Rename assembly files with mldsa_ prefix to avoid basename collisions
# with ML-KEM assembly files (e.g., ntt.S exists in both). See x86_64
# comment above for rationale. Upstream files may use either no prefix
# or a short mld_ prefix; normalize everything to mldsa_.
for file in $SRC/native/aarch64/src/*.S; do
  base=$(basename "$file")
  case "$base" in
    mldsa_*) ;; # already prefixed
    mld_*) mv "$file" "$SRC/native/aarch64/src/mldsa_${base#mld_}" ;;
    *) mv "$file" "$SRC/native/aarch64/src/mldsa_$base" ;;
  esac
done

# We use the custom `mldsa_native_config.h`, so can remove the default one
rm -f $SRC/config.h

# Copy formatting file
cp $TMP/.clang-format $SRC

if [[ "$(uname)" == "Darwin" ]]; then
  SED_I=(-i "")
else
  SED_I=(-i)
fi

# ================================================================
# Helpers shared by the x86_64 and AArch64 post-processing blocks
# ================================================================

# Delete the MLD_MUST_CHECK_RETURN_VALUE attribute line (if present)
# immediately preceding the function, then the function body itself
# (from `static MLD_INLINE ...fn(` through the matching `^}$`), plus
# any trailing blank line.
strip_inline_fn() {
  local file="$1"
  local fn="$2"
  awk -v fn="$fn" '
    BEGIN { skip = 0; buffered = "" }
    {
      if (skip == 0 && $0 == "MLD_MUST_CHECK_RETURN_VALUE") {
        if (buffered != "") print buffered
        buffered = $0
        next
      }
      if (skip == 0 && $0 ~ ("^static MLD_INLINE.*" fn "\\(")) {
        buffered = ""
        skip = 1
        next
      }
      if (buffered != "") { print buffered; buffered = "" }
      if (skip == 1) {
        if ($0 ~ /^}$/) { skip = 2; next }
        next
      }
      if (skip == 2) {
        if ($0 ~ /^$/) { skip = 0; next }
        skip = 0
      }
      print
    }
    END { if (buffered != "") print buffered }
  ' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
}

# Remove preprocessor guard blocks whose body is empty or whitespace-only
# after function stripping (e.g. `#if X\n#endif /* X */`). Iterate until
# the file converges, since dropping an inner guard can leave its outer
# guard empty. `#if` directives may span multiple physical lines via
# line-continuations; we collapse when the `#if` is immediately followed
# (ignoring blank lines) by the matching `#endif`.
drop_empty_guards() {
  local file="$1"
  while :; do
    awk '
      BEGIN { n = 0 }
      {
        lines[n++] = $0
      }
      END {
        i = 0
        while (i < n) {
          line = lines[i]
          if (line ~ /^#if /) {
            open_start = i
            while (lines[i] ~ /\\$/ && i + 1 < n) i++
            open_end = i
            j = i + 1
            while (j < n && lines[j] ~ /^[ \t]*$/) j++
            if (j < n && lines[j] ~ /^#endif/) {
              end_stop = j
              while (end_stop < n - 1 && lines[end_stop] ~ /\\$/) end_stop++
              if (end_stop + 1 < n && lines[end_stop + 1] ~ /^[ \t]*\*\/[ \t]*$/) {
                end_stop++
              }
              i = end_stop + 1
              continue
            }
            for (k = open_start; k <= open_end; k++) print lines[k]
            i = open_end + 1
            continue
          }
          print line
          i++
        }
      }
    ' "$file" > "$file.tmp"
    if cmp -s "$file" "$file.tmp"; then
      rm "$file.tmp"
      break
    fi
    mv "$file.tmp" "$file"
  done
}

# Drop orphan `MLD_MUST_CHECK_RETURN_VALUE` attribute lines. An attribute
# is orphaned when it is not immediately followed (ignoring blank lines)
# by the `static MLD_INLINE` prototype it was decorating.
strip_orphan_attrs() {
  local file="$1"
  awk '
    BEGIN { held = 0 }
    {
      if (held == 1) {
        if ($0 ~ /^static MLD_INLINE/) {
          print attr; held = 0; print; next
        }
        held = 0
      }
      if ($0 == "MLD_MUST_CHECK_RETURN_VALUE") {
        attr = $0; held = 1; next
      }
      print
    }
    END { if (held == 1) print attr }
  ' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
}

# ================================================================
# Strip C-intrinsic content from x86_64 backend headers
#
# We only import assembly-backed operations (NTT, INTT, nttunpack,
# pointwise, polyvecl_pointwise_acc). C-intrinsic operations
# (rej_uniform, decompose, use_hint, chknorm, polyz_unpack, caddq)
# are intentionally excluded.
# ================================================================

echo "Strip C-intrinsic content from arith_native_x86_64.h"
ARITH_H=$SRC/native/x86_64/src/arith_native_x86_64.h
# Resolve the MLD_CONFIG_NO_{KEYPAIR,SIGN,VERIFY}_API guards upstream
# now wraps around each C-intrinsic declaration. This turns the nested
# `#if !defined(MLD_CONFIG_NO_*_API) ... #endif` pairs into straight-
# line code so that the per-function `#define mld_<fn>_avx2` deletions
# below don't leave orphan opening guards behind.
unifdef -UMLD_CONFIG_NO_KEYPAIR_API -UMLD_CONFIG_NO_SIGN_API \
        -UMLD_CONFIG_NO_VERIFY_API "$ARITH_H" > "$ARITH_H.tmp" \
  || true
mv "$ARITH_H.tmp" "$ARITH_H"
# Remove #include <stdint.h>
sed "${SED_I[@]}" '/#include <stdint.h>/d' "$ARITH_H"
# Remove everything between #include "consts.h" and #define mld_ntt_avx2
# (buffer length macros, comments, rej_uniform_table extern),
# but preserve one blank line separator
sed "${SED_I[@]}" '/^#include "consts.h"$/,/^#define mld_ntt_avx2/{/^#include "consts.h"$/b; /^#define mld_ntt_avx2/b; d;}' "$ARITH_H"
# Replace __contract__ annotated mld_ntt_avx2 declaration with plain declaration
sed "${SED_I[@]}" '/^void mld_ntt_avx2/,/^);$/c\void mld_ntt_avx2(int32_t *r, const int32_t *qdata);' "$ARITH_H"
# Fix mld_invntt_avx2 parameter name (upstream uses mld_qdata, we use qdata)
sed "${SED_I[@]}" 's/const int32_t \*mld_qdata);/const int32_t *qdata);/' "$ARITH_H"
# Remove C-intrinsic function declarations (rej_uniform through polyz_unpack_19)
# and the trailing blank line
sed "${SED_I[@]}" '/^#define mld_rej_uniform_avx2/,/^$/d' "$ARITH_H"
sed "${SED_I[@]}" '/^#define mld_rej_uniform_eta2_avx2/,/^$/d' "$ARITH_H"
sed "${SED_I[@]}" '/^#define mld_rej_uniform_eta4_avx2/,/^$/d' "$ARITH_H"
sed "${SED_I[@]}" '/^#define mld_poly_decompose_32_avx2/,/^$/d' "$ARITH_H"
sed "${SED_I[@]}" '/^#define mld_poly_decompose_88_avx2/,/^$/d' "$ARITH_H"
sed "${SED_I[@]}" '/^#define mld_poly_caddq_avx2/,/^$/d' "$ARITH_H"
sed "${SED_I[@]}" '/^#define mld_poly_use_hint_32_avx2/,/^$/d' "$ARITH_H"
sed "${SED_I[@]}" '/^#define mld_poly_use_hint_88_avx2/,/^$/d' "$ARITH_H"
sed "${SED_I[@]}" '/^#define mld_poly_chknorm_avx2/,/^$/d' "$ARITH_H"
sed "${SED_I[@]}" '/^#define mld_polyz_unpack_17_avx2/,/^$/d' "$ARITH_H"
sed "${SED_I[@]}" '/^#define mld_polyz_unpack_19_avx2/,/^$/d' "$ARITH_H"
# Clean up: remove consecutive blank lines left by deletions
sed "${SED_I[@]}" '/^$/N;/^\n$/d' "$ARITH_H"
# Re-insert blank line between #include "consts.h" and #define mld_ntt_avx2
sed "${SED_I[@]}" 's/^#include "consts.h"$/#include "consts.h"\n/' "$ARITH_H"

echo "Strip C-intrinsic content from meta.h"
META_H=$SRC/native/x86_64/meta.h
# Resolve MLD_CONFIG_NO_*_API guards, same rationale as arith header.
unifdef -UMLD_CONFIG_NO_KEYPAIR_API -UMLD_CONFIG_NO_SIGN_API \
        -UMLD_CONFIG_NO_VERIFY_API "$META_H" > "$META_H.tmp" \
  || true
mv "$META_H.tmp" "$META_H"
# Remove C-intrinsic #define MLD_USE_NATIVE_* lines
sed "${SED_I[@]}" '/#define MLD_USE_NATIVE_REJ_UNIFORM$/d' "$META_H"
sed "${SED_I[@]}" '/#define MLD_USE_NATIVE_REJ_UNIFORM_ETA2$/d' "$META_H"
sed "${SED_I[@]}" '/#define MLD_USE_NATIVE_REJ_UNIFORM_ETA4$/d' "$META_H"
sed "${SED_I[@]}" '/#define MLD_USE_NATIVE_POLY_DECOMPOSE_32$/d' "$META_H"
sed "${SED_I[@]}" '/#define MLD_USE_NATIVE_POLY_DECOMPOSE_88$/d' "$META_H"
sed "${SED_I[@]}" '/#define MLD_USE_NATIVE_POLY_CADDQ$/d' "$META_H"
sed "${SED_I[@]}" '/#define MLD_USE_NATIVE_POLY_USE_HINT_32$/d' "$META_H"
sed "${SED_I[@]}" '/#define MLD_USE_NATIVE_POLY_USE_HINT_88$/d' "$META_H"
sed "${SED_I[@]}" '/#define MLD_USE_NATIVE_POLY_CHKNORM$/d' "$META_H"
sed "${SED_I[@]}" '/#define MLD_USE_NATIVE_POLYZ_UNPACK_17$/d' "$META_H"
sed "${SED_I[@]}" '/#define MLD_USE_NATIVE_POLYZ_UNPACK_19$/d' "$META_H"
# Remove #include <string.h>
sed "${SED_I[@]}" '/#include <string.h>/d' "$META_H"
# Remove C-intrinsic inline function bodies (from mld_rej_uniform_native
# through mld_polyz_unpack_19_native closing brace)
sed "${SED_I[@]}" '/^static MLD_INLINE int mld_rej_uniform_native/,/^static MLD_INLINE int mld_poly_pointwise_montgomery_native/{/^static MLD_INLINE int mld_poly_pointwise_montgomery_native/!d;}' "$META_H"
# The range delete above consumes the `#if !defined(MLD_CONFIG_NO_SIGN_API)
# || !defined(MLD_CONFIG_NO_VERIFY_API) || MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST`
# opener that upstream wraps around |mld_poly_pointwise_montgomery_native|,
# but the matching `#endif` is after that function (outside the range) and
# survives. Delete that orphan `#endif` (multi-line continuation form).
sed "${SED_I[@]}" '/^#endif \/\* !MLD_CONFIG_NO_SIGN_API || !MLD_CONFIG_NO_VERIFY_API || \\$/,/^          MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST \*\/$/d' "$META_H"
# Drop any preprocessor guard blocks whose body is now empty (upstream
# wraps each C-intrinsic in its own `#if !defined(MLD_CONFIG_NO_*_API)`
# guard; the range-based sed delete above consumes the `#define ... #endif`
# but can leave the `#if` behind). Iterate also takes care of the few
# declarations upstream now stacks into nested guards.
drop_empty_guards "$META_H"
strip_orphan_attrs "$META_H"
# Clean up consecutive blank lines
sed "${SED_I[@]}" '/^$/N;/^\n$/d' "$META_H"

# Same cleanup for arith_native_x86_64.h, where the range-based deletions
# above can leave orphan `#if !defined(MLD_CONFIG_NO_*_API)` guards.
drop_empty_guards "$ARITH_H"
sed "${SED_I[@]}" '/^$/N;/^\n$/d' "$ARITH_H"

echo "Add MLD_INTERNAL_API to consts.c and consts.h"
# consts.c: add MLD_INTERNAL_API to the array definition
sed "${SED_I[@]}" 's/MLD_ALIGN const int32_t mld_qdata/MLD_ALIGN MLD_INTERNAL_API const int32_t mld_qdata/' "$SRC/native/x86_64/src/consts.c"
# consts.h: replace extern with MLD_INTERNAL_API
sed "${SED_I[@]}" 's/extern const int32_t mld_qdata\[624\]/MLD_INTERNAL_API const int32_t mld_qdata[624]/' "$SRC/native/x86_64/src/consts.h"

# ================================================================
# Strip unproven content from AArch64 backend headers
#
# We only import assembly routines with completed HOL-Light proofs
# (poly_caddq, poly_chknorm, poly_decompose_{32,88}, poly_use_hint_{32,88},
# pointwise_montgomery, polyvecl_pointwise_acc_montgomery_l{4,5,7}).
# NTT/INTT, rej_uniform* and polyz_unpack* are intentionally excluded
# on AArch64 because they are not yet formally verified.
# ================================================================

echo "Strip unproven content from aarch64 meta.h"
AARCH64_META_H=$SRC/native/aarch64/meta.h
# Remove MLD_USE_NATIVE_* defines for unproven operations
sed "${SED_I[@]}" '/^#define MLD_USE_NATIVE_NTT$/d'                "$AARCH64_META_H"
sed "${SED_I[@]}" '/^#define MLD_USE_NATIVE_INTT$/d'               "$AARCH64_META_H"
sed "${SED_I[@]}" '/^#define MLD_USE_NATIVE_REJ_UNIFORM$/d'        "$AARCH64_META_H"
sed "${SED_I[@]}" '/^#define MLD_USE_NATIVE_REJ_UNIFORM_ETA2$/d'   "$AARCH64_META_H"
sed "${SED_I[@]}" '/^#define MLD_USE_NATIVE_REJ_UNIFORM_ETA4$/d'   "$AARCH64_META_H"
sed "${SED_I[@]}" '/^#define MLD_USE_NATIVE_POLYZ_UNPACK_17$/d'    "$AARCH64_META_H"
sed "${SED_I[@]}" '/^#define MLD_USE_NATIVE_POLYZ_UNPACK_19$/d'    "$AARCH64_META_H"
# Remove the inline wrapper bodies for the stripped operations (helpers
# strip_inline_fn / drop_empty_guards / strip_orphan_attrs are defined
# above).
strip_inline_fn "$AARCH64_META_H" mld_ntt_native
strip_inline_fn "$AARCH64_META_H" mld_intt_native
strip_inline_fn "$AARCH64_META_H" mld_rej_uniform_native
strip_inline_fn "$AARCH64_META_H" mld_rej_uniform_eta2_native
strip_inline_fn "$AARCH64_META_H" mld_rej_uniform_eta4_native
strip_inline_fn "$AARCH64_META_H" mld_polyz_unpack_17_native
strip_inline_fn "$AARCH64_META_H" mld_polyz_unpack_19_native
# Drop preprocessor guard blocks whose body is now empty (the functions
# they wrapped were just stripped).
drop_empty_guards "$AARCH64_META_H"
strip_orphan_attrs "$AARCH64_META_H"
sed "${SED_I[@]}" '/^$/N;/^\n$/d' "$AARCH64_META_H"

echo "Strip unproven content from arith_native_aarch64.h"
AARCH64_ARITH_H=$SRC/native/aarch64/src/arith_native_aarch64.h

# Flatten line continuations so every logical `#define` / declaration
# lives on a single physical line. This makes the subsequent regex
# deletions unambiguous.
sed -e ':a' -e 'N' -e '$!ba' -e 's/\\\n[ \t]*/ /g' "$AARCH64_ARITH_H" \
  > "$AARCH64_ARITH_H.flat" && mv "$AARCH64_ARITH_H.flat" "$AARCH64_ARITH_H"
# Also flatten declarations that span multiple lines without a
# line-continuation (e.g. the type/name split of
# `MLD_INTERNAL_DATA_DECLARATION const int32_t\n    mld_aarch64_*[N];`).
# Join any line that ends on `int32_t` with the following line.
awk '
  {
    if (buf != "") { print buf " " $0; buf = ""; next }
    if ($0 ~ /^MLD_INTERNAL_DATA_DECLARATION const (int32_t|uint8_t)$/) {
      buf = $0; next
    }
    print
  }
  END { if (buf != "") print buf }
' "$AARCH64_ARITH_H" > "$AARCH64_ARITH_H.flat" \
  && mv "$AARCH64_ARITH_H.flat" "$AARCH64_ARITH_H"

# Drop the NTT/INTT zetas `#define` aliases and data declarations.
sed "${SED_I[@]}" '/^#define mld_aarch64_ntt_zetas_layer123456 /d'  "$AARCH64_ARITH_H"
sed "${SED_I[@]}" '/^#define mld_aarch64_ntt_zetas_layer78 /d'      "$AARCH64_ARITH_H"
sed "${SED_I[@]}" '/^#define mld_aarch64_intt_zetas_layer78 /d'     "$AARCH64_ARITH_H"
sed "${SED_I[@]}" '/^#define mld_aarch64_intt_zetas_layer123456 /d' "$AARCH64_ARITH_H"
sed "${SED_I[@]}" '/^MLD_INTERNAL_DATA_DECLARATION const int32_t.*mld_aarch64_ntt_zetas_layer123456\[144\];/d'  "$AARCH64_ARITH_H"
sed "${SED_I[@]}" '/^MLD_INTERNAL_DATA_DECLARATION const int32_t.*mld_aarch64_ntt_zetas_layer78\[384\];/d'     "$AARCH64_ARITH_H"
sed "${SED_I[@]}" '/^MLD_INTERNAL_DATA_DECLARATION const int32_t.*mld_aarch64_intt_zetas_layer78\[384\];/d'    "$AARCH64_ARITH_H"
sed "${SED_I[@]}" '/^MLD_INTERNAL_DATA_DECLARATION const int32_t.*mld_aarch64_intt_zetas_layer123456\[160\];/d' "$AARCH64_ARITH_H"

# Drop rej_uniform_table / rej_uniform_eta_table declarations and their
# `#define` aliases.
sed "${SED_I[@]}" '/^#define mld_rej_uniform_table /d' "$AARCH64_ARITH_H"
sed "${SED_I[@]}" '/^MLD_INTERNAL_DATA_DECLARATION const uint8_t.*mld_rej_uniform_table\[256\];/d' "$AARCH64_ARITH_H"
sed "${SED_I[@]}" '/^#define mld_rej_uniform_eta_table /d' "$AARCH64_ARITH_H"
sed "${SED_I[@]}" '/^MLD_INTERNAL_DATA_DECLARATION const uint8_t.*mld_rej_uniform_eta_table\[4096\];/d' "$AARCH64_ARITH_H"
# Drop polyz_unpack_{17,19}_indices declarations
sed "${SED_I[@]}" '/^#define mld_polyz_unpack_17_indices /d' "$AARCH64_ARITH_H"
sed "${SED_I[@]}" '/^MLD_INTERNAL_DATA_DECLARATION const uint8_t.*mld_polyz_unpack_17_indices\[64\];/d' "$AARCH64_ARITH_H"
sed "${SED_I[@]}" '/^#define mld_polyz_unpack_19_indices /d' "$AARCH64_ARITH_H"
sed "${SED_I[@]}" '/^MLD_INTERNAL_DATA_DECLARATION const uint8_t.*mld_polyz_unpack_19_indices\[64\];/d' "$AARCH64_ARITH_H"
# Drop buflen macros (only referenced by rej_uniform_eta*)
sed "${SED_I[@]}" '/^#define MLD_AARCH64_REJ_UNIFORM_ETA2_BUFLEN /d' "$AARCH64_ARITH_H"
sed "${SED_I[@]}" '/^#define MLD_AARCH64_REJ_UNIFORM_ETA4_BUFLEN /d' "$AARCH64_ARITH_H"
# Drop the comments that only document the buflen macros (above the macro
# definitions upstream).
awk '
  BEGIN { skip = 0 }
  {
    if (skip == 0 && $0 ~ /^\/\*$/) {
      buf = $0; skip = 1; next
    }
    if (skip == 1) {
      buf = buf "\n" $0
      if ($0 ~ /\*\/$/) {
        if (buf ~ /Sampling 256 coefficients mod (15|9)/) { buf = ""; skip = 0; next }
        print buf; buf = ""; skip = 0
      }
      next
    }
    print
  }
' "$AARCH64_ARITH_H" > "$AARCH64_ARITH_H.flat" \
  && mv "$AARCH64_ARITH_H.flat" "$AARCH64_ARITH_H"

# Drop function declarations for unproven routines. After the flatten pass,
# each declaration spans from the `#define mld_<fn> ...` line through the
# first `);` that closes the __contract__ (or prototype for a one-liner).
strip_ref_decl() {
  local file="$1"
  local fn="$2"
  awk -v fn="$fn" '
    BEGIN { skip = 0 }
    {
      if (skip == 0 && $0 ~ ("^#define " fn " ")) { skip = 1; next }
      if (skip == 1) {
        if ($0 ~ /\);$/) { skip = 2; next }
        next
      }
      if (skip == 2) {
        if ($0 ~ /^$/) { skip = 0; next }
        skip = 0
      }
      print
    }
  ' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
}
strip_ref_decl "$AARCH64_ARITH_H" mld_ntt_asm
strip_ref_decl "$AARCH64_ARITH_H" mld_intt_asm
strip_ref_decl "$AARCH64_ARITH_H" mld_rej_uniform_asm
strip_ref_decl "$AARCH64_ARITH_H" mld_rej_uniform_eta2_asm
strip_ref_decl "$AARCH64_ARITH_H" mld_rej_uniform_eta4_asm
strip_ref_decl "$AARCH64_ARITH_H" mld_polyz_unpack_17_asm
strip_ref_decl "$AARCH64_ARITH_H" mld_polyz_unpack_19_asm

# Drop now-empty preprocessor guards and collapse runs of blank lines.
drop_empty_guards "$AARCH64_ARITH_H"
sed "${SED_I[@]}" '/^$/N;/^\n$/d' "$AARCH64_ARITH_H"
# ================================================================
# Process mldsa_native_bcm.c
# ================================================================

# Copy and statically simplify BCM file
# The static simplification is not necessary, but improves readability
# by removing directives related to the FIPS-202 backend that we provide
# via our own glue layer.
unifdef -DMLD_CONFIG_FIPS202_CUSTOM_HEADER                             \
        -UMLD_CONFIG_USE_NATIVE_BACKEND_FIPS202                        \
        $TMP/mldsa/mldsa_native.c                                      \
        > $SRC/mldsa_native_bcm.c

# Copy mldsa-native header
# This is only needed for access to the various macros defining key sizes.
# The function declarations itself are all visible in ml_dsa.c by virtue
# of everything being inlined into that file.
cp $TMP/mldsa/mldsa_native.h $SRC

# Modify include paths to match position of mldsa_native_bcm.c
# In mldsa-native, the include path is "mldsa/*", while here we
# embed mldsa_native_bcm.c in the main source directory of mldsa-native,
# hence the relative import path is just ".".
echo "Fixup include paths"
sed "${SED_I[@]}" 's/#include "src\/\([^"]*\)"/#include "\1"/' $SRC/mldsa_native_bcm.c

# Strip unproven AArch64 data table includes from BCM. The aarch64 section
# only ships the HOL-Light-proved assembly routines; ntt/intt, rej_uniform*
# and polyz_unpack* are not imported and their data tables (aarch64_zetas,
# rej_uniform_table, rej_uniform_eta_table, polyz_unpack_table) are unused.
echo "Strip unproven AArch64 data table includes from mldsa_native_bcm.c"
BCM=$SRC/mldsa_native_bcm.c
sed "${SED_I[@]}" '/^#include "native\/aarch64\/src\/aarch64_zetas\.c"/d' "$BCM"
sed "${SED_I[@]}" '/^#include "native\/aarch64\/src\/polyz_unpack_table\.c"/d' "$BCM"
sed "${SED_I[@]}" '/^#include "native\/aarch64\/src\/rej_uniform_eta_table\.c"/d' "$BCM"
sed "${SED_I[@]}" '/^#include "native\/aarch64\/src\/rej_uniform_table\.c"/d' "$BCM"

# Strip C-intrinsic .c file includes from BCM (keep only consts.c)
echo "Strip C-intrinsic includes from mldsa_native_bcm.c"
sed "${SED_I[@]}" '/^#include "native\/x86_64\/src\/poly_caddq_avx2\.c"/d' "$BCM"
sed "${SED_I[@]}" '/^#include "native\/x86_64\/src\/poly_chknorm_avx2\.c"/d' "$BCM"
sed "${SED_I[@]}" '/^#include "native\/x86_64\/src\/poly_decompose_32_avx2\.c"/d' "$BCM"
sed "${SED_I[@]}" '/^#include "native\/x86_64\/src\/poly_decompose_88_avx2\.c"/d' "$BCM"
sed "${SED_I[@]}" '/^#include "native\/x86_64\/src\/poly_use_hint_32_avx2\.c"/d' "$BCM"
sed "${SED_I[@]}" '/^#include "native\/x86_64\/src\/poly_use_hint_88_avx2\.c"/d' "$BCM"
sed "${SED_I[@]}" '/^#include "native\/x86_64\/src\/polyz_unpack_17_avx2\.c"/d' "$BCM"
sed "${SED_I[@]}" '/^#include "native\/x86_64\/src\/polyz_unpack_19_avx2\.c"/d' "$BCM"
sed "${SED_I[@]}" '/^#include "native\/x86_64\/src\/rej_uniform_avx2\.c"/d' "$BCM"
sed "${SED_I[@]}" '/^#include "native\/x86_64\/src\/rej_uniform_eta2_avx2\.c"/d' "$BCM"
sed "${SED_I[@]}" '/^#include "native\/x86_64\/src\/rej_uniform_eta4_avx2\.c"/d' "$BCM"
sed "${SED_I[@]}" '/^#include "native\/x86_64\/src\/rej_uniform_table\.c"/d' "$BCM"

# Strip C-intrinsic #undef entries from the x86_64 undef block
sed "${SED_I[@]}" '/^#undef MLD_USE_NATIVE_POLYZ_UNPACK_17$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef MLD_USE_NATIVE_POLYZ_UNPACK_19$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef MLD_USE_NATIVE_POLY_CADDQ$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef MLD_USE_NATIVE_POLY_CHKNORM$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef MLD_USE_NATIVE_POLY_DECOMPOSE_32$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef MLD_USE_NATIVE_POLY_DECOMPOSE_88$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef MLD_USE_NATIVE_POLY_USE_HINT_32$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef MLD_USE_NATIVE_POLY_USE_HINT_88$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef MLD_USE_NATIVE_REJ_UNIFORM$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef MLD_USE_NATIVE_REJ_UNIFORM_ETA2$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef MLD_USE_NATIVE_REJ_UNIFORM_ETA4$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef MLD_AVX2_REJ_UNIFORM_BUFLEN$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef MLD_AVX2_REJ_UNIFORM_ETA2_BUFLEN$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef MLD_AVX2_REJ_UNIFORM_ETA4_BUFLEN$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef mld_poly_caddq_avx2$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef mld_poly_chknorm_avx2$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef mld_poly_decompose_32_avx2$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef mld_poly_decompose_88_avx2$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef mld_poly_use_hint_32_avx2$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef mld_poly_use_hint_88_avx2$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef mld_polyz_unpack_17_avx2$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef mld_polyz_unpack_19_avx2$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef mld_rej_uniform_avx2$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef mld_rej_uniform_eta2_avx2$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef mld_rej_uniform_eta4_avx2$/d' "$BCM"
sed "${SED_I[@]}" '/^#undef mld_rej_uniform_table$/d' "$BCM"

# ================================================================
# Fixup native assembly backends to use s2n-bignum macros
# ================================================================

fixup_asm_backend() {
  # $1 = directory of .S files
  # $2 = backend define (e.g. MLD_ARITH_BACKEND_X86_64_DEFAULT)
  # $3 = s2n-bignum header to include
  local dir="$1"
  local backend_define="$2"
  local s2n_header="$3"

  for file in "$dir"/*.S; do
    echo "Processing $file"
    tmp_file=$(mktemp)

    # Flatten multiline preprocessor directives, then process with unifdef.
    # -DMLD_CONFIG_MULTILEVEL_WITH_SHARED / -UMLD_CONFIG_MULTILEVEL_NO_SHARED
    # is the configuration we use for the single BCM build. We also
    # -U the NO_{KEYPAIR,SIGN,VERIFY}_API flags so unifdef can fully
    # resolve the multi-clause `#if` guards upstream attaches to the
    # per-primitive aarch64 assembly files.
    sed -e ':a' -e 'N' -e '$!ba' -e 's/\\\n/ /g' "$file" | \
      unifdef -D"$backend_define" \
              -UMLD_CONFIG_MULTILEVEL_NO_SHARED \
              -DMLD_CONFIG_MULTILEVEL_WITH_SHARED \
              -UMLD_CONFIG_NO_KEYPAIR_API \
              -UMLD_CONFIG_NO_SIGN_API \
              -UMLD_CONFIG_NO_VERIFY_API \
              > "$tmp_file"
    mv "$tmp_file" "$file"

    # Replace common.h include with the s2n-bignum header
    sed "${SED_I[@]}" "s|#include \"\.\./\.\./\.\./common\.h\"|#include \"$s2n_header\"|" "$file"

    func_name=$(grep -o '\.global MLD_ASM_NAMESPACE(\([^)]*\))' "$file" | sed 's/\.global MLD_ASM_NAMESPACE(\([^)]*\))/\1/')
    if [ -n "$func_name" ]; then
      sed "${SED_I[@]}" "s/\.global MLD_ASM_NAMESPACE($func_name)/        S2N_BN_SYM_VISIBILITY_DIRECTIVE(mldsa_$func_name)\n        S2N_BN_SYM_PRIVACY_DIRECTIVE(mldsa_$func_name)/" "$file"
      sed "${SED_I[@]}" "s/MLD_ASM_FN_SYMBOL($func_name)/S2N_BN_SYMBOL(mldsa_$func_name):/" "$file"
      # Upstream aarch64 files close with `MLD_ASM_FN_SIZE(name)` rather than
      # needing a post-`.cfi_endproc` insertion, so handle that case too.
      sed "${SED_I[@]}" "s/MLD_ASM_FN_SIZE($func_name)/S2N_BN_SIZE_DIRECTIVE(mldsa_$func_name)/" "$file"

      # If the file did not carry an MLD_ASM_FN_SIZE directive, add
      # S2N_BN_SIZE_DIRECTIVE after .cfi_endproc (x86_64 case).
      if ! grep -q "S2N_BN_SIZE_DIRECTIVE(mldsa_$func_name)" "$file"; then
        sed "${SED_I[@]}" "/.cfi_endproc/a\\
\\
S2N_BN_SIZE_DIRECTIVE(mldsa_$func_name)" "$file"
      fi
    fi

    # Move ELF section before .text (match s2n-bignum convention) and
    # normalize to `@progbits` (upstream aarch64 uses `%progbits`).
    sed "${SED_I[@]}" '/#if defined(__ELF__)/,/#endif/d' "$file"
    sed "${SED_I[@]}" '/^\.text$/i\
#if defined(__ELF__)\
.section .note.GNU-stack,"",@progbits\
#endif\
' "$file"

    # Clean up: strip leading whitespace from lines left indented after unifdef
    sed "${SED_I[@]}" 's/^ \(\/\*\)/\1/' "$file"
    sed "${SED_I[@]}" 's/^ \(#include\)/#include/' "$file"
    # Remove consecutive blank lines
    sed "${SED_I[@]}" '/^$/N;/^\n$/d' "$file"
  done
}

echo "Fixup x86_64 assembly backend to use s2n-bignum macros"
fixup_asm_backend "$SRC/native/x86_64/src" \
  "MLD_ARITH_BACKEND_X86_64_DEFAULT" \
  "_internal_s2n_bignum_x86_att.h"

echo "Fixup AArch64 assembly backend to use s2n-bignum macros"
fixup_asm_backend "$SRC/native/aarch64/src" \
  "MLD_ARITH_BACKEND_AARCH64" \
  "_internal_s2n_bignum_arm.h"

echo "Remove temporary artifacts ..."
rm -rf $TMP

# Log timestamp, repository, and commit

echo "Generating META.yml file ..."
cat <<EOF > META.yml
name: mldsa-native
source: $GITHUB_REPOSITORY
branch: $GITHUB_SHA
commit: $GITHUB_COMMIT
imported-at: $(date "+%Y-%m-%dT%H:%M:%S%z")
EOF

echo "Import complete!"
echo "Imported mldsa-native commit: $GITHUB_COMMIT"
