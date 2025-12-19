#pragma once

#include "mc.h"

/* Minimal float math helpers (no libc/libm).
 * Implementations are in core/mc_mathf.c.
 */

float mc_expf(float x);
float mc_sqrtf(float x);
float mc_tanhf(float x);

/* Tensor helpers (kept in mc_mathf.c for now). */

/* Write a transposed float32 matrix.
 * Input layout: src[in_dim][out_dim] (row-major, out_dim contiguous).
 * Output stream layout: out_dim rows of length in_dim, i.e. dst[out_dim][in_dim].
 */
mc_i64 mc_write_transposed_f32(mc_i32 out_fd, const float *src, mc_u32 in_dim, mc_u32 out_dim);
