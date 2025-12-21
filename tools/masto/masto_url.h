#pragma once

#include "mc.h"

// URL-encodes `in` into `out` for application/x-www-form-urlencoded.
// Encodes everything except: A-Z a-z 0-9 - _ . ~
// Encodes space as '+' (form encoding).
//
// Returns 0 on success, non-zero on truncation/error.
int masto_urlencode_form(const char *in, char *out, mc_usize out_cap);
