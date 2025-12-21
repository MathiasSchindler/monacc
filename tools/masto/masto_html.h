#pragma once

#include "mc.h"

// Strips a small subset of HTML for terminal output.
// - Removes tags like <p>, <a>, ...
// - Converts </p> and <br> into newlines
// - Decodes a few common entities: &amp; &lt; &gt; &quot; &#39;
//
// Returns number of bytes written (excluding NUL terminator).
mc_usize masto_html_strip(const char *in, mc_usize in_len, char *out, mc_usize out_cap);
