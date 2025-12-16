#!/bin/sh
set -eu

# Convert build/matrix TSVs into a human-friendly HTML report.
#
# Inputs:
#   - build TSV:  build/matrix/build.tsv   (tc \t tool \t OK|FAIL \t mode \t bytes)
#   - size TSV:   build/matrix/report.tsv  (tc \t tool \t bytes)  [header optional]
#
# Output:
#   - HTML file (default: build/matrix/report.html)
#
# Usage:
#   sh tests/matrix/tsv-to-html.sh [--build FILE] [--sizes FILE] [--out FILE]

BUILD_TSV="build/matrix/build.tsv"
SIZES_TSV="build/matrix/report.tsv"
OUT_HTML="build/matrix/report.html"
AWK_CMD=""

while [ "$#" -gt 0 ]; do
	case "$1" in
		--awk)
			[ "$#" -ge 2 ] || { echo "error: --awk needs a command/path" >&2; exit 1; }
			AWK_CMD="$2"; shift 2
			;;
		--build)
			[ "$#" -ge 2 ] || { echo "error: --build needs a path" >&2; exit 1; }
			BUILD_TSV="$2"; shift 2
			;;
		--sizes|--size)
			[ "$#" -ge 2 ] || { echo "error: --sizes needs a path" >&2; exit 1; }
			SIZES_TSV="$2"; shift 2
			;;
		--out)
			[ "$#" -ge 2 ] || { echo "error: --out needs a path" >&2; exit 1; }
			OUT_HTML="$2"; shift 2
			;;
		-h|--help)
			echo "Usage: sh tests/matrix/tsv-to-html.sh [--build FILE] [--sizes FILE] [--out FILE] [--awk CMD]" >&2
			exit 0
			;;
		*)
			echo "error: unknown arg: $1" >&2
			exit 1
			;;
	esac

done

if [ -z "$AWK_CMD" ]; then
	# Prefer monacc-built awk only if it supports the features we use (notably -v).
	if [ -x ./bin/awk ] && ./bin/awk -v __probe=1 'BEGIN{exit (__probe==1)?0:1}' </dev/null >/dev/null 2>/dev/null; then
		AWK_CMD="./bin/awk"
	else
		AWK_CMD="awk"
	fi
fi
command -v "${AWK_CMD#./}" >/dev/null 2>/dev/null || { echo "error: awk not found: $AWK_CMD" >&2; exit 1; }

# Ensure output directory exists.
out_dir="$(dirname "$OUT_HTML")"
mkdir -p "$out_dir"

"$AWK_CMD" -v BUILD_TSV="$BUILD_TSV" -v SIZES_TSV="$SIZES_TSV" '
function esc_html(s,    t) {
	# minimal escaping for table cells
	t = s
	gsub(/&/, "&amp;", t)
	gsub(/</, "&lt;", t)
	gsub(/>/, "&gt;", t)
	gsub(/"/, "&quot;", t)
	return t
}

function clamp01(x) {
	if (x < 0) return 0
	if (x > 1) return 1
	return x
}

function bg_for_ratio(r,    rr, gg, bb) {
	# Mild red/green for dark background.
	r = clamp01(r)
	rr = int(30 + (200 - 30) * r)
	gg = int(140 - (140 - 35) * r)
	bb = int(45 - (45 - 25) * r)
	return sprintf("background-color: rgba(%d,%d,%d,0.22);", rr, gg, bb)
}

function norm_tabs(line,    t) {
	# tolerate files that accidentally contain literal "\\t" sequences
	t = line
	gsub(/\\t/, "\t", t)
	return t
}

function add_tc(tc) {
	if (!(tc in seen_tc)) {
		seen_tc[tc] = 1
		tc_list[++tc_n] = tc
	}
}

function add_tool(tool) {
	if (!(tool in seen_tool)) {
		seen_tool[tool] = 1
		tool_list[++tool_n] = tool
	}
}

BEGIN {
	# Read build TSV (no header expected)
	while ((getline raw < BUILD_TSV) > 0) {
		line = norm_tabs(raw)
		split(line, f, "\t")
		if (length(f[1]) == 0) continue
		tc = f[1]
		tool = f[2]
		status = f[3]
		mode = f[4]
		bytes = f[5]
		add_tc(tc)
		add_tool(tool)
		build[tool SUBSEP tc] = status "\t" mode "\t" bytes
		if (status == "OK" && bytes ~ /^[0-9]+$/) {
			b = bytes + 0
			if (!(tool in build_min) || b < build_min[tool]) build_min[tool] = b
			if (!(tool in build_max) || b > build_max[tool]) build_max[tool] = b
		}
	}
	close(BUILD_TSV)

	# Read size TSV (header optional)
	while ((getline raw2 < SIZES_TSV) > 0) {
		line2 = norm_tabs(raw2)
		split(line2, g, "\t")
		# header forms: "toolchain\ttool\tbytes" or actual tabs
		if (g[1] == "toolchain" && g[2] == "tool" && g[3] == "bytes") continue
		if (g[1] ~ /^toolchain\\ttool\\tbytes$/) continue
		if (length(g[1]) == 0) continue
		tc2 = g[1]
		tool2 = g[2]
		bytes2 = g[3]
		# report.tsv contains aliases too; keep union of tools/toolchains
		add_tc(tc2)
		add_tool(tool2)
		size[tool2 SUBSEP tc2] = bytes2
		if (bytes2 ~ /^[0-9]+$/) {
			b2 = bytes2 + 0
			if (!(tool2 in size_min) || b2 < size_min[tool2]) size_min[tool2] = b2
			if (!(tool2 in size_max) || b2 > size_max[tool2]) size_max[tool2] = b2
		}
	}
	close(SIZES_TSV)

	# Basic sort tool list (lexicographic) for readability
	for (i = 1; i <= tool_n; i++) {
		for (j = i + 1; j <= tool_n; j++) {
			if (tool_list[j] < tool_list[i]) {
				tmp = tool_list[i]
				tool_list[i] = tool_list[j]
				tool_list[j] = tmp
			}
		}
	}

	# Sort toolchains but keep monacc first if present
	# simple stable selection: extract monacc if present, then sort the rest
	monacc_present = ("monacc" in seen_tc)
	out_tc_n = 0
	if (monacc_present) {
		out_tc[++out_tc_n] = "monacc"
	}
	k = 0
	for (i = 1; i <= tc_n; i++) {
		if (tc_list[i] == "monacc") continue
		others[++k] = tc_list[i]
	}
	for (i = 1; i <= k; i++) {
		for (j = i + 1; j <= k; j++) {
			if (others[j] < others[i]) { tmp = others[i]; others[i] = others[j]; others[j] = tmp }
		}
	}
	for (i = 1; i <= k; i++) out_tc[++out_tc_n] = others[i]

	print "<!doctype html>"
	print "<html lang=\"en\">"
	print "<head>"
	print "  <meta charset=\"utf-8\">"
	print "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
	print "  <title>monacc matrix report</title>"
	print "  <style>"
	print "    :root {"
	print "      --bg: #0b0d10;"
	print "      --fg: #e6edf3;"
	print "      --muted: #9aa4af;"
	print "      --border: #22303a;"
	print "      --ok: #17331c;"
	print "      --fail: #3a1717;"
	print "      --skip: #2a2512;"
	print "      --best: #1c3b21;"
	print "      --worst: #3f1c1c;"
	print "      --head: #11161c;"
	print "    }"
	print "    body { background: var(--bg); color: var(--fg); font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 24px; }"
	print "    h1 { font-size: 20px; margin: 0 0 10px 0; }"
	print "    h2 { font-size: 16px; margin: 22px 0 10px 0; }"
	print "    .muted { color: var(--muted); font-size: 12px; }"
	print "    .card { border: 1px solid var(--border); border-radius: 10px; padding: 14px; background: rgba(255,255,255,0.02); }"
	print "    table { width: 100%; border-collapse: collapse; margin: 10px 0 0 0; font-size: 12px; }"
	print "    th, td { border: 1px solid var(--border); padding: 6px 8px; vertical-align: top; }"
	print "    th { background: var(--head); position: sticky; top: 0; z-index: 1; }"
	print "    td.tool { white-space: nowrap; font-weight: 600; }"
	print "    td.ok { background: var(--ok); }"
	print "    td.fail { background: var(--fail); }"
	print "    td.skip { background: var(--skip); }"
	print "    td.best { background: var(--best); }"
	print "    td.worst { background: var(--worst); }"
	print "    .cell { display: flex; gap: 6px; flex-wrap: wrap; }"
	print "    .badge { padding: 1px 6px; border-radius: 999px; border: 1px solid var(--border); font-size: 11px; color: var(--muted); }"
	print "    .num { font-variant-numeric: tabular-nums; }"
	print "    .right { text-align: right; }"
	print "  </style>"
	print "</head>"
	print "<body>"
	print "  <h1>Matrix report</h1>"
	print "  <div class=\"muted\">Generated from build.tsv + report.tsv</div>"

	# Build table
	print "  <h2>Build matrix (status + mode + bytes)</h2>"
	print "  <div class=\"card\">"
	print "  <table>"
	print "    <thead><tr><th>tool</th>"
	for (c = 1; c <= out_tc_n; c++) {
		print "<th>" esc_html(out_tc[c]) "</th>"
	}
	print "</tr></thead>"
	print "    <tbody>"
	for (r = 1; r <= tool_n; r++) {
		tool = tool_list[r]
		print "      <tr><td class=\"tool\">" esc_html(tool) "</td>"
		for (c = 1; c <= out_tc_n; c++) {
			tc = out_tc[c]
			key = tool SUBSEP tc
			if (key in build) {
				split(build[key], bf, "\t")
				st = bf[1]
				md = bf[2]
				by = bf[3]
				cls = (st == "OK") ? "ok" : (st == "FAIL") ? "fail" : "skip"
				style = ""
				title = ""
				if (st == "OK" && by ~ /^[0-9]+$/ && (tool in build_min) && (tool in build_max) && build_max[tool] > build_min[tool]) {
					ratio = ((by + 0) - build_min[tool]) / (build_max[tool] - build_min[tool])
					style = bg_for_ratio(ratio)
					delta = (by + 0) - build_min[tool]
					title = sprintf("%s bytes (min %d, +%d)", by, build_min[tool], delta)
				}
				print "<td class=\"" cls "\"" \
				      (style != "" ? " style=\"" style "\"" : "") \
				      (title != "" ? " title=\"" esc_html(title) "\"" : "") \
				      "><div class=\"cell\">" \
				      "<span class=\"badge\">" esc_html(st) "</span>" \
				      "<span class=\"badge\">" esc_html(md) "</span>" \
				      "<span class=\"badge num\">" esc_html(by) "</span>" \
				      "</div></td>"
			} else {
				print "<td class=\"skip\"><span class=\"badge\">n/a</span></td>"
			}
		}
		print "</tr>"
	}
	print "    </tbody>"
	print "  </table>"
	print "  </div>"

	# Size table with per-row gradient (min->green, max->red)
	print "  <h2>Size report (bytes; best per tool highlighted)</h2>"
	print "  <div class=\"card\">"
	print "  <table>"
	print "    <thead><tr><th>tool</th>"
	for (c = 1; c <= out_tc_n; c++) print "<th class=\"right\">" esc_html(out_tc[c]) "</th>"
	print "</tr></thead>"
	print "    <tbody>"
	for (r = 1; r <= tool_n; r++) {
		tool = tool_list[r]
		min = (tool in size_min) ? size_min[tool] : -1
		max = (tool in size_max) ? size_max[tool] : -1

		print "      <tr><td class=\"tool\">" esc_html(tool) "</td>"
		for (c = 1; c <= out_tc_n; c++) {
			tc = out_tc[c]
			k2 = tool SUBSEP tc
			if (k2 in size) {
				v = size[k2] + 0
				cls2 = ""
				if (min >= 0 && v == min) cls2 = "best"
				else if (max >= 0 && v == max && max != min) cls2 = "worst"
				style2 = ""
				title2 = ""
				if (min >= 0 && max >= 0 && max > min) {
					ratio2 = (v - min) / (max - min)
					style2 = bg_for_ratio(ratio2)
					delta2 = v - min
					title2 = sprintf("%d bytes (min %d, +%d)", v, min, delta2)
				}
				print "<td class=\"right num " cls2 "\"" \
				      (style2 != "" ? " style=\"" style2 "\"" : "") \
				      (title2 != "" ? " title=\"" esc_html(title2) "\"" : "") \
				      ">" esc_html(size[k2]) "</td>"
			} else {
				print "<td class=\"right skip\"><span class=\"badge\">n/a</span></td>"
			}
		}
		print "</tr>"
	}
	print "    </tbody>"
	print "  </table>"
	print "  </div>"

	print "</body>"
	print "</html>"
}
' >"$OUT_HTML"

echo "Wrote $OUT_HTML"
