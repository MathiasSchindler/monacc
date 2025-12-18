#!/bin/sh
# Common helpers for matrix scripts (POSIX sh)

say() {
	printf '%s\n' "$*"
}

die() {
	say "error: $*" >&2
	exit 1
}

have_cmd() {
	command -v "$1" >/dev/null 2>/dev/null
}

# Determine parallelism for matrix builds.
# Priority:
#   1) MATRIX_JOBS (explicit)
#   2) GNU make -j via MAKEFLAGS (so `make -jN MULTI=1 test` propagates)
#   3) CPU count
#   4) 1
matrix_jobs() {
	# Explicit override.
	if [ -n "${MATRIX_JOBS:-}" ]; then
		case "$MATRIX_JOBS" in
			*[!0-9]*|'') die "MATRIX_JOBS must be a positive integer" ;;
		esac
		if [ "$MATRIX_JOBS" -ge 1 ]; then
			say "$MATRIX_JOBS"
			return 0
		fi
	fi

	# Try to pick up -j from GNU make (MAKEFLAGS is usually exported).
	jobs=""
	prev=""
	for w in ${MAKEFLAGS:-}; do
		if [ "$prev" = "-j" ]; then
			jobs="$w"
			prev=""
			continue
		fi
		case "$w" in
			-j)
				prev="-j"
				;;
			-j*)
				jobs="${w#-j}"
				;;
			--jobs=*)
				jobs="${w#--jobs=}"
				;;
		esac
	done
	case "$jobs" in
		''|*[!0-9]*) jobs="" ;;
	esac
	if [ -n "$jobs" ] && [ "$jobs" -ge 1 ]; then
		say "$jobs"
		return 0
	fi

	# CPU count.
	if have_cmd getconf; then
		jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
		case "$jobs" in
			''|*[!0-9]*) jobs="1" ;;
		esac
		if [ "$jobs" -ge 1 ]; then
			say "$jobs"
			return 0
		fi
	fi
	if have_cmd nproc; then
		jobs="$(nproc 2>/dev/null || echo 1)"
		case "$jobs" in
			''|*[!0-9]*) jobs="1" ;;
		esac
		if [ "$jobs" -ge 1 ]; then
			say "$jobs"
			return 0
		fi
	fi

	say 1
}

# Determine repo root from this script location.
repo_root() {
	# tests/matrix/common.sh -> repo root is ../..
	# shellcheck disable=SC2164
	cd "$(dirname "$0")/../.." && pwd
}

# Default toolchains: monacc + any discovered gcc/clang.
# Users can override by passing explicit args to scripts.
default_toolchains() {
	# Always include monacc first.
	say monacc

	# Prefer versioned gcc if present.
	found_gcc=0
	i=20
	while [ "$i" -ge 4 ]; do
		if have_cmd "gcc-$i"; then
			say "gcc-$i"
			found_gcc=1
		fi
		i=$((i - 1))
	done
	if [ "$found_gcc" -eq 0 ] && have_cmd gcc; then
		say gcc
	fi

	# Prefer versioned clang if present.
	found_clang=0
	i=20
	while [ "$i" -ge 4 ]; do
		if have_cmd "clang-$i"; then
			say "clang-$i"
			found_clang=1
		fi
		i=$((i - 1))
	done
	if [ "$found_clang" -eq 0 ] && have_cmd clang; then
		say clang
	fi
}

# Map toolchain name -> compiler command.
# Returns empty if unsupported.
compiler_for_tc() {
	case "$1" in
		monacc)
			# repo-root relative path expected
			say ./bin/monacc
			;;
		gcc|gcc-*)
			say "$1"
			;;
		clang|clang-*)
			say "$1"
			;;
		*)
			say ""
			;;
	esac
}

# Make a safe-ish directory name for toolchain strings.
# (Keep it simple: accept alnum, dot, dash; map others to underscore.)
tc_dirname() {
	say "$1" | tr -c 'A-Za-z0-9.-_' '_'
}
