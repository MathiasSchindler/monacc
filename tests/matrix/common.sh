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

# Default toolchains: monacc + any discovered gcc/clang (including versioned
# gcc-N / clang-N found on PATH).
# Users can override by passing explicit args to scripts, or via MATRIX_TCS.
default_toolchains() {
	# Allow explicit override from the environment.
	# Example: MATRIX_TCS="monacc gcc-15 clang-21"
	if [ -n "${MATRIX_TCS:-}" ]; then
		# Intentionally split on whitespace.
		# shellcheck disable=SC2086
		printf '%s\n' $MATRIX_TCS
		return 0
	fi

	seen=""
	seen_paths=""
	canonical_cmd_path() {
		p="$(command -v "$1" 2>/dev/null || true)"
		[ -n "$p" ] || return 1
		if have_cmd readlink; then
			readlink -f "$p" 2>/dev/null || printf '%s\n' "$p"
		else
			printf '%s\n' "$p"
		fi
	}
	add_tc() {
		case " $seen " in
			*" $1 "*) return 0 ;;
		esac

		# Avoid duplicate work when (for example) gcc and gcc-15 are the same binary.
		# We prefer versioned names by scanning them first.
		case "$1" in
			monacc)
				# Always include monacc first; not deduped by PATH.
				;;
			gcc|gcc-*|clang|clang-*)
				cp="$(canonical_cmd_path "$1" 2>/dev/null || true)"
				[ -n "$cp" ] || return 0
				case " $seen_paths " in
					*" $cp "*) return 0 ;;
				esac
				seen_paths="$seen_paths $cp"
				;;
		esac

		printf '%s\n' "$1"
		seen="$seen $1"
	}

	scan_versioned() {
		prefix="$1"
		old_ifs="$IFS"
		IFS=:
		# shellcheck disable=SC2086
		for d in $PATH; do
			[ -n "$d" ] || continue
			for f in "$d"/"$prefix"-[0-9]*; do
				[ -f "$f" ] || continue
				[ -x "$f" ] || continue
				base=${f##*/}
				add_tc "$base"
			done
		done
		IFS="$old_ifs"
	}

	# Always include monacc first.
	add_tc monacc

	# Discover any versioned compilers present on PATH.
	scan_versioned gcc
	scan_versioned clang

	# Also include unversioned names if present.
	if have_cmd gcc; then add_tc gcc; fi
	if have_cmd clang; then add_tc clang; fi
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
