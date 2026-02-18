# Self-contained build+test script, runnable under ./bin/sh.
# Goal: exercise the self-host ladder without host /bin/sh or coreutils.
# Assumptions: ./bin/monacc exists (bootstrap compiler already built).

BUILD_DIR=build/selfcontained

if ./bin/test -x ./bin/monacc; then
	./bin/true >/dev/null
else
	./bin/echo "selfcontained-build: FAIL: missing ./bin/monacc (run 'make' once to bootstrap)"
	exit 1
fi

./bin/mkdir -p "$BUILD_DIR"
if ./bin/test "$?" = 0; then ./bin/true >/dev/null; else
	./bin/echo "selfcontained-build: FAIL: mkdir $BUILD_DIR"
	exit 1
fi

# Stage 1.
./bin/echo "selfcontained-build: stage1"
./bin/monacc -DSELFHOST -I core -I compiler compiler/mc_compiler.c compiler/monacc_main.c compiler/monacc_front.c compiler/monacc_fmt.c compiler/monacc_elfread.c compiler/monacc_link.c compiler/monacc_elfobj.c compiler/monacc_sys.c compiler/monacc_ast.c compiler/monacc_parse.c compiler/monacc_sema.c compiler/monacc_str.c compiler/monacc_codegen.c compiler/back/x64/emit.c compiler/back/x64/fixup.c compiler/monacc_pp.c compiler/parse/ppexpr.c core/mc_str.c core/mc_fmt.c core/mc_snprint.c core/mc_libc_compat.c core/mc_start_env.c core/mc_io.c core/mc_regex.c -o "$BUILD_DIR/monacc-self"
if ./bin/test "$?" = 0; then ./bin/true >/dev/null; else
	./bin/echo "selfcontained-build: FAIL: build stage1"
	exit 1
fi

# Stage 2.
./bin/echo "selfcontained-build: stage2"
"$BUILD_DIR/monacc-self" --ld ld -DSELFHOST -I core -I compiler compiler/mc_compiler.c compiler/monacc_main.c compiler/monacc_front.c compiler/monacc_fmt.c compiler/monacc_elfread.c compiler/monacc_link.c compiler/monacc_elfobj.c compiler/monacc_sys.c compiler/monacc_ast.c compiler/monacc_parse.c compiler/monacc_sema.c compiler/monacc_str.c compiler/monacc_codegen.c compiler/back/x64/emit.c compiler/back/x64/fixup.c compiler/monacc_pp.c compiler/parse/ppexpr.c core/mc_str.c core/mc_fmt.c core/mc_snprint.c core/mc_libc_compat.c core/mc_start_env.c core/mc_io.c core/mc_regex.c -o "$BUILD_DIR/monacc-self2"
if ./bin/test "$?" = 0; then ./bin/true >/dev/null; else
	./bin/echo "selfcontained-build: FAIL: build stage2"
	exit 1
fi

# Stage 3.
./bin/echo "selfcontained-build: stage3"
"$BUILD_DIR/monacc-self2" --ld ld -DSELFHOST -I core -I compiler compiler/mc_compiler.c compiler/monacc_main.c compiler/monacc_front.c compiler/monacc_fmt.c compiler/monacc_elfread.c compiler/monacc_link.c compiler/monacc_elfobj.c compiler/monacc_sys.c compiler/monacc_ast.c compiler/monacc_parse.c compiler/monacc_sema.c compiler/monacc_str.c compiler/monacc_codegen.c compiler/back/x64/emit.c compiler/back/x64/fixup.c compiler/monacc_pp.c compiler/parse/ppexpr.c core/mc_str.c core/mc_fmt.c core/mc_snprint.c core/mc_libc_compat.c core/mc_start_env.c core/mc_io.c core/mc_regex.c -o "$BUILD_DIR/monacc-self3"
if ./bin/test "$?" = 0; then ./bin/true >/dev/null; else
	./bin/echo "selfcontained-build: FAIL: build stage3"
	exit 1
fi

# Smoke: compile+run a couple of examples with stage3.
./bin/echo "selfcontained-build: stage3 smoke"
"$BUILD_DIR/monacc-self3" examples/hello.c -o "$BUILD_DIR/hello"
if ./bin/test "$?" = 0; then ./bin/true >/dev/null; else
	./bin/echo "selfcontained-build: FAIL: stage3 compile hello"
	exit 1
fi
"$BUILD_DIR/hello" >/dev/null
RC=$?
if ./bin/test "$RC" = 42; then
	./bin/true >/dev/null
else
	./bin/echo "selfcontained-build: FAIL: stage3 hello rc=$RC (expected 42)"
	exit 1
fi

"$BUILD_DIR/monacc-self3" examples/loop.c -o "$BUILD_DIR/loop"
if ./bin/test "$?" = 0; then ./bin/true >/dev/null; else
	./bin/echo "selfcontained-build: FAIL: stage3 compile loop"
	exit 1
fi
"$BUILD_DIR/loop" >/dev/null
RC=$?
if ./bin/test "$RC" = 42; then
	./bin/true >/dev/null
else
	./bin/echo "selfcontained-build: FAIL: stage3 loop rc=$RC (expected 42)"
	exit 1
fi

./bin/echo "selfcontained-build: OK" >/dev/null
exit 0
