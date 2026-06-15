#!/usr/bin/env bash
#
# cppimport/mayhem/build.sh — compile the ELF launcher shims for the Atheris fuzz harness and the
# pytest oracle runner.
#
# cppimport (tbenthompson/cppimport) compiles C++/pybind11 modules at *use* time; the full pipeline
# (template -> g++ compile -> dlopen) is far too slow / toolchain-bound to fuzz. The Atheris harness
# (mayhem/fuzz_import.py) therefore drives only the PURE-PYTHON templating sub-step
# (setup_module_data -> cppimport.templating.run_templating) that runs BEFORE any compilation — real
# upstream code, no native module built by the harness. So there is nothing here to sanitize.
#
# Mayhem requires every target `cmd:` to be an ELF (it rejects a shebang/script wrapper and
# fuzz-smoke.sh checks the ELF magic), so we compile a tiny C shim per Python entry point that
# exec()s `python3 <script>` (see mayhem/launcher.c). The Python deps (atheris, cppimport + mako +
# pybind11, pytest) are installed into the image system Python by the Dockerfile (root + network);
# this script does NOT pip-install, so its offline PATCH-tier re-run (non-root `mayhem`, --network
# none) stays idempotent + air-gapped: it only compiles the shims (clang, no network).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

SRC="${SRC:-/mayhem}"
cd "$SRC"

: "${CC:=clang}"

# $DEBUG_FLAGS threads DWARF < 4 debug info onto the shims (SPEC §6.2 item 10): clang-19's plain
# `-g` emits DWARF-5, which Mayhem's triage can't read, so force DWARF-3 explicitly.
: "${DEBUG_FLAGS:=-gdwarf-3}"

# cppimport's fuzzed code (the Mako templating layer) is pure Python, run under Atheris/libFuzzer at
# runtime; the shims are pure exec() wrappers (sanitizing them would only add ASan noise on the
# wrapper, never on the fuzzed Python). Referenced for parity / so an override is visible.
echo "SANITIZER_FLAGS=${SANITIZER_FLAGS:-<unset>} (pure-Python fuzz target; not applied to the exec shims)"
echo "DEBUG_FLAGS=$DEBUG_FLAGS"

build_launcher() {
  local out="$1" script="$2"
  echo "--- compiling launcher /mayhem/$out -> $script ---"
  # Dynamically linked (default) so the verify-repo sabotage oracle's LD_PRELOAD can reach it.
  "$CC" $DEBUG_FLAGS -O1 -DPY_SCRIPT="\"$script\"" -o "/mayhem/$out" mayhem/launcher.c
  chmod +x "/mayhem/$out"
}

# Fuzz target: the preserved Atheris harness (cppimport templating layer). Name kept for parity.
build_launcher import-fuzz    /mayhem/mayhem/fuzz_import.py
# Test oracle runner: runs cppimport's real pytest suite (driven by mayhem/test.sh through this ELF
# so the sabotage check can neuter it).
build_launcher cppimport-tests /mayhem/mayhem/run_tests.py

echo "build.sh complete:"
ls -la /mayhem/import-fuzz /mayhem/cppimport-tests
