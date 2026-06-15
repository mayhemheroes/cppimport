# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile (SMALL form) — builds ON TOP of the org base image
# (ghcr.io/mayhemheroes/base). The base provides debian + clang/llvm + libFuzzer + Python 3 + the
# identities + the build-contract ENV. cppimport (tbenthompson/cppimport) imports C++/pybind11 files
# directly from Python by compiling them with g++ at use time; its test suite therefore needs a C++
# toolchain. The Atheris fuzz harness drives only cppimport's PURE-PYTHON templating layer (no
# compile), so the fuzz target has no native code to sanitize. This image installs the Atheris engine
# plus cppimport and its deps (mako, pybind11, filelock) into the base system Python as root, adds
# gcc/g++/python3-dev for the test suite, then (as non-root `mayhem`) compiles the ELF launcher shims
# and runs the real pytest suite via build.sh / test.sh.
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] \
#       -t cppimport-commit:test .

FROM ghcr.io/mayhemheroes/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); never bake it as ENV — an empty value
# breaks clang. build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH
# Declared for parity with the build contract; the cppimport fuzz target (pure-Python templating)
# has no native code to sanitize.
ARG SANITIZER_FLAGS

# Toolchain for cppimport's runtime compiles (the test suite builds pybind11/C modules with g++).
USER root
RUN apt-get update && apt-get install -yq --no-install-recommends \
      python3-dev python-is-python3 g++ gcc \
    && rm -rf /var/lib/apt/lists/*

# Atheris (the libFuzzer harness engine — builds a native module against the base clang/libFuzzer)
# plus pytest go into the base SYSTEM Python. PEP 668 marks that interpreter externally-managed, so
# --break-system-packages. This is the (networked) install step; build.sh deliberately does NOT
# pip-install, so its offline PATCH-tier re-run stays air-gapped. Atheris is pinned for a
# reproducible engine.
RUN pip install --no-cache-dir --break-system-packages atheris==3.1.0 pytest

# Source enters from the build CONTEXT (the CI checkout): the FULL repo (incl. .git history)
# is copied to /mayhem as `mayhem`; build.sh builds in place.
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

# Install cppimport itself + its runtime deps (mako, pybind11, filelock, setuptools) so the harness
# and the oracle can `import cppimport`. setuptools_scm needs a version; the fork build context has
# no upstream tags, so pin a fallback (no effect on behavior). --no-build-isolation reuses the
# already-installed setuptools/wheel so the build backend needs no network.
RUN SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0 \
    pip install --no-cache-dir --break-system-packages mako pybind11 filelock setuptools wheel \
 && SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0 \
    pip install --no-cache-dir --break-system-packages --no-build-isolation .

USER mayhem

# Compile the ELF launcher shims (Mayhem needs an ELF target, not a .py).
RUN bash mayhem/build.sh

# Run cppimport's real pytest known-answer suite at build time; a failing suite fails the build.
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
