#!/usr/bin/python3
"""run_tests.py — RUN cppimport's own pytest suite and print a parseable summary.

Invoked via the /mayhem/cppimport-tests ELF launcher (NOT directly), so the verify-repo sabotage
oracle can neuter the launcher and prove the test oracle is behavioral: cppimport's suite
(tests/test_cppimport.py) is a set of known-answer cases that actually compile + import pybind11/C
modules with g++/gcc and assert their behavior (mymodule.square, extra sources, package imports,
raw C extensions, rebuild-on-change, import hooks, template rendering), so a no-op / exit(0) /
behavior-altering patch to cppimport cannot pass it.

The suite references fixtures by CWD-relative paths (e.g. cppimport.imp_from_filepath(
"tests/mymodule.cpp")), so we chdir to the repo root first. cppimport compiles the fixtures at
runtime, so we pin the toolchain to gcc/g++ (installed in the image).
"""
from __future__ import annotations

import os
import sys
import xml.etree.ElementTree as ET

import pytest

SRC = os.environ.get("SRC", "/mayhem")
XML = "/tmp/cppimport-junit.xml"
TESTS_DIR = "tests"

# cppimport compiles the pybind11/C fixtures at test time; pin the toolchain to gcc/g++.
os.environ.setdefault("CC", "gcc")
os.environ.setdefault("CXX", "g++")


def main() -> int:
    os.chdir(SRC)
    pytest.main(["-q", "-p", "no:cacheprovider", TESTS_DIR, "--junitxml", XML])

    root = ET.parse(XML).getroot()
    suites = root.findall("testsuite") or ([root] if root.tag == "testsuite" else [])
    if not suites:
        print("RUNTESTS tests=0 passed=0 failed=1 skipped=0")
        return 1

    tests = failed = skipped = 0
    for s in suites:
        tests += int(s.get("tests", 0))
        failed += int(s.get("failures", 0)) + int(s.get("errors", 0))
        skipped += int(s.get("skipped", 0))
    passed = tests - failed - skipped

    print(f"RUNTESTS tests={tests} passed={passed} failed={failed} skipped={skipped}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
