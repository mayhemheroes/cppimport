#!/usr/bin/env python3
"""Atheris harness for cppimport's PURE templating / config-extraction layer.

Old fork target ``import-fuzz`` drove ``cppimport.imp_from_filepath`` which runs
the FULL pipeline: templating -> C++ compile (g++/pybind11) -> dlopen. The
compile step needs a C++ toolchain and is far too slow / unsuitable for
fuzzing, so we narrow scope to the honest pure-Python sub-step that runs
*before* any compilation:

    setup_module_data(...)  ->  run_templating(module_data)

``run_templating`` (cppimport/templating.py) is the text-processing layer: it
locates the source file, runs it through Mako (which extracts and executes the
embedded ``<% ... %>`` cppimport config block), builds the ``BuildArgs`` cfg
dict, invokes ``setup_pybind11``, computes the rendered-source path and writes
the rendered output. This is real upstream code; only the trailing g++ invoke
is skipped. Target name ``import-fuzz`` is preserved for parity.
"""
import sys
import os
import tempfile

import atheris

import fuzz_helpers

with atheris.instrument_imports():
    import cppimport
    import cppimport.templating
    from cppimport.importer import setup_module_data

import mako.exceptions

# Build everything inside a single scratch dir so Mako's TemplateLookup (which
# is rooted at the file's directory) only ever sees our fuzz file.
_SCRATCH = tempfile.mkdtemp(prefix="cppimport-fuzz-")
_CPP_PATH = os.path.join(_SCRATCH, "fuzzmod.cpp")

# Exceptions that are NORMAL outcomes of feeding arbitrary text through Mako.
# Mako compiles the ``<% ... %>`` block to Python and executes it, then
# re-raises whatever that user-controlled code raised. cppimport itself does
# not promise these inputs are valid, so they are expected parse/eval noise --
# not bugs in cppimport. Anything outside this set propagates as a real crash.
_EXPECTED = (
    mako.exceptions.MakoException,  # CompileException / SyntaxException / etc.
    SyntaxError,
    ValueError,
    KeyError,
    IndexError,
    AttributeError,
    TypeError,
    NameError,
    ImportError,
    RecursionError,
    UnicodeError,
    OverflowError,
    ZeroDivisionError,
    ArithmeticError,
    LookupError,
)


@atheris.instrument_func
def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    src = fdp.ConsumeRemainingBytes()

    # Write fuzzed bytes to the .cpp the templating layer will read.
    with open(_CPP_PATH, "wb") as f:
        f.write(src)

    module_data = setup_module_data("fuzzmod", _CPP_PATH)
    try:
        cppimport.templating.run_templating(module_data)
    except _EXPECTED:
        return -1
    finally:
        # run_templating writes ".rendered.fuzzmod.cpp"; clean it up.
        rendered = cppimport.templating.get_rendered_source_filepath(_CPP_PATH)
        try:
            os.remove(rendered)
        except OSError:
            pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
