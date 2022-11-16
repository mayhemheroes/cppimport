#!/usr/bin/env python3
import atheris
import io
import sys
import tempfile

from contextlib import contextmanager

from mako.exceptions import CompileException, SyntaxException

with atheris.instrument_imports():
    import cppimport.import_hook
    import cppimport


# Disable stdout
@contextmanager
def nostdout():
    save_stdout = sys.stdout
    save_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    yield
    sys.stdout = save_stdout
    sys.stderr = save_stderr


@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    with tempfile.NamedTemporaryFile('w+') as cpp_file:
        cpp_file.write(fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes()))
        cpp_file.flush()
        try:
            with nostdout():
                cppimport.imp_from_filepath(cpp_file.name)
        except (SystemExit, CompileException, SyntaxException):
            return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
