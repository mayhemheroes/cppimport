#!/usr/bin/env python3
import atheris
import io
import sys
import logging

from contextlib import contextmanager

from mako.exceptions import CompileException, SyntaxException

with atheris.instrument_imports():
    import cppimport.import_hook
    import cppimport

logging.disable(logging.ERROR)

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


file_name = '/tmp/somecode.cpp'
cpp_file = open(file_name, 'w+')


@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    cpp_file.truncate(0)
    cpp_file.write(fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes()))
    cpp_file.flush()

    try:
        with nostdout():
            cppimport.imp_from_filepath(file_name)
    except (SystemExit, ImportError, CompileException, SyntaxException):
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
