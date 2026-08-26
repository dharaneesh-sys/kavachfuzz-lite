import atheris
import ctypes
import sys

with atheris.instrument_imports():
    pass  # no heavy imports needed, but keep instrumentation block

def TestOneInput(data: bytes) -> None:
    # Magic trigger: if input starts with b'KAVH', cause genuine SIGSEGV via ctypes that bypasses try/except
    if data.startswith(b'KAVH'):
        ctypes.string_at(0)  # segfault, does NOT raise Python exception, bypasses try/except
    # Otherwise, demonstrate normal path with try/except that swallows only Exception (not BaseException)
    try:
        # no-op, just to show exception swallowing does not affect segfault
        if len(data) == 0:
            raise ValueError("empty")
    except Exception:
        pass

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
