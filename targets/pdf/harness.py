"""PDF harness - instrumented for coverage-guided fuzzing."""
import sys

import atheris

with atheris.instrument_imports():
    import pymupdf  # noqa: F401


def TestOneInput(data: bytes) -> None:
    try:
        doc = pymupdf.open(stream=data, filetype="pdf")
        if doc.page_count:
            doc.load_page(0)
        doc.close()
    except Exception:
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
