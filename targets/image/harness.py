"""Image harness - instrumented for coverage-guided fuzzing."""
import sys

import atheris

with atheris.instrument_imports():
    from PIL import Image  # noqa: F401
    from io import BytesIO  # noqa: F401


def TestOneInput(data: bytes) -> None:
    try:
        from io import BytesIO
        from PIL import Image

        Image.open(BytesIO(data)).verify()
    except Exception:
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
