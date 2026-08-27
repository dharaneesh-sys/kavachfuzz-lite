"""Image deep harness — full-decode for maximum coverage of PIL + C decoders.

Exercises ImageFile parser, JPEG/PNG plugins, EXIF parsing, resize, and split
to hit deeper code paths than the shallow .verify() harness.
"""
import sys

import atheris

with atheris.instrument_imports():
    from PIL import Image  # noqa: F401
    from io import BytesIO  # noqa: F401


def TestOneInput(data: bytes) -> None:
    try:
        from io import BytesIO
        from PIL import Image

        buf = BytesIO(data)
        img = Image.open(buf)
        # Full decode — forces ImageFile._load() through actual plugin decoder
        img.load()
        # EXIF parse — exercises _getexif → TiffImagePlugin
        try:
            img.getexif()
        except Exception:
            pass
        # Resize — forces resampling through C code paths
        try:
            img.resize((4, 4), Image.BILINEAR)
        except Exception:
            pass
        # Split — exercises channel decomposition
        try:
            img.split()
        except Exception:
            pass
    except Exception:
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
