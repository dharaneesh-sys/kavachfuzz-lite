# KavachFuzz-Lite

Coverage-guided fuzzing for Python-native parsers (Atheris + libFuzzer).

## Quickstart

```bash
uv pip install -e .
kavach --help
kavach init mytarget
kavach fuzz --target pdf --time 60
kavach report serve
```

## Project layout

- `kavach/` — CLI and pipeline (L1-L6)
- `targets/` — target packs (manifest.yaml + harness.py + seeds/)
- `campaigns/` — fuzzing campaigns output
- `tests/` — pytest suite
```
