# Lessons

- Compose YAML must escape shell `$vars` as `$$vars` or Compose interpolates them.
- `cp -a src dest` into an existing directory nests as `dest/src`; use `cp -a src/. dest/`.
- Ruff on read-only mounts needs `--no-cache` / `RUFF_CACHE_DIR=/tmp`.
- Lizard 1.24 uses `analyze()`, not `analyze_paths()`.
- Python 3.14 rejects inline `(?i)` mid-pattern; use `re.IGNORECASE`.
- `docker compose run` may not accept `--network none`; use `docker run --network none` for offline verify.
- Report dirs mounted for uid 10001 need host `chmod` writable.
- `install.sh -y` must not auto-pull large default models; skip pull when any Ollama model exists; use `--pull-model` only when Ollama is empty.
