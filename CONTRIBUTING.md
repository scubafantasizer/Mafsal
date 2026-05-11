# Contributing to Mafsal

Thank you for your interest in contributing!

## How to contribute

1. Fork the repository and create a feature branch.
2. Make your changes. Keep commits focused and descriptive.
3. Run a quick sanity check:
   ```bash
   python3 -m py_compile mafsal_client.py mafsal_server.py traffic_shaping.py
   ```
4. Open a pull request describing what you changed and why.

## Good first contributions

- `traffic_shaping.py` — tune decoy interval defaults, add tests
- `QUICK_START.md` — add Windows (native) instructions
- Add a `--config` CLI flag to override `TrafficShapingConfig` at launch

## Code style

- Python: PEP 8, type hints where practical
- All comments, docstrings, log messages, and docs in **English**
- GPL-3.0 SPDX header on every new source file

## Security issues

Please do **not** open a public issue for security vulnerabilities.
Open a private GitHub Security Advisory instead.
