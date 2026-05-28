# Contributing to OBSIDIOS

## Code of Conduct

Be respectful, constructive, and professional. This is a security research project — focus on the code, not the person.

## How to Contribute

### Reporting Bugs

Open a GitHub issue with:
- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error output (with sensitive data redacted)

### Suggesting Features

Open a GitHub issue with:
- What the feature does
- Why it's useful
- Any implementation ideas

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Make your changes
4. Test that the project still runs: `python3 obsidios.py --help`
5. Commit with a clear message
6. Push and open a PR

## Code Style

- Python 3.11+ with type hints (`from __future__ import annotations`)
- Use `loguru` for logging (not `print`)
- Async-first: use `async/await`, avoid blocking calls in async contexts
- SQL: use parameterized queries (`?` placeholders), never f-string interpolation
- Imports: standard library, third-party, local — grouped with blank lines

## Project Structure

Keep changes within the appropriate subsystem module:
- `iris/` — scanning and discovery
- `oracle/` — AI and intelligence
- `phantom/` — attack paths
- `forge/` — rule generation
- `sentinel/` — IDS
- `shield/` — defense
- `echo/` — drift detection
- `chronicle/` — database
- `dashboard/` — web UI
- `config/` — settings

## Testing

There is a test suite in `tests/`. Run with:

```bash
python3 -m pytest tests/
```

For manual testing, use a lab environment — do not run against production networks without authorization.

## Security

If you find a security vulnerability, do **not** open a public issue. See [SECURITY.md](SECURITY.md).