# Contributing to antaris-guard

## Getting Started

```bash
git clone https://github.com/Antaris-Analytics/antaris-guard.git
cd antaris-guard
pip install -e ".[dev]"
python -m pytest tests/ -v
```

## Running Tests

```bash
python -m pytest tests/ -v
```

All 43 tests must pass before submitting changes.

## Code Style

- Python 3.9+ compatible
- Zero external dependencies in core package
- All detection is deterministic (no model calls, no network)
- Follow existing code patterns

## Submitting Changes

1. Fork the repo
2. Create a branch (`git checkout -b fix/my-fix`)
3. Make changes and add tests
4. Run `python -m pytest tests/ -v`
5. Submit a pull request

## Reporting Security Issues

If you find a security vulnerability, please email dev@antarisanalytics.com instead of opening a public issue.
