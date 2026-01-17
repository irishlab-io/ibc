---
hide:
  - toc
---

# Testing Overview

The [pytest](https://github.com/pytest-dev/pytest) framework makes it easy to write small tests yet scales to support complex functional testing.
A couple of add-ons are installed (`pytest-cov`, `pytest-django`, `pytest-mock`, `pytest-xdist`) to improve the experience.

The project includes a comprehensive test suite organized by test type:

```bash
tests/
├── e2e/               # End-to-end tests using Playwright
├── integration/       # Integration tests for component interactions
├── load/              # Load testing scripts using k6
├── security/          # Security vulnerability tests
└── unit/              # Unit tests for individual components
```

This project uses [pytest-xdist](https://github.com/pytest-dev/pytest-xdist), a pytest plugin for distributed testing and loop-on-failures modes. `pytest-xdist` shards your test suite across all available CPU cores for faster performance. Sometimes it can generate flaky tests, but it’s rare. Just re-run the tests and you should be fine.

There is a minimal set of e2e tests using [Playwright](https://playwright.dev/).

## Running Tests

Execute the complete test suite:

```bash
uv run playwright install --with-deps       # Install additional playwright dependencies
uv run pytest                               # Run the whole test suite
uv run pytest tests/unit/test_models.py     # Run a single test file
uv run pytest --cov=src                     # Generate code coverage reports
uv run pytest -m unit                       # Specific marker
```

## Load Testing

Load tests validate application performance and stability under various load conditions. See [tests/load/README.md](../../tests/load/README.md) for detailed information.

Load tests are automatically executed in the CD pipeline for the dev environment and include:

- **Workload Stability Test**: Tests constant moderate load (5 minutes)
- **Peak Load Test**: Tests traffic spikes and peak usage (5 minutes)
- **Soak Test**: Tests sustained load over extended periods (10 minutes)

To run load tests locally:

```bash
# Install k6 first (see tests/load/README.md)
k6 run tests/load/workload-stability.js
k6 run tests/load/peak-load.js
k6 run tests/load/soak-test.js
```
