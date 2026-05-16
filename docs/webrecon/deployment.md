# Deployment

`webrecon` is a regular Python package; any deployment that runs
Python 3.10+ will host it. This guide describes the three patterns
the project ships templates for: PyPI, Docker, and systemd.

## PyPI / wheel

The project's `pyproject.toml` declares both `binchecker` and
`webrecon` console scripts. Build a wheel with:

```bash
pip install build
python -m build
ls dist/
```

The resulting wheel can be uploaded to PyPI with `twine upload` once
project metadata is finalised.

Editable installs are the recommended development workflow:

```bash
pip install -e ".[dev]"
```

## Docker

A reference `Dockerfile` for production runs:

```dockerfile
# Dockerfile
FROM python:3.12-slim AS base

# Install system deps for lxml + cryptography wheels.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libxml2-dev libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/webrecon
COPY pyproject.toml ./
COPY webrecon/ ./webrecon/
COPY binchecker/ ./binchecker/

RUN pip install --no-cache-dir .

# Run as a non-root user.
RUN useradd -m -u 10001 webrecon
USER webrecon
WORKDIR /home/webrecon

# Mount /home/webrecon/.env for credentials, /var/lib/webrecon for the DB.
VOLUME ["/home/webrecon", "/var/lib/webrecon"]

ENTRYPOINT ["webrecon"]
CMD ["--help"]
```

Build and run:

```bash
docker build -t webrecon:latest -f Dockerfile .
docker run --rm \
    -v "$PWD/.env:/home/webrecon/.env:ro" \
    -v "webrecon-data:/var/lib/webrecon" \
    -e WEBRECON_DATABASE__PATH=/var/lib/webrecon/webrecon.sqlite3 \
    webrecon:latest discover --source serper --query "site:example.com"
```

The image runs as UID 10001 by default. Bind-mount your `.env` and
let the container persist the asset database to a named volume.

## Systemd

Run a recurring discovery sweep on a fixed schedule:

```ini
# /etc/systemd/system/webrecon-discover.service
[Unit]
Description=webrecon recurring discovery sweep
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=webrecon
EnvironmentFile=/etc/webrecon/.env
WorkingDirectory=/var/lib/webrecon
ExecStart=/usr/local/bin/webrecon discover --source all --save
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/webrecon-discover.timer
[Unit]
Description=Trigger webrecon discovery every 6 hours

[Timer]
OnCalendar=*-*-* 00,06,12,18:00:00
RandomizedDelaySec=15min
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
systemctl enable --now webrecon-discover.timer
systemctl list-timers | grep webrecon
journalctl -u webrecon-discover.service --since "1h ago"
```

## CI

A minimal GitHub Actions workflow:

```yaml
# .github/workflows/webrecon-ci.yml
name: webrecon CI

on:
  push:
    branches: [main]
    paths: ["webrecon/**", "tests/webrecon/**", "pyproject.toml"]
  pull_request:
    paths: ["webrecon/**", "tests/webrecon/**", "pyproject.toml"]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
      - run: pip install -e ".[dev]"
      - run: ruff check webrecon
      - run: mypy -p webrecon
      - run: pytest tests/webrecon -q
```

Run the same three commands locally before pushing -- the CI is just
a guard, not a substitute for local verification.

## Operational checklist

Before running webrecon against real targets:

1. **Authorisation**: confirm written permission to scan the targets.
2. **Rate limits**: review `WEBRECON_RATE_LIMITING__*` defaults; lower
   them if you are scanning a small / shared infrastructure.
3. **Safety guards**: leave `TEST_MODE` and `REQUIRE_CONFIRMATION`
   enabled unless a specific runbook documents why they should be off.
4. **Storage**: point `WEBRECON_DATABASE__PATH` at a persistent
   volume; the asset database is the system of record.
5. **Logging**: route `webrecon`'s structured logs to your central
   log aggregator (the `redact_sensitive_processor` masks API keys
   before render).
