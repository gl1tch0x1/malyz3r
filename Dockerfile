# syntax=docker/dockerfile:1
ARG PYTHON_IMAGE=python:3.13-slim@sha256:57b29a7c050c4e679e4bea572e14b3965cf4b5839de2da49d55e49ffc4024f39
FROM ${PYTHON_IMAGE}

LABEL maintainer="gl1tch0x1"
LABEL description="malyz3r - Advanced YARA Malware Scanner, Workbench and Research Lab with bundled datasets"

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MALYZ3R_LOG_FILE=/app/runs/malyz3r.log \
    MALYZ3R_RULES_DIR=/app/malware_scanner/rules \
    MALYZ3R_DATASETS_DIR=/app/datasets \
    MALYZ3R_CORPUS_DIR=/app/local-corpus \
    MALYZ3R_SAMPLES_DIR=/app/samples \
    RUFF_CACHE_DIR=/tmp/ruff-cache

# Install build & system dependencies if required
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies with pinned constraints
COPY constraints.txt pyproject.toml setup.py requirements.txt /app/
RUN python -m pip install --no-cache-dir -c constraints.txt ".[dev,mcp]"

# Copy versioned dataset metadata and harmless fixtures; mount private corpora at runtime.
COPY datasets/ /app/datasets/
COPY samples/ /app/samples/
COPY policies/ /app/policies/
COPY research_rules/ /app/research_rules/
COPY malware_scanner/ /app/malware_scanner/
COPY tests/ /app/tests/
COPY scripts/ /app/scripts/
COPY run_scanner.py /app/run_scanner.py
COPY *.md /app/

# Install the malyz3r package
RUN python -m pip install --no-cache-dir --no-deps -e .

# Create persistent output and cache directories with proper permissions
RUN mkdir -p /app/runs /app/local-corpus /tmp/ruff-cache && \
    chown -R 10001:10001 /app/runs /app/local-corpus /tmp/ruff-cache

# Verification step: Assert all datasets, corpora, and 50+ YARA rules are properly stored in the image
RUN python -c "\
from pathlib import Path; \
assert Path('/app/datasets').is_dir(), 'Datasets directory missing'; \
assert Path('/app/local-corpus').is_dir(), 'Local corpus directory missing'; \
assert Path('/app/samples').is_dir(), 'Samples directory missing'; \
rules_count = len(list(Path('/app/malware_scanner/rules').glob('*.yar'))); \
assert rules_count >= 50, f'Expected >= 50 rules, found {rules_count}'; \
print(f'Docker image verification successful: {rules_count} YARA rules and all datasets stored.'); \
"

USER 10001:10001

CMD ["malyz3r-workbench", "--help"]
