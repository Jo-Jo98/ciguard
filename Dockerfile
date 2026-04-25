FROM python:3.14-slim

LABEL org.opencontainers.image.title="ciguard"
LABEL org.opencontainers.image.description="Static security auditor for CI/CD pipelines"
LABEL org.opencontainers.image.source="https://github.com/Jo-Jo98/ciguard"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

# Install package + deps via pyproject.toml so the `ciguard` CLI entry point
# is available on PATH and the package is importable as `ciguard`.
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
COPY policies/ ./policies/
RUN pip install --no-cache-dir .

# Output volumes
RUN mkdir -p /reports /policies-mount

EXPOSE 8080

# Default: run the web server. Override for CLI use, e.g.:
#   docker run --rm -v $PWD:/work ghcr.io/jo-jo98/ciguard \
#     ciguard scan --input /work/.gitlab-ci.yml --output /work/report.html
CMD ["uvicorn", "ciguard.web.app:app", "--host", "0.0.0.0", "--port", "8080"]
