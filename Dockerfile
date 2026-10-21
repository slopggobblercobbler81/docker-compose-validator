# syntax=docker/dockerfile:1
FROM python:3.11-slim AS builder

WORKDIR /build
COPY . /build
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.11-slim AS runner

WORKDIR /app
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

# Run as non-root user for DevSecOps best practices
USER 10001:10001

ENTRYPOINT ["docker-compose-validator"]
CMD ["--help"]
