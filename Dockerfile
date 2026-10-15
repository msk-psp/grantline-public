FROM python:3.13-slim@sha256:bb2988715db2cf7ace7b53f38f3cffbef7c7046a656bee66245eb0ed386e2e81

LABEL org.opencontainers.image.source="https://github.com/msk-psp/grantline-public" \
      org.opencontainers.image.description="Untangle access. Follow the grants. PostgreSQL, ClickHouse and S3 permission console." \
      org.opencontainers.image.licenses="Apache-2.0"
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY grantline ./grantline
RUN pip install --no-cache-dir '.[postgres]' \
    && groupadd --gid 10001 grantline \
    && useradd --uid 10001 --gid grantline --create-home grantline
COPY --chown=10001:10001 examples/demo ./demo
USER 10001:10001
EXPOSE 8420
ENTRYPOINT ["grantline"]
CMD ["-c", "/app/demo/grantline.toml", "serve", "--host", "0.0.0.0", "--port", "8420"]
