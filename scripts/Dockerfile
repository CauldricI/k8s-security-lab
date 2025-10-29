# Intentionally uses a common base to produce some findings for demo purposes.
FROM python:3.11-slim

# App user (non-root)
RUN useradd -u 10001 appuser
USER appuser

# Minimal app
WORKDIR /app
COPY --chown=appuser:appuser . /app
CMD ["python", "-c", "print('hello from demo image')"]
