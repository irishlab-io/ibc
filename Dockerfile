# Build stage
FROM docker.io/python:3.10.11-bullseye AS builder

COPY --from=ghcr.io/astral-sh/uv:0.9.18@sha256:5713fa8217f92b80223bc83aac7db36ec80a84437dbc0d04bbc659cae030d8c9 /uv /usr/local/bin/uv

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV UV_COMPILE_BYTECODE=1
ENV VIRTUAL_ENV=/app/.venv

WORKDIR /app

COPY requirements.txt .

RUN apt-get update && \
  apt-get install -y --no-install-recommends build-essential libffi-dev && \
  rm -rf /var/lib/apt/lists/*

RUN uv venv /app/.venv

RUN uv pip install --no-cache-dir -r requirements.txt
RUN uv pip install --no-cache-dir httplib2==0.14.0 pycrypto==2.6.1 urllib3==1.24.3

# Runtime stage
FROM docker.io/python:3.10.11-bullseye AS runtime

ARG GIT_COMMIT="unknown"
ARG REPO_URL=""

ENV GIT_COMMIT=${GIT_COMMIT}
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV REPO_URL=${REPO_URL}

WORKDIR /app

RUN groupadd --system appgroup && useradd --system --no-create-home --gid appgroup appuser

RUN apt-get update && \
  apt-get install -y --no-install-recommends curl libffi-dev tini && \
  rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/.venv /app/.venv

COPY src /app/src
COPY manage.py /app/manage.py

RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 8000

RUN python manage.py migrate

HEALTHCHECK --interval=10s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/login || exit 1

ENTRYPOINT ["tini", "--"]
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
