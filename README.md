# Insecure Bank Corporation

## Running the application locally

1. Build and run the application:

   ```bash
   uv venv .venv --python 3.10
   uv sync --all-extras --dev --frozen
   python src/manage.py migrate
   python src/manage.py runserver
   ```

2. You can then access the bank application here: <http://localhost:8000>

## Running with Docker

1. Build and run the application with Docker.

   ```bash
   docker build \
     --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) \
     --build-arg REPO_URL=$(git config --get remote.origin.url | sed 's/git@/https:\/\//; s/.com:/.com\//; s/\.git$//') \
     --file Dockerfile --no-cache --tag ibc .
   docker stop ibc && docker rm ibc
   docker run --detach --publish 8000:8000 --name ibc ibc
   docker logs ibc
   ```

2. Open the application here: <http://localhost:8000>

## Running with Docker Compose

1. Start the application stack:

   ```bash
   docker compose up -d
   ```

2. Verify all containers are healthy:

   ```bash
   ./scripts/health_check.sh compose.yml ibc
   ```

3. Access the application at <http://localhost:8000>

## Login credentials

```text
Username: guillaume
Password: timinou
```

## Health Checks

The application includes built-in health checks at multiple levels:

- **Dockerfile**: Built-in health check (already present) that verifies the `/login` endpoint responds
- **Docker Compose**: Health check configuration added for the `ibc` service for orchestration visibility
- **CD Pipeline**: New automated health check script after deployment to ensure all containers are running

The health check script (`scripts/health_check.sh`) added in this PR verifies:
- All containers in the compose project are running
- Containers with health checks are in a healthy state
- Provides detailed logs if health checks fail

