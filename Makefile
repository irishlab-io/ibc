.PHONY: help

help:
	@echo "Usage:"
	@echo "  make all                Setup & Run"
	@echo "  make build              Build the package wheel"
	@echo "  make check              CI: Lint the code"
	@echo "  make docker             Build & Run the container"
	@echo "  make format             CI: Format the code"
	@echo "  make publish            Publish package"
	@echo "  make pytest             CI: Run test and calculate coverage"
	@echo "  make run                Run the package"
	@echo "  make setup              Create the venv and install dependencies"
	@echo "  make sync               UV: Sync all dependencies"
	@echo "  make type               CI: Check typing"

all:
	$(MAKE) setup
	$(MAKE) sync
	$(MAKE) pytest
	$(MAKE) build
	$(MAKE) docker-build
	$(MAKE) run

docker:
	$(MAKE) docker-clean
	$(MAKE) docker-build
	$(MAKE) docker-run

talk:
	$(MAKE) docker-quick
	$(MAKE) sbom-generate
	$(MAKE) sbom-analyse
	$(MAKE) sbom-push

run:
	$(MAKE) migrate
	$(MAKE) flight-check
	$(MAKE) runserver

build:
	uv build

docker-build:
	docker build \
     --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) \
     --build-arg REPO_URL=$(git config --get remote.origin.url | sed 's/git@/https:\/\//; s/.com:/.com\//; s/\.git$//') \
     --file Dockerfile --no-cache --tag ibc .

docker-clean:
	docker stop ibc && docker rm ibc

docker-quick:
	docker build --file Dockerfile --tag ibc .

docker-run:
	docker run --detach --publish 8000:8000 --name ibc ibc

check:
	uv run ruff check $$(git diff --name-only --cached -- '*.py')

format:
	uv run ruff format $$(git diff --name-only --cached -- '*.py')

flight-check:
	uv run python manage.py check

pytest:
	uv run pytest

migrate:
	uv run python manage.py migrate

runserver:
	uv run python manage.py runserver

sbom-analyse:
	grype sbom:sbom.json

sbom-generate:
	syft scan ibc --output cyclonedx-json=sbom.json

sbom-push:
	dtrack-cli --server https://dependencytrack.local.irishlab.io --api-key ${DEPENDENCYTRACK_TOKEN} --project-name "A-demo-test" --project-version "0.0.1" --bom-path sbom.json --auto-create true

setup:
	uv venv .venv --python 3.10 --clear

sync:
	uv sync --all-extras --all-packages

type:
	uv run ty check $$(git diff --name-only --cached -- '*.py')
