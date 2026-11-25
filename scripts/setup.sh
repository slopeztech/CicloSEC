#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
TEMP_ENV=""

cleanup() {
    if [[ -n "$TEMP_ENV" && -e "$TEMP_ENV" ]]; then
        rm -- "$TEMP_ENV"
    fi
}
trap cleanup EXIT

MODE="native"
if [[ "${1:-}" == "--docker" && "$#" -eq 1 ]]; then
    MODE="docker"
elif [[ "$#" -ne 0 ]]; then
    echo "Usage: bash scripts/setup.sh [--docker]" >&2
    exit 2
fi

die() {
    echo "Setup failed: $*" >&2
    exit 1
}

new_secret() {
    od -An -N48 -tx1 /dev/urandom | tr -d ' \n'
}

initialize_local_files() {
    if [[ ! -f .env ]]; then
        local database_password django_secret
        database_password="$(new_secret)"
        django_secret="$(new_secret)"
        TEMP_ENV=".env.bootstrap.$$"
        sed \
            -e "s|replace-with-a-local-only-password|${database_password}|" \
            -e "s|replace-with-a-generated-local-secret|${django_secret}|" \
            .env.example > "$TEMP_ENV"
        mv -- "$TEMP_ENV" .env
        TEMP_ENV=""
        chmod 600 .env
        echo "Created .env with newly generated local-only secrets."
    elif grep -Fq 'replace-with-a-local-only-password' .env ||
        grep -Fq 'replace-with-a-generated-local-secret' .env; then
        die ".env contains example placeholders. Replace them locally; setup will not overwrite an existing .env."
    fi

    if [[ ! -f config/ciclosec.yaml ]]; then
        cp config/ciclosec.yaml.example config/ciclosec.yaml
        echo "Created config/ciclosec.yaml without enabling on-demand scans."
    fi
}

check_docker() {
    command -v docker >/dev/null 2>&1 ||
        die "Docker CLI is required. Install Docker Desktop/Engine with Compose, then rerun setup."
    docker info >/dev/null 2>&1 ||
        die "Docker is installed but its daemon is unavailable. Start Docker Desktop/Engine and rerun setup."
    docker compose version ||
        die "Docker Compose is required. Install the Docker Compose plugin and rerun setup."
}

wait_for_local_services() {
    local attempt postgres_ready redis_ready
    attempt=0
    while (( attempt < 60 )); do
        if docker compose exec -T postgres \
            sh -c 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"' >/dev/null 2>&1; then
            postgres_ready=true
        else
            postgres_ready=false
        fi
        if docker compose exec -T redis redis-cli ping >/dev/null 2>&1; then
            redis_ready=true
        else
            redis_ready=false
        fi
        if [[ "$postgres_ready" == true && "$redis_ready" == true ]]; then
            return
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    die "PostgreSQL and Redis did not become ready. Inspect them with 'docker compose ps' and 'docker compose logs postgres redis'."
}

install_uv() {
    if command -v uv >/dev/null 2>&1; then
        return
    fi
    if command -v curl >/dev/null 2>&1; then
        curl -LsSf https://astral.sh/uv/install.sh | sh
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- https://astral.sh/uv/install.sh | sh
    else
        die "curl or wget is required to install uv from Astral's official installer."
    fi
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
    command -v uv >/dev/null 2>&1 || die "uv installer completed but uv is not on PATH."
}

initialize_local_files
check_docker

if [[ "$MODE" == "docker" ]]; then
    docker compose --profile app up --build -d
    web_ready=false
    for attempt in {1..60}; do
        if docker compose exec -T web python -c \
            "import socket; socket.create_connection(('127.0.0.1', 8000), timeout=2).close()" \
            >/dev/null 2>&1; then
            web_ready=true
            break
        fi
        sleep 2
    done
    worker_ready=false
    for attempt in {1..60}; do
        if worker_logs=$(docker compose --profile app logs --no-color --tail 100 worker 2>/dev/null) &&
            grep -Eq 'ready\.' <<< "$worker_logs"; then
            worker_ready=true
            break
        fi
        sleep 2
    done
    [[ "$worker_ready" == true ]] ||
        die "The Docker worker did not report readiness. Inspect 'docker compose --profile app logs worker'."
    docker compose --profile app exec -T worker trivy --version
    docker compose --profile app exec -T worker osv-scanner --version
    docker compose --profile app exec -T web python manage.py check
    docker compose --profile app ps
    [[ "$web_ready" == true ]] ||
        die "The Docker web service did not become ready. Inspect 'docker compose --profile app logs web worker migrate'."
    web_port="$(sed -n 's/^CICLOSEC_WEB_PORT=//p' .env | head -n 1)"
    echo "Docker setup is ready at http://127.0.0.1:${web_port:-8000}/"
    echo "Create a local account with: docker compose exec web python manage.py createsuperuser"
    exit 0
fi

install_uv
uv python install 3.12
uv sync --locked
uv run --no-sync python scripts/install_scanners.py
docker compose up -d postgres redis
wait_for_local_services
uv run --no-sync python manage.py migrate --noinput
uv run --no-sync python manage.py check

echo "Native setup is ready. Python dependencies and scanners are installed in the project environment."
echo "Start the web process with: uv run python manage.py runserver 127.0.0.1:8000"
echo "Start a worker with: uv run celery -A ciclosec.project.celery:app worker --loglevel INFO"
echo "Create a local account with: uv run python manage.py createsuperuser"
