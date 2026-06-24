# ADVERSA — convenience wrapper around docker compose.
.DEFAULT_GOAL := help
COMPOSE := docker compose

.PHONY: help run full ui up up-graph up-ai down logs ps migrate seed shell test probe-build probe-run clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

run: ## Build + start platform + local probe (API + probe, no frontend) — fast
	@test -f .env || cp .env.docker.example .env
	$(COMPOSE) --profile probe up -d --build
	@port=$$(grep -E '^API_PORT=' .env | cut -d= -f2); port=$${port:-18080}; \
	  echo "API → http://localhost:$$port  (docs: /docs)  |  probe: docker compose logs -f probe"

full: ## Build + start THE WHOLE PROJECT (API + probe + Next.js dashboard). First build is slow.
	@test -f .env || cp .env.docker.example .env
	$(COMPOSE) --profile probe --profile ui up -d --build
	@fport=$$(grep -E '^FRONTEND_PORT=' .env | cut -d= -f2); fport=$${fport:-3000}; \
	  echo "Dashboard → http://localhost:$$fport   (login with SEED_ADMIN_EMAIL / SEED_ADMIN_PASSWORD)"

ui: ## Build + start just the Next.js dashboard (API must be up)
	@test -f .env || cp .env.docker.example .env
	$(COMPOSE) --profile ui up -d --build frontend

up: ## Build + start EVERYTHING incl. the dashboard (postgres, redis, migrate, api, frontend)
	@test -f .env || cp .env.docker.example .env
	$(COMPOSE) --profile ui up -d --build
	@aport=$$(grep -E '^API_PORT=' .env | cut -d= -f2); aport=$${aport:-18080}; \
	 fport=$$(grep -E '^FRONTEND_PORT=' .env | cut -d= -f2); fport=$${fport:-3000}; \
	 echo ""; \
	 echo "  Dashboard  → http://localhost:$$fport         (login with SEED_ADMIN_EMAIL / SEED_ADMIN_PASSWORD)"; \
	 echo "  Simple UI  → http://localhost:$$aport/dashboard"; \
	 echo "  API docs   → http://localhost:$$aport/docs"; \
	 echo "  Probe      → cd probe && ./probe run"

api-only: ## Build + start the platform only (postgres, redis, migrate, api) — no dashboard
	@test -f .env || cp .env.docker.example .env
	$(COMPOSE) up -d --build

up-graph: ## Start the platform + Neo4j (attack-path graph)
	@test -f .env || cp .env.docker.example .env
	NEO4J_ENABLED=true $(COMPOSE) --profile graph up -d --build

up-ai: ## Build with AI/AD extras + start the platform
	@test -f .env || cp .env.docker.example .env
	INSTALL_EXTRAS=1 $(COMPOSE) up -d --build

down: ## Stop all services (keeps volumes)
	$(COMPOSE) --profile graph --profile probe --profile ui down

clean: ## Stop and DELETE volumes (wipes the database)
	$(COMPOSE) --profile graph --profile probe --profile ui down -v

logs: ## Tail API logs
	$(COMPOSE) logs -f api

ps: ## Show service status
	$(COMPOSE) ps

migrate: ## Re-run database migrations
	$(COMPOSE) run --rm migrate alembic upgrade head

seed: ## Re-run the admin seeder
	$(COMPOSE) run --rm migrate python scripts/seed_admin.py

shell: ## Open a shell in the API container
	$(COMPOSE) exec api sh

test: ## Run the backend test suite locally (needs backend/.venv)
	cd backend && ./.venv/bin/python -m pytest -q

probe-build: ## Build the probe image
	$(COMPOSE) build probe

probe-run: ## Start a local probe (joins the stack, self-registers)
	$(COMPOSE) --profile probe up -d probe
