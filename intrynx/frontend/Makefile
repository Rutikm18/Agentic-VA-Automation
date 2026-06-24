# ─────────────────────────────────────────────────────────────────────────────
#  ADVERSA Platform — Makefile
# ─────────────────────────────────────────────────────────────────────────────
#  Usage:  make <target>
#  Tip:    Copy .env.example → .env.local and set ANTHROPIC_API_KEY
# ─────────────────────────────────────────────────────────────────────────────

IMAGE_NAME  ?= adversa
IMAGE_TAG   ?= latest
CONTAINER   ?= adversa-prod
PORT        ?= 3000
DEV_PORT    ?= 3001

# Load .env.local automatically (silently ignore if missing)
-include .env.local
export

.DEFAULT_GOAL := help

# Detect docker compose v2 vs v1
COMPOSE := $(shell docker compose version > /dev/null 2>&1 && echo "docker compose" || echo "docker-compose")

# ─────────────────────────────────────────────────────────────────────────────
# Help
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: help
help: ## Show all available targets
	@printf '\n'
	@printf '  \033[1;36mADVERSA Platform\033[0m — Makefile targets\n'
	@printf '\n'
	@printf '  \033[1mLocal Development\033[0m\n'
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
	  grep -vE '(docker|Docker|image|Image|compose|Compose|prune|Prune)' | \
	  awk 'BEGIN {FS=":.*##"}; {printf "    \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@printf '\n'
	@printf '  \033[1mDocker — Single Container\033[0m\n'
	@grep -E '^docker-[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS=":.*##"}; {printf "    \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@printf '\n'
	@printf '  \033[1mDocker Compose\033[0m\n'
	@grep -E '^(up|down|dev-up|dev-down|logs|shell|prune)[a-zA-Z_-]*:.*##' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS=":.*##"}; {printf "    \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@printf '\n'

# ─────────────────────────────────────────────────────────────────────────────
# Local Development
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: install
install: ## Install Node.js dependencies
	npm install

.PHONY: dev
dev: ## Start local dev server with hot reload (http://localhost:3000)
	npm run dev

.PHONY: build
build: ## Build the production Next.js bundle (standalone mode)
	npm run build

.PHONY: start
start: build ## Build then start the production Node.js server locally
	npm run start

.PHONY: typecheck
typecheck: ## Run TypeScript type checking (no emit)
	npx tsc --noEmit

.PHONY: lint
lint: ## Run ESLint across all source files
	npm run lint

.PHONY: lint-fix
lint-fix: ## Run ESLint and auto-fix fixable issues
	npm run lint -- --fix

.PHONY: clean
clean: ## Remove .next build output and out/ static export
	rm -rf .next out
	@echo "Build artifacts removed."

.PHONY: clean-all
clean-all: clean ## Remove .next, out/, and node_modules
	rm -rf node_modules
	@echo "node_modules removed."

# ─────────────────────────────────────────────────────────────────────────────
# Docker — Single Container
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: docker-build
docker-build: ## Build the production Docker image
	@echo "→ Building $(IMAGE_NAME):$(IMAGE_TAG) ..."
	docker build \
	  --tag $(IMAGE_NAME):$(IMAGE_TAG) \
	  --tag $(IMAGE_NAME):latest \
	  --file Dockerfile \
	  .
	@echo ""
	@echo "✓ Image ready: $(IMAGE_NAME):$(IMAGE_TAG)"
	@echo "  Run:  make docker-run"

.PHONY: docker-build-no-cache
docker-build-no-cache: ## Force-rebuild Docker image without layer cache
	docker build \
	  --no-cache \
	  --tag $(IMAGE_NAME):$(IMAGE_TAG) \
	  --tag $(IMAGE_NAME):latest \
	  --file Dockerfile \
	  .

.PHONY: docker-run
docker-run: ## Run the production container (detached, port $(PORT))
	@docker stop $(CONTAINER) 2>/dev/null || true
	@docker rm   $(CONTAINER) 2>/dev/null || true
	@echo "→ Starting $(CONTAINER) on http://localhost:$(PORT) ..."
	docker run -d \
	  --name $(CONTAINER) \
	  --publish $(PORT):3000 \
	  --env-file .env.local \
	  --restart unless-stopped \
	  $(IMAGE_NAME):$(IMAGE_TAG)
	@echo ""
	@echo "✓ Container running: http://localhost:$(PORT)"
	@echo "  Logs:  make docker-logs"
	@echo "  Stop:  make docker-stop"

.PHONY: docker-run-it
docker-run-it: ## Run the container interactively (foreground)
	docker run --rm -it \
	  --name $(CONTAINER)-it \
	  --publish $(PORT):3000 \
	  --env-file .env.local \
	  $(IMAGE_NAME):$(IMAGE_TAG)

.PHONY: docker-stop
docker-stop: ## Stop and remove the production container
	@docker stop $(CONTAINER) 2>/dev/null && echo "✓ Stopped $(CONTAINER)" || echo "  (not running)"
	@docker rm   $(CONTAINER) 2>/dev/null && echo "✓ Removed $(CONTAINER)" || true

.PHONY: docker-logs
docker-logs: ## Tail logs from the running container
	docker logs -f $(CONTAINER)

.PHONY: docker-shell
docker-shell: ## Open a shell inside the running container
	docker exec -it $(CONTAINER) sh

.PHONY: docker-inspect
docker-inspect: ## Show image layers and size breakdown
	docker image inspect $(IMAGE_NAME):$(IMAGE_TAG) | \
	  python3 -c "import sys,json; d=json.load(sys.stdin)[0]; print('ID:', d['Id'][:19]); print('Size:', round(d['Size']/1e6,1), 'MB'); print('Layers:', len(d['RootFS']['Layers']))"

# ─────────────────────────────────────────────────────────────────────────────
# Docker Compose
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: up
up: ## Build and start the production stack (http://localhost:$(PORT))
	$(COMPOSE) --profile prod up --build -d
	@echo ""
	@echo "✓ Production stack running: http://localhost:$(PORT)"
	@echo "  Logs:   make logs"
	@echo "  Stop:   make down"

.PHONY: down
down: ## Stop and remove all compose containers
	$(COMPOSE) --profile prod --profile dev down
	@echo "✓ All services stopped."

.PHONY: dev-up
dev-up: ## Start the development stack with hot reload (http://localhost:$(DEV_PORT))
	$(COMPOSE) --profile dev up --build
# Runs in foreground so Ctrl+C stops it cleanly

.PHONY: dev-down
dev-down: ## Stop the development compose stack
	$(COMPOSE) --profile dev down

.PHONY: restart
restart: down up ## Restart the production stack

.PHONY: logs
logs: ## Follow compose service logs (all services)
	$(COMPOSE) logs -f

.PHONY: logs-prod
logs-prod: ## Follow logs for the production service only
	$(COMPOSE) logs -f adversa

.PHONY: logs-dev
logs-dev: ## Follow logs for the development service only
	$(COMPOSE) logs -f adversa-dev

.PHONY: shell
shell: ## Open a shell inside the running production compose container
	$(COMPOSE) exec adversa sh

.PHONY: ps
ps: ## Show running compose services
	$(COMPOSE) ps

# ─────────────────────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: docker-clean
docker-clean: docker-stop ## Remove the local Docker image
	docker rmi $(IMAGE_NAME):$(IMAGE_TAG) $(IMAGE_NAME):latest 2>/dev/null || true
	$(COMPOSE) down --rmi local 2>/dev/null || true
	@echo "✓ Images removed."

.PHONY: prune
prune: ## Prune ALL unused Docker resources (images, volumes, networks)
	docker system prune -f
	docker volume prune -f
	@echo "✓ Docker pruned."

# ─────────────────────────────────────────────────────────────────────────────
# CI helpers
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: ci
ci: install typecheck lint build ## Full CI pipeline: install → typecheck → lint → build
	@echo ""
	@echo "✓ CI pipeline passed."

.PHONY: ci-docker
ci-docker: ci docker-build ## CI pipeline + Docker image build
	@echo ""
	@echo "✓ Docker image built: $(IMAGE_NAME):$(IMAGE_TAG)"
