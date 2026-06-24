FROM python:3.12-slim AS base
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# Minimal OS deps: curl for the container healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

FROM base AS deps
# Install the lean core by default; opt into heavy integrations (AI/AD/Neo4j)
# with: docker build --build-arg INSTALL_EXTRAS=1
ARG INSTALL_EXTRAS=0
COPY requirements-core.txt requirements-extras.txt ./
RUN pip install --no-cache-dir -r requirements-core.txt \
    && if [ "$INSTALL_EXTRAS" = "1" ]; then pip install --no-cache-dir -r requirements-extras.txt; fi

FROM deps AS runner
COPY . .

EXPOSE 8000

# Default command serves the API. The compose `migrate` service overrides this
# to run `alembic upgrade head` + seed before the API starts.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
