.PHONY: frontend test vet build dev clean

# Builds the real frontend into internal/web/dist (go:embed needs it).
frontend:
	cd frontend && npm ci && npm run build

# go:embed requires internal/web/dist to exist at compile time -- this
# drops in a stub if the real frontend hasn't been built yet (see
# scripts/ensure-frontend-dist.sh and TESTING.md).
test:
	./scripts/ensure-frontend-dist.sh
	go test -race ./...

vet:
	./scripts/ensure-frontend-dist.sh
	go vet ./...

# Real static binary, real frontend -- same as the Dockerfile's build stage.
build: frontend
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/panel ./cmd/panel

# Self-contained stack (panel + its own Postgres), no host prep -- same as
# README's "just want to try it" quick start.
dev:
	@if [ ! -f .env.standalone ]; then \
		cp .env.standalone.example .env.standalone; \
		echo "Created .env.standalone from the example -- fill in the 4 required values, then rerun 'make dev'."; \
		exit 1; \
	fi
	docker compose -f docker-compose.standalone.yml --env-file .env.standalone up -d --build

clean:
	rm -rf internal/web/dist bin
