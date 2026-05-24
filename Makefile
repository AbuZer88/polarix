.PHONY: dev staging install deploy-staging deploy-prod

install:
	pip install -r backend/requirements.txt

# Local dev — hot reload, port 8000, uses .env (canary.db)
dev:
	set -a && . .env.development && set +a && \
	uvicorn backend.main:app --reload --port 8000

# Local staging simulation — port 8001, uses .env.staging (canary_staging.db)
# Visit: http://localhost:8001  and open dashboard/index.html pointed at :8001
staging:
	set -a && . .env.staging && set +a && \
	uvicorn backend.main:app --port 8001

# Deploy to Railway staging environment
# Requires: railway link (run once), Railway project must have an env named "staging"
deploy-staging:
	railway up --environment staging

# Deploy to Railway production — intentionally verbose, forces a manual step
deploy-prod:
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  Deploying to PRODUCTION. Did you test on staging?"
	@echo "  If yes, run:  railway up --environment production"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
