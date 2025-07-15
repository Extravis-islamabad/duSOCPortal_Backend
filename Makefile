# Project variables
COMPOSE=docker compose -f docker-compose-backend-staging.yml
PROJECT_NAME=duSOC

# Default target
.DEFAULT_GOAL := help

# Help
help:
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  restart-backend-services  Restart backend, celery, celery-beat, celery-intel"
	@echo "  logs                      View logs for all services"
	@echo "  logs-backend              View logs for backend"
	@echo "  bash-backend              Shell into backend container"
	@echo "  bash-celery               Shell into celery worker"
	@echo "  ps                        Show container status"
	@echo ""

# Start containers


# Restart backend-related services only
restart-backend-services:
	$(COMPOSE) restart backend celery celery-beat celery-intel

# Logs
logs:
	$(COMPOSE) logs -f --tail=100

logs-backend:
	$(COMPOSE) logs -f backend

# Shell Access
bash-backend:
	$(COMPOSE) exec backend sh

bash-celery:
	$(COMPOSE) exec celery sh

# Container status
ps:
	$(COMPOSE) ps
