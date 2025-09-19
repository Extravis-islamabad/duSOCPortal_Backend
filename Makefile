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
	@echo "  build-backend             Build backend Docker image"
	@echo "  deploy-backend            Build and deploy backend services, then prune"
	@echo "  restart-backend-services  Restart backend, celery, celery-beat, celery-intel"
	@echo "  logs                      View logs for all services"
	@echo "  logs-backend              View logs for backend"
	@echo "  bash-backend              Shell into backend container"
	@echo "  bash-celery               Shell into celery worker"
	@echo "  ps                        Show container status"
	@echo ""

# Build backend image
build-backend:
	sudo docker build -t backend-api:latest .

# Deploy backend services
deploy-backend: build-backend
	$(COMPOSE) up -d backend celery celery-beat celery-intel celery-qradar celery-itsm celery-soar redis rabbitmq

# Restart backend-related services only
restart-backend-services:
	$(COMPOSE) restart backend celery celery-beat celery-intel celery-qradar celery-itsm celery-soar

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
