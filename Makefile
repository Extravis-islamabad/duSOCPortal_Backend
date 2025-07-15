# Project variables
COMPOSE=docker-compose
PROJECT_NAME=duSOC

# Default target
.DEFAULT_GOAL := help

# Help
help:
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  up              Start all services"
	@echo "  up-build        Build images and start all services"
	@echo "  down            Stop all services"
	@echo "  restart         Restart all services"
	@echo "  restart-backend-services Restart all backend services"
	@echo "  logs            View logs for all services"
	@echo "  logs-backend    View logs for backend"
	@echo "  bash-backend    Shell into backend container"
	@echo "  bash-celery     Shell into celery worker"
	@echo "  ps              Show container status"
	@echo "  prune           Remove unused containers and volumes"
	@echo ""

# Start containers
up:
	$(COMPOSE) up -d

# Build and start
up-build:
	$(COMPOSE) up -d --build

# Stop containers
down:
	$(COMPOSE) down

# Restart
restart: down up

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

# Status
ps:
	$(COMPOSE) ps

# Clean unused
prune:
	docker system prune -f --volumes


restart-backend-services:
	$(COMPOSE) restart backend celery celery-beat celery-intel
