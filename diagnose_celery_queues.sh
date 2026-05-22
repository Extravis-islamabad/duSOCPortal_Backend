#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}Celery Queue Diagnostics and Fix Script${NC}"
echo -e "${GREEN}=========================================${NC}"

COMPOSE_FILE="docker-compose-backend-staging.yml"

# Function to check worker status
check_worker_status() {
    local container=$1
    local queue=$2

    echo -e "\n${YELLOW}Checking $container (Queue: $queue)...${NC}"

    # Check if container is running
    if docker ps --format "table {{.Names}}" | grep -q "$container"; then
        echo -e "${GREEN}✓ Container $container is running${NC}"

        # Check active tasks
        echo "Active tasks:"
        docker exec -it $container celery -A sockportal__backend inspect active 2>/dev/null | head -20

        # Check registered queues
        echo "Registered queues:"
        docker exec -it $container celery -A sockportal__backend inspect active_queues 2>/dev/null | grep -A 5 "queues"

        # Check worker stats
        echo "Worker stats:"
        docker exec -it $container celery -A sockportal__backend inspect stats 2>/dev/null | head -15
    else
        echo -e "${RED}✗ Container $container is not running${NC}"
    fi
}

# Function to properly restart a worker with correct queue binding
restart_worker_with_queue() {
    local service=$1
    local queue=$2

    echo -e "\n${YELLOW}Restarting $service with queue: $queue${NC}"

    # Stop the service
    docker compose -f $COMPOSE_FILE stop $service

    # Remove any stale worker processes
    docker compose -f $COMPOSE_FILE rm -f $service

    # Start the service fresh
    docker compose -f $COMPOSE_FILE up -d $service

    echo -e "${GREEN}✓ $service restarted${NC}"
}

echo -e "\n${YELLOW}=== STEP 1: Current Status ===${NC}"

# Check all workers
check_worker_status "duSOC_Celery_Container" "default"
check_worker_status "duSOC_Celery_Cyware" "cyware"
check_worker_status "duSOC_Celery_Qradar" "qradar"
check_worker_status "duSOC_Celery_Itsm" "itsm"
check_worker_status "duSOC_Celery_Soar" "soar"

echo -e "\n${YELLOW}=== STEP 2: Check for Queue Misrouting ===${NC}"

# Check which worker is processing SOAR tasks
echo -e "\nChecking for SOAR tasks in wrong queues..."
for container in duSOC_Celery_Container duSOC_Celery_Qradar duSOC_Celery_Itsm duSOC_Celery_Cyware; do
    echo -e "\n${YELLOW}Checking $container:${NC}"
    result=$(docker exec -it $container celery -A sockportal__backend inspect active 2>/dev/null | grep -c "cortex_soar_tasks" || echo "0")
    if [ "$result" -gt "0" ]; then
        echo -e "${RED}WARNING: Found $result SOAR tasks in $container!${NC}"
    else
        echo -e "${GREEN}✓ No SOAR tasks found${NC}"
    fi
done

echo -e "\n${YELLOW}=== STEP 3: Fix Options ===${NC}"
echo "1. Quick fix: Restart affected workers"
echo "2. Full fix: Restart all Celery workers and purge queues"
echo "3. Emergency fix: Stop all workers, purge everything, restart"
echo "4. Diagnose only (no changes)"

read -p "Choose an option (1-4): " choice

case $choice in
    1)
        echo -e "\n${YELLOW}Quick fix: Restarting affected workers...${NC}"
        restart_worker_with_queue "celery-qradar" "qradar"
        restart_worker_with_queue "celery-soar" "soar"
        ;;
    2)
        echo -e "\n${YELLOW}Full fix: Restarting all Celery workers...${NC}"

        # Stop all workers
        docker compose -f $COMPOSE_FILE stop celery celery-intel celery-qradar celery-itsm celery-soar celery-beat

        # Purge queues
        echo -e "${YELLOW}Purging queues...${NC}"
        docker compose -f $COMPOSE_FILE exec -T rabbitmq rabbitmqctl purge_queue qradar 2>/dev/null
        docker compose -f $COMPOSE_FILE exec -T rabbitmq rabbitmqctl purge_queue soar 2>/dev/null
        docker compose -f $COMPOSE_FILE exec -T rabbitmq rabbitmqctl purge_queue itsm 2>/dev/null
        docker compose -f $COMPOSE_FILE exec -T rabbitmq rabbitmqctl purge_queue cyware 2>/dev/null

        # Restart all workers
        echo -e "${YELLOW}Starting workers...${NC}"
        docker compose -f $COMPOSE_FILE up -d celery celery-intel celery-qradar celery-itsm celery-soar celery-beat

        # Wait for workers to start
        echo "Waiting for workers to initialize..."
        sleep 10
        ;;
    3)
        echo -e "\n${RED}Emergency fix: Complete reset of Celery workers...${NC}"

        # Stop everything
        docker compose -f $COMPOSE_FILE down

        # Remove volumes (optional - uncomment if needed)
        # docker volume prune -f

        # Restart everything
        docker compose -f $COMPOSE_FILE up -d

        echo "Waiting for services to start..."
        sleep 15
        ;;
    4)
        echo -e "\n${GREEN}Diagnosis complete. No changes made.${NC}"
        ;;
    *)
        echo -e "${RED}Invalid option${NC}"
        exit 1
        ;;
esac

echo -e "\n${YELLOW}=== STEP 4: Verification ===${NC}"

# Verify the fix
if [ "$choice" != "4" ]; then
    echo "Waiting for workers to stabilize..."
    sleep 5

    echo -e "\n${YELLOW}Verifying queue assignments...${NC}"

    # Check QRadar worker
    echo -e "\n${YELLOW}QRadar Worker:${NC}"
    docker exec -it duSOC_Celery_Qradar celery -A sockportal__backend inspect active_queues 2>/dev/null | grep -A 3 "qradar"

    # Check SOAR worker
    echo -e "\n${YELLOW}SOAR Worker:${NC}"
    docker exec -it duSOC_Celery_Soar celery -A sockportal__backend inspect active_queues 2>/dev/null | grep -A 3 "soar"

    # Final check for misrouted tasks
    echo -e "\n${YELLOW}Final check for misrouted SOAR tasks...${NC}"
    result=$(docker exec -it duSOC_Celery_Qradar celery -A sockportal__backend inspect active 2>/dev/null | grep -c "cortex_soar_tasks" || echo "0")
    if [ "$result" -eq "0" ]; then
        echo -e "${GREEN}✓ SUCCESS: No SOAR tasks in QRadar worker${NC}"
    else
        echo -e "${RED}✗ WARNING: Still found $result SOAR tasks in QRadar worker${NC}"
        echo "You may need to run option 3 (Emergency fix)"
    fi
fi

echo -e "\n${GREEN}=========================================${NC}"
echo -e "${GREEN}Diagnostics Complete${NC}"
echo -e "${GREEN}=========================================${NC}"

# Show summary
echo -e "\n${YELLOW}Queue Status Summary:${NC}"
docker compose -f $COMPOSE_FILE exec -T rabbitmq rabbitmqctl list_queues name messages 2>/dev/null || echo "Could not list queues"
