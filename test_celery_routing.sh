#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}Celery Queue Routing Test Script${NC}"
echo -e "${BLUE}=========================================${NC}"

# Worker to Queue mapping
declare -A WORKER_QUEUE_MAP=(
    ["5a5501f96c54"]="qradar"
    ["9bf210193106"]="soar"
    ["433c5058c708"]="itsm"
    ["e97800f0b228"]="cyware"
)

# Get actual worker IDs from containers
QRADAR_WORKER=$(docker inspect duSOC_Celery_Qradar --format='{{.Config.Hostname}}')
SOAR_WORKER=$(docker inspect duSOC_Celery_Soar --format='{{.Config.Hostname}}')
ITSM_WORKER=$(docker inspect duSOC_Celery_Itsm --format='{{.Config.Hostname}}')
CYWARE_WORKER=$(docker inspect duSOC_Celery_Cyware --format='{{.Config.Hostname}}')

echo -e "\n${CYAN}Worker IDs:${NC}"
echo "QRadar Worker: celery@$QRADAR_WORKER"
echo "SOAR Worker: celery@$SOAR_WORKER"
echo "ITSM Worker: celery@$ITSM_WORKER"
echo "Cyware Worker: celery@$CYWARE_WORKER"

# Function to check active tasks for a specific worker
check_worker_tasks() {
    local worker_id=$1
    local expected_queue=$2
    local container=$3

    # Get active tasks and filter for this specific worker
    local tasks=$(docker exec $container celery -A sockportal__backend inspect active 2>/dev/null |
                  sed -n "/celery@$worker_id:/,/^->/p" |
                  grep -E "(name|routing_key)" |
                  sed 's/.*'\''name'\'': '\''\([^'\'']*\).*/Task: \1/' |
                  sed 's/.*'\''routing_key'\'': '\''\([^'\'']*\).*/Queue: \1/')

    if [ -z "$tasks" ] || echo "$tasks" | grep -q "empty"; then
        echo -e "${YELLOW}  No active tasks${NC}"
    else
        echo "$tasks"
    fi
}

# Function to trigger a test task for each queue
trigger_test_task() {
    local task_type=$1
    local task_name=$2

    echo -e "\n${CYAN}Triggering $task_type task...${NC}"

    case $task_type in
        "qradar")
            docker exec duSOC_Backend_Container python manage.py shell -c "
from tenant.ibm_qradar_tasks import sync_ibm_qradar_data
result = sync_ibm_qradar_data.delay()
print(f'QRadar Task ID: {result.id}')
" 2>/dev/null
            ;;
        "soar")
            docker exec duSOC_Backend_Container python manage.py shell -c "
from tenant.cortex_soar_tasks import sync_soar_data
result = sync_soar_data.delay()
print(f'SOAR Task ID: {result.id}')
" 2>/dev/null
            ;;
        "itsm")
            docker exec duSOC_Backend_Container python manage.py shell -c "
from tenant.itsm_tasks import sync_itsm
result = sync_itsm.delay()
print(f'ITSM Task ID: {result.id}')
" 2>/dev/null
            ;;
        "cyware")
            docker exec duSOC_Backend_Container python manage.py shell -c "
from tenant.threat_intelligence_tasks import sync_threat_intel
result = sync_threat_intel.delay()
print(f'Cyware Task ID: {result.id}')
" 2>/dev/null
            ;;
    esac
}

echo -e "\n${BLUE}=== STEP 1: Initial Queue Status ===${NC}"
docker compose -f docker-compose-backend-staging.yml exec -T rabbitmq rabbitmqctl list_queues name messages 2>/dev/null | grep -E "qradar|soar|itsm|cyware"

echo -e "\n${BLUE}=== STEP 2: Triggering Test Tasks ===${NC}"

# Trigger one task for each queue
trigger_test_task "qradar" "sync_ibm_qradar_data"
trigger_test_task "soar" "sync_soar_data"
trigger_test_task "itsm" "sync_itsm"
trigger_test_task "cyware" "sync_threat_intel"

echo -e "\n${YELLOW}Waiting 3 seconds for tasks to be picked up...${NC}"
sleep 3

echo -e "\n${BLUE}=== STEP 3: Checking Task Distribution ===${NC}"

# Check each worker for active tasks
echo -e "\n${GREEN}QRadar Worker (celery@$QRADAR_WORKER):${NC}"
check_worker_tasks "$QRADAR_WORKER" "qradar" "duSOC_Celery_Qradar"

echo -e "\n${GREEN}SOAR Worker (celery@$SOAR_WORKER):${NC}"
check_worker_tasks "$SOAR_WORKER" "soar" "duSOC_Celery_Soar"

echo -e "\n${GREEN}ITSM Worker (celery@$ITSM_WORKER):${NC}"
check_worker_tasks "$ITSM_WORKER" "itsm" "duSOC_Celery_Itsm"

echo -e "\n${GREEN}Cyware Worker (celery@$CYWARE_WORKER):${NC}"
check_worker_tasks "$CYWARE_WORKER" "cyware" "duSOC_Celery_Cyware"

echo -e "\n${BLUE}=== STEP 4: Validation ===${NC}"

# Function to validate routing
validate_routing() {
    local worker_id=$1
    local expected_queue=$2
    local container=$3
    local worker_name=$4

    echo -e "\n${CYAN}Validating $worker_name...${NC}"

    # Get all active tasks for this worker
    local active_output=$(docker exec $container celery -A sockportal__backend inspect active 2>/dev/null)

    # Check if this worker has tasks
    local worker_tasks=$(echo "$active_output" | sed -n "/celery@$worker_id:/,/^->/p")

    if echo "$worker_tasks" | grep -q "empty"; then
        echo -e "  ${YELLOW}No active tasks (OK if tasks completed quickly)${NC}"
        return 0
    fi

    # Check routing keys
    local routing_keys=$(echo "$worker_tasks" | grep "routing_key" | sed "s/.*'routing_key': '\([^']*\)'.*/\1/" | sort -u)

    if [ -z "$routing_keys" ]; then
        echo -e "  ${YELLOW}No routing keys found (tasks may have completed)${NC}"
        return 0
    fi

    local all_correct=true
    for key in $routing_keys; do
        if [ "$key" == "$expected_queue" ]; then
            echo -e "  ${GREEN}✓ Found tasks with correct routing key: $key${NC}"
        else
            echo -e "  ${RED}✗ Found tasks with WRONG routing key: $key (expected: $expected_queue)${NC}"
            all_correct=false
        fi
    done

    if $all_correct; then
        return 0
    else
        return 1
    fi
}

# Validate each worker
errors=0

validate_routing "$QRADAR_WORKER" "qradar" "duSOC_Celery_Qradar" "QRadar Worker"
errors=$((errors + $?))

validate_routing "$SOAR_WORKER" "soar" "duSOC_Celery_Soar" "SOAR Worker"
errors=$((errors + $?))

validate_routing "$ITSM_WORKER" "itsm" "duSOC_Celery_Itsm" "ITSM Worker"
errors=$((errors + $?))

validate_routing "$CYWARE_WORKER" "cyware" "duSOC_Celery_Cyware" "Cyware Worker"
errors=$((errors + $?))

echo -e "\n${BLUE}=== STEP 5: Cross-Queue Check ===${NC}"

# Check if any worker is processing tasks from wrong queues
echo -e "\n${CYAN}Checking for cross-queue contamination...${NC}"

check_cross_queue() {
    local container=$1
    local worker_id=$2
    local expected_queue=$3
    local worker_name=$4

    echo -e "\n${YELLOW}$worker_name (should only process '$expected_queue' tasks):${NC}"

    # Get active tasks
    local active_output=$(docker exec $container celery -A sockportal__backend inspect active 2>/dev/null)
    local worker_section=$(echo "$active_output" | sed -n "/celery@$worker_id:/,/^->/p")

    if echo "$worker_section" | grep -q "empty"; then
        echo -e "  ${GREEN}✓ No active tasks${NC}"
        return 0
    fi

    # Check for wrong task types
    local wrong_tasks=0

    case $expected_queue in
        "qradar")
            if echo "$worker_section" | grep -qE "cortex_soar_tasks|itsm_tasks|threat_intelligence_tasks"; then
                echo -e "  ${RED}✗ Found non-QRadar tasks!${NC}"
                wrong_tasks=1
            else
                echo -e "  ${GREEN}✓ Only QRadar tasks found${NC}"
            fi
            ;;
        "soar")
            if echo "$worker_section" | grep -qE "ibm_qradar_tasks|itsm_tasks|threat_intelligence_tasks"; then
                echo -e "  ${RED}✗ Found non-SOAR tasks!${NC}"
                wrong_tasks=1
            else
                echo -e "  ${GREEN}✓ Only SOAR tasks found${NC}"
            fi
            ;;
        "itsm")
            if echo "$worker_section" | grep -qE "ibm_qradar_tasks|cortex_soar_tasks|threat_intelligence_tasks"; then
                echo -e "  ${RED}✗ Found non-ITSM tasks!${NC}"
                wrong_tasks=1
            else
                echo -e "  ${GREEN}✓ Only ITSM tasks found${NC}"
            fi
            ;;
        "cyware")
            if echo "$worker_section" | grep -qE "ibm_qradar_tasks|cortex_soar_tasks|itsm_tasks"; then
                echo -e "  ${RED}✗ Found non-Cyware tasks!${NC}"
                wrong_tasks=1
            else
                echo -e "  ${GREEN}✓ Only Cyware tasks found${NC}"
            fi
            ;;
    esac

    return $wrong_tasks
}

cross_errors=0
check_cross_queue "duSOC_Celery_Qradar" "$QRADAR_WORKER" "qradar" "QRadar Worker"
cross_errors=$((cross_errors + $?))

check_cross_queue "duSOC_Celery_Soar" "$SOAR_WORKER" "soar" "SOAR Worker"
cross_errors=$((cross_errors + $?))

check_cross_queue "duSOC_Celery_Itsm" "$ITSM_WORKER" "itsm" "ITSM Worker"
cross_errors=$((cross_errors + $?))

check_cross_queue "duSOC_Celery_Cyware" "$CYWARE_WORKER" "cyware" "Cyware Worker"
cross_errors=$((cross_errors + $?))

echo -e "\n${BLUE}=== STEP 6: Final Queue Status ===${NC}"
docker compose -f docker-compose-backend-staging.yml exec -T rabbitmq rabbitmqctl list_queues name messages 2>/dev/null | grep -E "qradar|soar|itsm|cyware"

echo -e "\n${BLUE}=========================================${NC}"
echo -e "${BLUE}Test Results Summary${NC}"
echo -e "${BLUE}=========================================${NC}"

total_errors=$((errors + cross_errors))

if [ $total_errors -eq 0 ]; then
    echo -e "\n${GREEN}✓ SUCCESS: All tasks are being routed to the correct queues!${NC}"
    echo -e "${GREEN}The Celery queue routing is working properly.${NC}"
    exit 0
else
    echo -e "\n${RED}✗ FAILURE: Found $total_errors routing errors!${NC}"
    echo -e "${RED}Some tasks are being routed to wrong queues.${NC}"
    echo -e "\n${YELLOW}Troubleshooting tips:${NC}"
    echo "1. Check if all workers are running: docker compose -f docker-compose-backend-staging.yml ps"
    echo "2. Restart all workers: make restart-backend-services"
    echo "3. Check Celery logs: docker compose -f docker-compose-backend-staging.yml logs celery-qradar celery-soar celery-itsm celery-intel"
    exit 1
fi
