#!/bin/bash
# Health check script for verifying deployed containers are up and running

set -e

# Configuration
COMPOSE_FILE="${1:-compose.yml}"
COMPOSE_PROJECT="${2:-ibc-dev}"
MAX_WAIT_TIME=300  # 5 minutes max wait time
CHECK_INTERVAL=5   # Check every 5 seconds

echo "================================================"
echo "Container Health Check for ${COMPOSE_PROJECT}"
echo "================================================"
echo ""

# Function to check if a container is running
check_container_running() {
    local container_name=$1
    if docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
        return 0
    else
        return 1
    fi
}

# Function to check container health status
check_container_health() {
    local container_name=$1
    local health_status=$(docker inspect --format='{{.State.Health.Status}}' "${container_name}" 2>/dev/null || echo "no-healthcheck")
    
    if [ "${health_status}" = "healthy" ]; then
        return 0
    elif [ "${health_status}" = "no-healthcheck" ]; then
        # If no health check is defined, consider it healthy if running
        if check_container_running "${container_name}"; then
            return 0
        fi
    fi
    return 1
}

# Function to get container status
get_container_status() {
    local container_name=$1
    if ! check_container_running "${container_name}"; then
        echo "NOT_RUNNING"
        return
    fi
    
    local health_status=$(docker inspect --format='{{.State.Health.Status}}' "${container_name}" 2>/dev/null || echo "no-healthcheck")
    if [ "${health_status}" = "no-healthcheck" ]; then
        echo "RUNNING (no healthcheck)"
    else
        echo "${health_status^^}"
    fi
}

# Get list of containers from compose project
echo "Retrieving container list from project: ${COMPOSE_PROJECT}"
containers=$(docker ps --filter "label=com.docker.compose.project=${COMPOSE_PROJECT}" --format '{{.Names}}' 2>/dev/null || echo "")

if [ -z "${containers}" ]; then
    echo "ERROR: No containers found for project '${COMPOSE_PROJECT}'"
    echo "Checking for containers without project filter..."
    echo ""
    docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
    exit 1
fi

echo "Found containers:"
for container in ${containers}; do
    echo "  - ${container}"
done
echo ""

# Wait for all containers to be healthy
echo "Waiting for containers to become healthy (timeout: ${MAX_WAIT_TIME}s)..."
elapsed=0

while [ ${elapsed} -lt ${MAX_WAIT_TIME} ]; do
    all_healthy=true
    
    echo "Check at ${elapsed}s:"
    for container in ${containers}; do
        status=$(get_container_status "${container}")
        echo "  ${container}: ${status}"
        
        if ! check_container_health "${container}"; then
            all_healthy=false
        fi
    done
    echo ""
    
    if [ "${all_healthy}" = true ]; then
        echo "✓ All containers are healthy!"
        echo ""
        
        # Show final status
        echo "Final container status:"
        docker ps --filter "label=com.docker.compose.project=${COMPOSE_PROJECT}" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        echo ""
        
        echo "================================================"
        echo "Health check PASSED"
        echo "================================================"
        exit 0
    fi
    
    sleep ${CHECK_INTERVAL}
    elapsed=$((elapsed + CHECK_INTERVAL))
done

# Timeout reached
echo "✗ Health check FAILED: Timeout reached after ${MAX_WAIT_TIME}s"
echo ""
echo "Final container status:"
for container in ${containers}; do
    status=$(get_container_status "${container}")
    echo "  ${container}: ${status}"
    
    # Show container logs for unhealthy containers
    if ! check_container_health "${container}"; then
        echo ""
        echo "Last 20 lines of logs for ${container}:"
        echo "----------------------------------------"
        docker logs --tail 20 "${container}" 2>&1 || echo "Unable to retrieve logs"
        echo "----------------------------------------"
        echo ""
    fi
done

echo "================================================"
echo "Health check FAILED"
echo "================================================"
exit 1
