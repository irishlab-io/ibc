# Load Testing

This directory contains load testing scripts for the IBC (Insecure Bank Corporation) application. The tests are implemented using [k6](https://k6.io/), a modern load testing tool designed for developer workflows and CI/CD integration.

## Test Types

### 1. Workload Stability Test (`workload-stability.js`)

**Purpose:** Validates that the application can handle constant moderate load without performance degradation.

**Profile:**
- Duration: 5 minutes
- Virtual Users: 1 → 10 → 10 → 0
- Stages:
  - Ramp up: 1 minute (1 to 10 users)
  - Sustain: 3 minutes (10 users)
  - Ramp down: 1 minute (10 to 0 users)

**Success Criteria:**
- 95% of requests complete in < 2 seconds
- Error rate < 1%

### 2. Peak Load Test (`peak-load.js`)

**Purpose:** Validates that the application can handle traffic spikes during high-usage periods.

**Profile:**
- Duration: 5 minutes
- Virtual Users: 1 → 50 → 50 → 0
- Stages:
  - Ramp up: 2 minutes (1 to 50 users)
  - Sustain: 2 minutes (50 users)
  - Ramp down: 1 minute (50 to 0 users)

**Success Criteria:**
- 90% of requests complete in < 5 seconds
- Error rate < 5%

### 3. Soak Test (`soak-test.js`)

**Purpose:** Validates that the application can handle sustained load over extended periods without memory leaks or resource exhaustion.

**Profile:**
- Duration: 10 minutes
- Virtual Users: 1 → 20 → 20 → 0
- Stages:
  - Ramp up: 2 minutes (1 to 20 users)
  - Sustain: 6 minutes (20 users) - **soak period**
  - Ramp down: 2 minutes (20 to 0 users)

**Success Criteria:**
- 95% of requests complete in < 3 seconds
- Error rate < 2%
- No performance degradation over time

## Running Load Tests Locally

### Prerequisites

Install k6:
```bash
# macOS
brew install k6

# Linux
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update
sudo apt-get install k6

# Windows
choco install k6
```

### Run Tests

1. Start the application:
   ```bash
   python src/manage.py runserver
   # or with Docker
   docker run --detach --publish 8000:8000 --name ibc ibc
   ```

2. Run a specific test:
   ```bash
   # Workload stability test
   k6 run tests/load/workload-stability.js

   # Peak load test
   k6 run tests/load/peak-load.js

   # Soak test
   k6 run tests/load/soak-test.js
   ```

3. Run with custom base URL:
   ```bash
   k6 run -e BASE_URL=http://localhost:8000 tests/load/workload-stability.js
   ```

## CI/CD Integration

Load tests are automatically executed in the CD pipeline for the **dev environment** after successful deployment. This validates that:

1. The deployed application is stable under normal load
2. The application can handle peak traffic spikes
3. The application doesn't degrade over extended usage periods

### When Tests Run

- **Trigger:** After deployment to dev environment
- **Frequency:** Every deployment to dev
- **Environment:** Deployed dev application
- **Duration:** ~20 minutes total for all three test types

### Failure Handling

If load tests fail:
- The pipeline will continue (tests are non-blocking)
- Warnings will be logged for investigation
- Review the test summary output for details

## Test Metrics

Each test tracks and reports:
- **Total Requests:** Number of HTTP requests made
- **Response Times:** Average, min, max, and percentiles
- **Error Rate:** Percentage of failed requests
- **Custom Metrics:** Test-specific measurements

## Best Practices

1. **Baseline Performance:** Run tests locally first to establish baseline performance
2. **Iterative Testing:** Start with lower load and gradually increase
3. **Monitor Resources:** Watch CPU, memory, and database connections during tests
4. **Analyze Trends:** Compare results over time to detect performance regressions
5. **Test Realistic Scenarios:** Update tests to reflect actual user behavior patterns

## Troubleshooting

### Tests Fail Immediately
- Check that the application is running and accessible
- Verify the BASE_URL is correct
- Check firewall/network connectivity

### High Error Rates
- Review application logs for errors
- Check database connection pool settings
- Verify resource limits (CPU, memory)

### Slow Response Times
- Profile the application to identify bottlenecks
- Check database query performance
- Review caching configuration
- Monitor server resource utilization

## Future Improvements

- Add authentication flow testing
- Implement transaction scenarios (transfers, account management)
- Add database load testing
- Implement stress testing (beyond peak load)
- Add breakpoint testing (find maximum capacity)
- Integrate with monitoring/observability tools
