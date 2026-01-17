/**
 * Peak Load Test
 * 
 * This test validates that the application can handle peak traffic spikes
 * that might occur during high-usage periods (e.g., end of month, promotions).
 * 
 * Test Profile:
 * - Duration: 5 minutes
 * - Virtual Users: Ramps from 1 to 50 users over 2 minutes, maintains 50 users for 2 minutes, ramps down to 0 over 1 minute
 * - Success Criteria: 90% of requests should complete in under 5 seconds with <5% error rate
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const requestCounter = new Counter('total_requests');
const failedRequests = new Counter('failed_requests');

// Test configuration
export const options = {
  stages: [
    { duration: '2m', target: 50 },  // Ramp up to 50 users over 2 minutes
    { duration: '2m', target: 50 },  // Stay at 50 users for 2 minutes
    { duration: '1m', target: 0 },   // Ramp down to 0 users over 1 minute
  ],
  thresholds: {
    http_req_duration: ['p(90)<5000'], // 90% of requests should be below 5s
    errors: ['rate<0.05'],              // Error rate should be less than 5%
    http_req_failed: ['rate<0.05'],     // HTTP errors should be less than 5%
  },
};

// Base URL from environment variable with default
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';

export default function () {
  requestCounter.add(1);

  // Test homepage
  let res = http.get(`${BASE_URL}/`, {
    timeout: '10s',
  });
  
  const homepageSuccess = check(res, {
    'homepage status is 200': (r) => r.status === 200,
    'homepage response time < 5s': (r) => r.timings.duration < 5000,
  });

  if (!homepageSuccess) {
    errorRate.add(1);
    failedRequests.add(1);
  }

  sleep(0.5);

  // Test login page
  res = http.get(`${BASE_URL}/login/`, {
    timeout: '10s',
  });
  
  const loginSuccess = check(res, {
    'login page status is 200': (r) => r.status === 200,
  });

  if (!loginSuccess) {
    errorRate.add(1);
    failedRequests.add(1);
  }

  sleep(1);

  // Test accounts page (should redirect to login if not authenticated)
  res = http.get(`${BASE_URL}/accounts/`, {
    timeout: '10s',
  });
  
  const accountsSuccess = check(res, {
    'accounts page responds': (r) => r.status === 200 || r.status === 302,
  });

  if (!accountsSuccess) {
    errorRate.add(1);
    failedRequests.add(1);
  }

  sleep(0.5);
}

export function handleSummary(data) {
  return {
    'stdout': textSummary(data, { indent: ' ', enableColors: true }),
  };
}

function textSummary(data, options) {
  const indent = options.indent || '';
  
  let summary = '\n\n';
  summary += indent + '=== Peak Load Test Summary ===\n\n';
  
  if (data.metrics.http_reqs) {
    summary += indent + `Total Requests: ${data.metrics.http_reqs.values.count}\n`;
  }
  
  if (data.metrics.http_req_duration) {
    summary += indent + `Average Response Time: ${data.metrics.http_req_duration.values.avg.toFixed(2)}ms\n`;
    summary += indent + `90th Percentile: ${data.metrics.http_req_duration.values['p(90)'].toFixed(2)}ms\n`;
    summary += indent + `95th Percentile: ${data.metrics.http_req_duration.values['p(95)'].toFixed(2)}ms\n`;
    summary += indent + `Max Response Time: ${data.metrics.http_req_duration.values.max.toFixed(2)}ms\n`;
  }
  
  if (data.metrics.http_req_failed) {
    summary += indent + `Request Failure Rate: ${(data.metrics.http_req_failed.values.rate * 100).toFixed(2)}%\n`;
  }
  
  if (data.metrics.errors) {
    summary += indent + `Error Rate: ${(data.metrics.errors.values.rate * 100).toFixed(2)}%\n`;
  }
  
  if (data.metrics.total_requests) {
    summary += indent + `Custom Total Requests: ${data.metrics.total_requests.values.count}\n`;
  }
  
  if (data.metrics.failed_requests) {
    summary += indent + `Custom Failed Requests: ${data.metrics.failed_requests.values.count}\n`;
  }
  
  summary += '\n';
  
  return summary;
}
