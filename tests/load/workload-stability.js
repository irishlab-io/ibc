/**
 * Workload Stability Test
 * 
 * This test validates that the application can handle a constant moderate load
 * without degrading performance or failing. It simulates typical production
 * traffic patterns.
 * 
 * Test Profile:
 * - Duration: 5 minutes
 * - Virtual Users: Ramps from 1 to 10 users over 1 minute, maintains 10 users for 3 minutes, ramps down to 0 over 1 minute
 * - Success Criteria: 95% of requests should complete in under 2 seconds with <1% error rate
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const loginDuration = new Trend('login_duration');

// Test configuration
export const options = {
  stages: [
    { duration: '1m', target: 10 },  // Ramp up to 10 users over 1 minute
    { duration: '3m', target: 10 },  // Stay at 10 users for 3 minutes
    { duration: '1m', target: 0 },   // Ramp down to 0 users over 1 minute
  ],
  thresholds: {
    http_req_duration: ['p(95)<2000'], // 95% of requests should be below 2s
    errors: ['rate<0.01'],              // Error rate should be less than 1%
    http_req_failed: ['rate<0.01'],     // HTTP errors should be less than 1%
  },
};

// Base URL from environment variable with default
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';

export default function () {
  // Test homepage
  let res = http.get(`${BASE_URL}/`);
  
  check(res, {
    'homepage status is 200': (r) => r.status === 200,
    'homepage response time < 2s': (r) => r.timings.duration < 2000,
  }) || errorRate.add(1);

  sleep(1);

  // Test login page
  res = http.get(`${BASE_URL}/login/`);
  
  check(res, {
    'login page status is 200': (r) => r.status === 200,
    'login page has form': (r) => r.body.includes('username') && r.body.includes('password'),
  }) || errorRate.add(1);

  sleep(2);

  // Test static assets
  res = http.get(`${BASE_URL}/static/css/styles.css`);
  
  check(res, {
    'static assets load': (r) => r.status === 200 || r.status === 404, // 404 is acceptable for missing assets
  }) || errorRate.add(1);

  sleep(1);
}

export function handleSummary(data) {
  return {
    'stdout': textSummary(data, { indent: ' ', enableColors: true }),
  };
}

function textSummary(data, options) {
  const indent = options.indent || '';
  const enableColors = options.enableColors || false;
  
  let summary = '\n\n';
  summary += indent + '=== Workload Stability Test Summary ===\n\n';
  
  if (data.metrics.http_reqs) {
    summary += indent + `Total Requests: ${data.metrics.http_reqs.values.count}\n`;
  }
  
  if (data.metrics.http_req_duration) {
    summary += indent + `Average Response Time: ${data.metrics.http_req_duration.values.avg.toFixed(2)}ms\n`;
    summary += indent + `95th Percentile: ${data.metrics.http_req_duration.values['p(95)'].toFixed(2)}ms\n`;
  }
  
  if (data.metrics.http_req_failed) {
    summary += indent + `Request Failure Rate: ${(data.metrics.http_req_failed.values.rate * 100).toFixed(2)}%\n`;
  }
  
  if (data.metrics.errors) {
    summary += indent + `Error Rate: ${(data.metrics.errors.values.rate * 100).toFixed(2)}%\n`;
  }
  
  summary += '\n';
  
  return summary;
}
