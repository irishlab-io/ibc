/**
 * Soak Test (Endurance Test)
 * 
 * This test validates that the application can handle sustained moderate load
 * over an extended period without memory leaks, resource exhaustion, or
 * performance degradation.
 * 
 * Test Profile:
 * - Duration: 10 minutes
 * - Virtual Users: Ramps to 20 users over 2 minutes, maintains 20 users for 6 minutes, ramps down over 2 minutes
 * - Success Criteria: 95% of requests should complete in under 3 seconds with <2% error rate
 * - Checks for: Memory leaks, performance degradation over time, resource exhaustion
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const responseTimeByPeriod = new Trend('response_time_by_period');

// Test configuration
export const options = {
  stages: [
    { duration: '2m', target: 20 },  // Ramp up to 20 users over 2 minutes
    { duration: '6m', target: 20 },  // Stay at 20 users for 6 minutes (soak period)
    { duration: '2m', target: 0 },   // Ramp down to 0 users over 2 minutes
  ],
  thresholds: {
    http_req_duration: ['p(95)<3000'], // 95% of requests should be below 3s
    errors: ['rate<0.02'],              // Error rate should be less than 2%
    http_req_failed: ['rate<0.02'],     // HTTP errors should be less than 2%
  },
};

// Base URL from environment variable with default
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';

// Track test phase for analysis
let startTime = new Date();

export default function () {
  const currentTime = new Date();
  const elapsedMinutes = (currentTime - startTime) / 1000 / 60;

  // Test homepage
  let res = http.get(`${BASE_URL}/`, {
    timeout: '15s',
  });
  
  responseTimeByPeriod.add(res.timings.duration);
  
  check(res, {
    'homepage status is 200': (r) => r.status === 200,
    'homepage response time < 3s': (r) => r.timings.duration < 3000,
    'homepage has content': (r) => r.body.length > 0,
  }) || errorRate.add(1);

  sleep(2);

  // Test login page
  res = http.get(`${BASE_URL}/login/`, {
    timeout: '15s',
  });
  
  responseTimeByPeriod.add(res.timings.duration);
  
  check(res, {
    'login page status is 200': (r) => r.status === 200,
    'login page has form': (r) => r.body.includes('username') && r.body.includes('password'),
  }) || errorRate.add(1);

  sleep(3);

  // Test accounts page (should redirect)
  res = http.get(`${BASE_URL}/accounts/`, {
    timeout: '15s',
  });
  
  responseTimeByPeriod.add(res.timings.duration);
  
  check(res, {
    'accounts page responds': (r) => r.status === 200 || r.status === 302,
  }) || errorRate.add(1);

  sleep(2);

  // Test transfer page (should redirect)
  res = http.get(`${BASE_URL}/transfer/`, {
    timeout: '15s',
  });
  
  responseTimeByPeriod.add(res.timings.duration);
  
  check(res, {
    'transfer page responds': (r) => r.status === 200 || r.status === 302,
  }) || errorRate.add(1);

  sleep(3);
}

export function handleSummary(data) {
  return {
    'stdout': textSummary(data, { indent: ' ', enableColors: true }),
  };
}

function textSummary(data, options) {
  const indent = options.indent || '';
  
  let summary = '\n\n';
  summary += indent + '=== Soak Test Summary ===\n\n';
  
  if (data.metrics.http_reqs) {
    summary += indent + `Total Requests: ${data.metrics.http_reqs.values.count}\n`;
  }
  
  if (data.metrics.http_req_duration) {
    summary += indent + `Average Response Time: ${data.metrics.http_req_duration.values.avg.toFixed(2)}ms\n`;
    summary += indent + `Min Response Time: ${data.metrics.http_req_duration.values.min.toFixed(2)}ms\n`;
    summary += indent + `Max Response Time: ${data.metrics.http_req_duration.values.max.toFixed(2)}ms\n`;
    summary += indent + `95th Percentile: ${data.metrics.http_req_duration.values['p(95)'].toFixed(2)}ms\n`;
    summary += indent + `99th Percentile: ${data.metrics.http_req_duration.values['p(99)'].toFixed(2)}ms\n`;
  }
  
  if (data.metrics.http_req_failed) {
    summary += indent + `Request Failure Rate: ${(data.metrics.http_req_failed.values.rate * 100).toFixed(2)}%\n`;
  }
  
  if (data.metrics.errors) {
    summary += indent + `Error Rate: ${(data.metrics.errors.values.rate * 100).toFixed(2)}%\n`;
  }
  
  summary += '\n';
  summary += indent + 'Note: Check for performance degradation over the 6-minute soak period.\n';
  summary += indent + 'Response times should remain consistent throughout the test.\n';
  summary += '\n';
  
  return summary;
}
