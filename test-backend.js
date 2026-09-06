/**
 * Automated Verification Script for SecureDev AI Backend
 */
const http = require('http');

// Start server
process.env.PORT = '5001';
process.env.MONGODB_URI = ''; // Force stateless in-memory mode for test
const app = require('./server');

const makeRequest = (options, postData) => {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch (e) {
          resolve({ status: res.statusCode, raw: data });
        }
      });
    });
    req.on('error', reject);
    if (postData) req.write(JSON.stringify(postData));
    req.end();
  });
};

setTimeout(async () => {
  try {
    console.log('--- TEST 1: Health Check (GET /api/health) ---');
    const health = await makeRequest({
      hostname: 'localhost',
      port: 5001,
      path: '/api/health',
      method: 'GET'
    });
    console.log('Health check status:', health.status);
    console.log('Health response:', health.body);

    if (health.status !== 200 || health.body.status !== 'ok') {
      throw new Error('Health check failed!');
    }

    console.log('\n--- TEST 2: Vulnerability Analysis (POST /api/analyze) ---');
    const sampleVulnerableCode = `
app.post("/login", async (req, res) => {
  const user = await User.findOne({
    email: req.body.email,
    password: req.body.password
  });
  res.json(user);
});
    `.trim();

    const analysis = await makeRequest({
      hostname: 'localhost',
      port: 5001,
      path: '/api/analyze',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    }, {
      language: 'javascript',
      code: sampleVulnerableCode
    });

    console.log('Analyze status:', analysis.status);
    console.log('Security Score:', analysis.body.score);
    console.log('Risk Level:', analysis.body.riskLevel);
    console.log('Vulnerabilities Found:', analysis.body.vulnerabilities?.length);
    analysis.body.vulnerabilities?.forEach((v, idx) => {
      console.log(`  [${v.severity}] ${v.title} (${v.category})`);
    });
    console.log('Secure Code Sample Preview:', analysis.body.secureCode ? 'Generated successfully' : 'Missing');
    console.log('Simple Explanation Preview:', analysis.body.simpleExplanation ? 'Generated successfully' : 'Missing');

    if (analysis.status !== 200 || !analysis.body.success || analysis.body.score > 70) {
      throw new Error(`Analyze test failed: status ${analysis.status}, score ${analysis.body.score}`);
    }

    console.log('\n--- TEST 3: Validation Error Handling (POST /api/analyze with empty code) ---');
    const emptyTest = await makeRequest({
      hostname: 'localhost',
      port: 5001,
      path: '/api/analyze',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, {
      language: 'javascript',
      code: '   '
    });
    console.log('Empty code rejection status:', emptyTest.status, '(Expected: 400)');
    if (emptyTest.status !== 400) throw new Error('Failed to reject empty code');

    console.log('\n--- TEST 4: Stats Endpoint (GET /api/stats) ---');
    const stats = await makeRequest({
      hostname: 'localhost',
      port: 5001,
      path: '/api/stats',
      method: 'GET'
    });
    console.log('Stats response:', stats.body);

    console.log('\n>>> ALL BACKEND AUTOMATED VERIFICATION TESTS PASSED! <<<');
    process.exit(0);
  } catch (err) {
    console.error('Backend test failure:', err);
    process.exit(1);
  }
}, 1000);
