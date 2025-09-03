const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// CORS configuration
app.use(
  cors({
    origin: [
      'https://kise-test.web.app',
      'https://kise-test.firebaseapp.com',
      'https://kise-test-39ea0.web.app',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:9002',
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  })
);

app.use(express.json());

// Health check endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Kise API Service is running! (Test Mode)',
    status: 'healthy',
    timestamp: new Date().toISOString(),
    note: 'This is a test version without Firebase integration',
  });
});

// Test SSO token endpoint (mock)
app.post('/api/sso-token', async (req, res) => {
  try {
    const { uid, email, redirectUrl } = req.body;
    if (!uid || !email) {
      return res.status(400).json({ error: 'UID and email are required' });
    }

    // Mock response for testing
    res.json({
      success: true,
      customToken: 'mock-token-for-testing',
      message: 'SSO token generated successfully (TEST MODE)',
      uid,
      email,
      redirectUrl,
    });
  } catch (error) {
    console.error('SSO token generation error:', error);
    res.status(500).json({ error: 'Failed to generate SSO token' });
  }
});

// Test auth check endpoint (mock)
app.post('/api/auth-check', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Mock response for testing
    res.json({
      authenticated: true,
      uid: 'test-uid-123',
      email: 'test@example.com',
      message: 'This is a test response (TEST MODE)',
    });
  } catch (error) {
    console.error('Auth check error:', error);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Test endpoint to verify CORS is working
app.post('/api/test-cors', (req, res) => {
  res.json({
    success: true,
    message: 'CORS test successful!',
    timestamp: new Date().toISOString(),
    requestBody: req.body,
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Kise API Service (TEST MODE) running on port ${PORT}`);
  console.log(
    `📡 CORS enabled for: ${[
      'https://kise-test.web.app',
      'https://kise-test.firebaseapp.com',
      'https://kise-test-39ea0.web.app',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:9002',
    ].join(', ')}`
  );
  console.log(`🔗 Test URL: http://localhost:${PORT}`);
  console.log(`📋 Available endpoints:`);
  console.log(`   - GET  / (health check)`);
  console.log(`   - POST /api/sso-token (mock)`);
  console.log(`   - POST /api/auth-check (mock)`);
  console.log(`   - POST /api/test-cors (CORS test)`);
});

module.exports = app;
