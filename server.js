const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// CORS configuration
app.use(cors({
  origin: [
    'https://kise-test.web.app',
    'https://kise-test.firebaseapp.com',
    'https://kise-test-39ea0.web.app',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:9002'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(express.json());

// Initialize Firebase Admin
const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID || "kise-test",
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL
};

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: `https://${process.env.FIREBASE_PROJECT_ID || 'kise-test'}.firebaseio.com`
  });
}

// Email configuration
const transporter = nodemailer.createTransporter({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.GMAIL_USER || 'seadahassen459@gmail.com',
    pass: process.env.GMAIL_PASS || 'haqm lfor zmxr jtxe',
  },
});

// Health check endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'Kise API Service is running!',
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

// Auth check endpoint
app.post('/api/auth-check', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const token = authHeader.split('Bearer ')[1];
    const decodedToken = await admin.auth().verifyIdToken(token);

    res.json({
      authenticated: true,
      uid: decodedToken.uid,
      email: decodedToken.email,
    });
  } catch (error) {
    console.error('Auth check error:', error);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// SSO token endpoint
app.post('/api/sso-token', async (req, res) => {
  try {
    const { uid, email, redirectUrl } = req.body;
    if (!uid || !email) {
      return res.status(400).json({ error: 'UID and email are required' });
    }

    const customToken = await admin.auth().createCustomToken(uid, {
      redirectUrl: redirectUrl || null,
      timestamp: Date.now(),
    });

    res.json({
      success: true,
      customToken,
      message: 'SSO token generated successfully',
    });
  } catch (error) {
    console.error('SSO token generation error:', error);
    res.status(500).json({ error: 'Failed to generate SSO token' });
  }
});

// SSO token for sync endpoint
app.post('/api/sso-token-for-sync', async (req, res) => {
  try {
    const { uid, email, site } = req.body;
    if (!uid || !email) {
      return res.status(400).json({ error: 'UID and email are required' });
    }

    const customToken = await admin.auth().createCustomToken(uid, {
      site: site || 'main',
      syncTimestamp: Date.now(),
      purpose: 'cross-site-sync',
    });

    res.json({
      success: true,
      customToken,
      message: 'SSO sync token generated successfully',
      site: site || 'main',
    });
  } catch (error) {
    console.error('SSO sync token generation error:', error);
    res.status(500).json({ error: 'Failed to generate SSO sync token' });
  }
});

// Send verification email endpoint
app.post('/api/send-verification-email', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const verificationLink = await admin.auth().generateEmailVerificationLink(email);
    
    const emailTemplate = {
      from: 'seadahassen459@gmail.com',
      to: email,
      subject: 'Verify Your Email - KiseTrust',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Email Verification</h2>
          <p>Hello,</p>
          <p>Please click the link below to verify your email address:</p>
          <a href="${verificationLink}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Verify Email</a>
          <p>If the button doesn't work, copy and paste this link into your browser:</p>
          <p style="word-break: break-all; color: #666;">${verificationLink}</p>
          <p>This link will expire in 24 hours.</p>
          <p>Best regards,<br>KiseTrust Team</p>
        </div>
      `,
    };

    const info = await transporter.sendMail(emailTemplate);
    console.log('Verification email sent:', info.messageId);
    
    res.json({
      success: true,
      message: 'Verification email sent successfully',
      messageId: info.messageId,
    });
  } catch (error) {
    console.error('Send verification email error:', error);
    res.status(500).json({ error: 'Failed to send verification email' });
  }
});

// Send password reset endpoint
app.post('/api/send-password-reset', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const resetLink = await admin.auth().generatePasswordResetLink(email);
    
    const emailTemplate = {
      from: 'seadahassen459@gmail.com',
      to: email,
      subject: 'Password Reset - KiseTrust',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Password Reset Request</h2>
          <p>Hello,</p>
          <p>You requested a password reset for your account. Click the link below to reset your password:</p>
          <a href="${resetLink}" style="background-color: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
          <p>If the button doesn't work, copy and paste this link into your browser:</p>
          <p style="word-break: break-all; color: #666;">${resetLink}</p>
          <p>This link will expire in 1 hour.</p>
          <p>If you didn't request this password reset, please ignore this email.</p>
          <p>Best regards,<br>KiseTrust Team</p>
        </div>
      `,
    };

    const info = await transporter.sendMail(emailTemplate);
    console.log('Password reset email sent:', info.messageId);
    
    res.json({
      success: true,
      message: 'Password reset email sent successfully',
      messageId: info.messageId,
    });
  } catch (error) {
    console.error('Send password reset error:', error);
    res.status(500).json({ error: 'Failed to send password reset email' });
  }
});

// Share notifications endpoint
app.post('/api/share-notifications', async (req, res) => {
  try {
    const { userId, shareId, action } = req.body;
    res.json({
      success: true,
      message: 'Share notification processed',
      data: { userId, shareId, action },
    });
  } catch (error) {
    console.error('Share notification error:', error);
    res.status(500).json({ error: 'Failed to process share notification' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Kise API Service running on port ${PORT}`);
  console.log(`📡 CORS enabled for: ${app.get('cors').origin.join(', ')}`);
});

module.exports = app; 