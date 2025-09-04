const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// CORS configuration - Allow all origins for now
app.use(
  cors({
    origin: true, // Allow all origins
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'Origin',
      'Accept',
    ],
    preflightContinue: false,
    optionsSuccessStatus: 204,
  })
);

app.use(express.json());

// Handle CORS preflight requests
app.options('*', cors());

// Debug middleware - log all requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  console.log('Headers:', req.headers);

  // Set CORS headers for all requests
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-Requested-With, Origin, Accept'
  );
  res.header('Access-Control-Allow-Credentials', 'true');

  next();
});

// Initialize Firebase Admin
const serviceAccount = {
  type: 'service_account',
  project_id: process.env.FIREBASE_PROJECT_ID || 'kise-test',
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: 'https://accounts.google.com/o/oauth2/auth',
  token_uri: 'https://oauth2.googleapis.com/token',
  auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
  client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL,
};

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: `https://${
      process.env.FIREBASE_PROJECT_ID || 'kise-test'
    }.firebaseio.com`,
  });
}

// Email configuration
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.GMAIL_USER || 'seadahassen459@gmail.com',
    pass: process.env.GMAIL_PASS || 'haqm lfor zmxr jtxe',
  },
});

// Helper function to send verification email
async function sendVerificationEmail(email, firstName, verificationUrl) {
  const emailTemplate = {
    from: 'seadahassen459@gmail.com',
    to: email,
    subject: 'Verify Your Email - KiseTrust',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333;">Email Verification</h2>
        <p>Hello ${firstName},</p>
        <p>Please click the link below to verify your email address:</p>
        <a href="${verificationUrl}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Verify Email</a>
        <p>If the button doesn't work, copy and paste this link into your browser:</p>
        <p style="word-break: break-all; color: #666;">${verificationUrl}</p>
        <p>This link will expire in 24 hours.</p>
        <p>Best regards,<br>KiseTrust Team</p>
      </div>
    `,
  };

  return await transporter.sendMail(emailTemplate);
}

// Helper function to send KYC notification emails
async function sendKYCNotificationEmail(
  email,
  userName,
  type,
  reviewNotes = ''
) {
  let subject, html, text;

  switch (type) {
    case 'approved':
      subject = '🎉 KYC Approved - Welcome to KiseTrust!';
      html = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #28a745;">KYC Verification Approved!</h2>
          <p>Hello ${userName},</p>
          <p>Great news! Your KYC verification has been approved. You now have full access to all KiseTrust services.</p>
          <p>You can now:</p>
          <ul>
            <li>Apply for loans</li>
            <li>Make investments</li>
            <li>Access all features</li>
          </ul>
          <p>Best regards,<br>KiseTrust Team</p>
        </div>
      `;
      break;

    case 'rejected':
      subject = '❌ KYC Verification Update';
      html = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #dc3545;">KYC Verification Update</h2>
          <p>Hello ${userName},</p>
          <p>We regret to inform you that your KYC verification could not be completed at this time.</p>
          <p><strong>Review Notes:</strong> ${reviewNotes}</p>
          <p>Please review the feedback and resubmit your KYC documents. We're here to help!</p>
          <p>Best regards,<br>KiseTrust Team</p>
        </div>
      `;
      break;

    case 'additional_info':
      subject = '📋 Additional KYC Information Required';
      html = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #ffc107;">Additional Information Required</h2>
          <p>Hello ${userName},</p>
          <p>We need additional information to complete your KYC verification.</p>
          <p><strong>Required Information:</strong> ${reviewNotes}</p>
          <p>Please provide the requested information to avoid delays.</p>
          <p>Best regards,<br>KiseTrust Team</p>
        </div>
      `;
      break;
  }

  return await transporter.sendMail({
    from: 'seadahassen459@gmail.com',
    to: email,
    subject,
    html,
    text: html.replace(/<[^>]*>/g, ''),
  });
}

// Helper function to send loan notification emails
async function sendLoanNotificationEmail(
  email,
  userName,
  type,
  applicationId,
  loanType,
  amount,
  additionalData = {}
) {
  let subject, html;

  switch (type) {
    case 'submitted':
      subject = '📝 Loan Application Submitted';
      html = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #007bff;">Loan Application Submitted</h2>
          <p>Hello ${userName},</p>
          <p>Your loan application has been successfully submitted!</p>
          <p><strong>Application ID:</strong> ${applicationId}</p>
          <p><strong>Loan Type:</strong> ${loanType}</p>
          <p><strong>Amount:</strong> $${amount}</p>
          <p>We'll review your application and get back to you within 24-48 hours.</p>
          <p>Best regards,<br>KiseTrust Loan Team</p>
        </div>
      `;
      break;

    case 'approved':
      const { interestRate, term, monthlyPayment } = additionalData;
      subject = '🎉 Loan Application Approved!';
      html = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #28a745;">Congratulations! Your Loan is Approved</h2>
          <p>Hello ${userName},</p>
          <p>Great news! Your loan application has been approved.</p>
          <p><strong>Application ID:</strong> ${applicationId}</p>
          <p><strong>Loan Type:</strong> ${loanType}</p>
          <p><strong>Amount:</strong> $${amount}</p>
          <p><strong>Interest Rate:</strong> ${interestRate}%</p>
          <p><strong>Term:</strong> ${term} months</p>
          <p><strong>Monthly Payment:</strong> $${
            monthlyPayment?.toFixed(2) || 'TBD'
          }</p>
          <p>You'll receive the funds within 1-2 business days.</p>
          <p>Best regards,<br>KiseTrust Loan Team</p>
        </div>
      `;
      break;

    case 'rejected':
      const { reviewNotes } = additionalData;
      subject = '❌ Loan Application Update';
      html = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #dc3545;">Loan Application Update</h2>
          <p>Hello ${userName},</p>
          <p>We regret to inform you that your loan application could not be approved at this time.</p>
          <p><strong>Application ID:</strong> ${applicationId}</p>
          <p><strong>Review Notes:</strong> ${reviewNotes}</p>
          <p>Please review the feedback and consider reapplying in the future.</p>
          <p>Best regards,<br>KiseTrust Loan Team</p>
        </div>
      `;
      break;

    case 'disbursed':
      subject = '💰 Loan Funds Disbursed';
      html = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #28a745;">Loan Funds Disbursed</h2>
          <p>Hello ${userName},</p>
          <p>Your loan funds have been successfully disbursed!</p>
          <p><strong>Application ID:</strong> ${applicationId}</strong></p>
          <p><strong>Amount:</strong> $${amount}</p>
          <p>The funds should appear in your account within 1-2 business days.</p>
          <p>Best regards,<br>KiseTrust Loan Team</p>
        </div>
      `;
      break;
  }

  return await transporter.sendMail({
    from: 'seadahassen459@gmail.com',
    to: email,
    subject,
    html,
    text: html.replace(/<[^>]*>/g, ''),
  });
}

// Helper function to send welcome email
async function sendWelcomeEmail(email, firstName) {
  const emailTemplate = {
    from: 'seadahassen459@gmail.com',
    to: email,
    subject: '🎉 Welcome to KiseTrust Express!',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="margin: 0; font-size: 28px;">🎉 Welcome to KiseTrust Express!</h1>
          <p style="margin: 10px 0 0 0; font-size: 16px;">Your account has been successfully verified</p>
        </div>
        
        <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
          <h2 style="color: #333; margin-top: 0;">Hello ${firstName}!</h2>
          
          <p style="color: #555; line-height: 1.6;">
            Welcome to KiseTrust Express! Your account has been successfully created and verified. 
            You now have access to all our financial services.
          </p>
          
          <div style="background: #e8f5e8; border: 1px solid #4caf50; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3 style="color: #2e7d32; margin-top: 0;">✅ What's Next?</h3>
            <ul style="color: #2e7d32; line-height: 1.6;">
              <li>Complete your KYC verification</li>
              <li>Explore our investment opportunities</li>
              <li>Apply for loans and financial services</li>
              <li>Set up your payment preferences</li>
            </ul>
          </div>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="https://kise-test.web.app/dashboard" style="background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 25px; display: inline-block; font-weight: bold;">
              🚀 Go to Dashboard
            </a>
          </div>
          
          <p style="color: #666; font-size: 14px; text-align: center;">
            If you have any questions, please don't hesitate to contact our support team.
          </p>
          
          <p style="color: #333; margin-top: 30px;">
            Best regards,<br>
            <strong>The KiseTrust Express Team</strong>
          </p>
        </div>
        
        <div style="text-align: center; margin-top: 20px; color: #666; font-size: 12px;">
          <p>© 2024 KiseTrust Express. All rights reserved.</p>
        </div>
      </div>
    `,
    text: `
Welcome to KiseTrust Express!

Hello ${firstName},

Welcome to KiseTrust Express! Your account has been successfully created and verified. 
You now have access to all our financial services.

What's Next?
- Complete your KYC verification
- Explore our investment opportunities  
- Apply for loans and financial services
- Set up your payment preferences

Go to Dashboard: https://kise-test.web.app/dashboard

If you have any questions, please don't hesitate to contact our support team.

Best regards,
The KiseTrust Express Team

© 2024 KiseTrust Express. All rights reserved.
    `,
  };

  return await transporter.sendMail(emailTemplate);
}

// Health check endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Kise API Service is running!',
    status: 'healthy',
    timestamp: new Date().toISOString(),
    cors: 'enabled for all origins',
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

// In-memory store for verification tokens
const verificationTokens = new Map();

// Send verification email endpoint
app.post('/api/send-verification-email', async (req, res) => {
  try {
    const { email, firstName, lastName, password, userData } = req.body;
    if (!email || !firstName || !lastName || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Generate a simple verification token (you can enhance this)
    const token =
      Math.random().toString(36).substring(2, 15) +
      Math.random().toString(36).substring(2, 15);

    // Create verification URL
    const baseUrl =
      process.env.NEXT_PUBLIC_APP_URL || 'https://kise-test.web.app';
    const verificationUrl = `${baseUrl}/verify-email?token=${token}`;

    // Store the user's data with the token (including userData)
    const expiresAt = Date.now() + 24 * 60 * 60 * 1000; // 24-hour expiration
    verificationTokens.set(token, {
      userData: { email, firstName, lastName, password, ...userData },
      expiresAt,
    });

    // Send verification email
    await sendVerificationEmail(email, firstName, verificationUrl);

    res.json({
      success: true,
      message: 'Verification email sent successfully',
      verificationUrl:
        process.env.NODE_ENV === 'development' ? verificationUrl : undefined,
    });
  } catch (error) {
    console.error('Send verification email error:', error);
    res.status(500).json({ error: 'Failed to send verification email' });
  }
});

// Send verification email for new users
app.post('/api/send-verification-email-new', async (req, res) => {
  try {
    const { email, firstName, lastName, password, userData } = req.body;
    if (!email || !firstName || !lastName || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const token =
      Math.random().toString(36).substring(2, 15) +
      Math.random().toString(36).substring(2, 15);
    const baseUrl =
      process.env.NEXT_PUBLIC_APP_URL || 'https://kise-test.web.app';
    const verificationUrl = `${baseUrl}/verify-email-new?token=${token}`;

    await sendVerificationEmail(email, firstName, verificationUrl);

    res.json({
      success: true,
      message: 'Verification email sent successfully',
      verificationUrl:
        process.env.NODE_ENV === 'development' ? verificationUrl : undefined,
    });
  } catch (error) {
    console.error('Send verification email error:', error);
    res.status(500).json({ error: 'Failed to send verification email' });
  }
});

// Send verification email for admin users
app.post('/api/send-verification-email-admin', async (req, res) => {
  try {
    const { email, firstName, lastName, password, role, adminKey, userData } =
      req.body;
    if (!email || !firstName || !lastName || !password || !role || !adminKey) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Validate admin key
    const validAdminKey =
      process.env.NEXT_PUBLIC_ADMIN_REGISTRATION_KEY || 'kise-admin-secret';
    if (adminKey !== validAdminKey) {
      return res.status(403).json({ error: 'Invalid admin registration key' });
    }

    const token =
      Math.random().toString(36).substring(2, 15) +
      Math.random().toString(36).substring(2, 15);
    const baseUrl =
      process.env.NEXT_PUBLIC_APP_URL || 'https://kise-test.web.app';
    const verificationUrl = `${baseUrl}/verify-email-admin?token=${token}`;

    await sendVerificationEmail(email, firstName, verificationUrl);

    res.json({
      success: true,
      message: 'Admin verification email sent successfully',
      verificationUrl:
        process.env.NODE_ENV === 'development' ? verificationUrl : undefined,
    });
  } catch (error) {
    console.error('Send admin verification email error:', error);
    res.status(500).json({ error: 'Failed to send admin verification email' });
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

// KYC notifications endpoint
app.post('/api/kyc-notifications', async (req, res) => {
  try {
    const { type, userId, reviewNotes } = req.body;
    if (!type || !userId) {
      return res.status(400).json({ error: 'Type and userId are required' });
    }

    // For demo purposes, we'll use a mock user email
    // In production, you'd fetch this from Firestore
    const userEmail = process.env.TEST_USER_EMAIL || 'test@example.com';
    const userName = 'Test User';

    await sendKYCNotificationEmail(userEmail, userName, type, reviewNotes);

    res.json({
      success: true,
      message: `KYC ${type} notification sent successfully`,
      userEmail,
      userName,
    });
  } catch (error) {
    console.error('KYC notification error:', error);
    res.status(500).json({ error: 'Failed to send KYC notification' });
  }
});

// Loan notifications endpoint
app.post('/api/loan-notifications', async (req, res) => {
  try {
    const { type, applicationId, userId, reviewNotes } = req.body;
    if (!type || !applicationId || !userId) {
      return res
        .status(400)
        .json({ error: 'Type, applicationId, and userId are required' });
    }

    // For demo purposes, we'll use mock data
    const userEmail = process.env.TEST_USER_EMAIL || 'test@example.com';
    const userName = 'Test User';
    const loanType = 'personal';
    const amount = 5000;

    let additionalData = {};

    if (type === 'approved') {
      const interestRate = loanType === 'emergency' ? 20 : 15;
      const term = 12;
      const monthlyRate = interestRate / 100 / 12;
      const monthlyPayment =
        (amount * monthlyRate * Math.pow(1 + monthlyRate, term)) /
        (Math.pow(1 + monthlyRate, term) - 1);

      additionalData = { interestRate, term, monthlyPayment };
    } else if (type === 'rejected') {
      additionalData = {
        reviewNotes:
          reviewNotes || 'Application did not meet our current criteria',
      };
    }

    await sendLoanNotificationEmail(
      userEmail,
      userName,
      type,
      applicationId,
      loanType,
      amount,
      additionalData
    );

    res.json({
      success: true,
      message: `Loan ${type} notification sent successfully`,
      userEmail,
      userName,
      applicationId,
    });
  } catch (error) {
    console.error('Loan notification error:', error);
    res.status(500).json({ error: 'Failed to send loan notification' });
  }
});

// Check email endpoint
app.post('/api/check-email', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // For demo purposes, always return success
    // In production, you'd check if email exists in Firebase Auth
    res.json({
      success: true,
      exists: true,
      message: 'Email check completed',
    });
  } catch (error) {
    console.error('Check email error:', error);
    res.status(500).json({ error: 'Failed to check email' });
  }
});

// Check email new endpoint
app.post('/api/check-email-new', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    res.json({
      success: true,
      exists: false,
      message: 'Email available for registration',
    });
  } catch (error) {
    console.error('Check email new error:', error);
    res.status(500).json({ error: 'Failed to check email' });
  }
});

// Verify email endpoint
app.post('/api/verify-email', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ error: 'Token is required' });
    }

    const verificationData = verificationTokens.get(token);

    if (!verificationData) {
      return res.status(400).json({ error: 'Invalid verification token' });
    }

    if (Date.now() > verificationData.expiresAt) {
      verificationTokens.delete(token);
      return res.status(400).json({ error: 'token_expired' });
    }

    const { email, firstName, lastName, password, phone, acceptMarketing } =
      verificationData.userData;

    try {
      // Create Firebase Auth user
      const userRecord = await admin.auth().createUser({
        email,
        password,
        displayName: `${firstName} ${lastName}`,
      });

      console.log(
        '✅ Firebase Auth user created successfully on backend. UID:',
        userRecord.uid
      );

      // Create Firestore user document
      const db = admin.firestore();
      const userDoc = {
        id: userRecord.uid,
        email: userRecord.email,
        firstName: firstName,
        lastName: lastName,
        phone: phone || '',
        dateOfBirth: '',
        address: {
          street: '',
          city: '',
          state: '',
          postalCode: '',
          country: '',
        },
        kycStatus: 'incomplete',
        role: 'customer',
        kyc: {
          personal: {
            gender: null,
            nationality: '',
          },
          employment: {
            status: '',
            employerName: '',
            jobTitle: '',
            monthlyIncome: 0,
            incomeSource: '',
          },
          financial: {
            bankName: '',
            accountNumber: '',
            accountType: '',
          },
          documents: [],
        },
        accountStatus: 'active',
        emailVerified: true,
        phoneVerified: false,
        preferences: {
          language: 'en',
          currency: 'ETB',
          notifications: {
            email: true,
            sms: true,
            push: true,
            marketing: acceptMarketing || false,
          },
        },
        security: {
          twoFactorEnabled: false,
          loginAttempts: 0,
        },
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      };

      // Save user document to Firestore
      await db.collection('users').doc(userRecord.uid).set(userDoc);
      console.log('✅ Firestore user document created successfully');

      // Send welcome email
      try {
        await sendWelcomeEmail(email, firstName);
        console.log('✅ Welcome email sent successfully');
      } catch (emailError) {
        console.warn('⚠️ Welcome email failed:', emailError.message);
        // Don't fail the registration if email fails
      }

      // Clean up the verification token
      verificationTokens.delete(token);

      // Construct the response payload
      const responsePayload = {
        success: true,
        verified: true,
        message:
          'Email verified, user created, and welcome email sent successfully',
        user: {
          uid: userRecord.uid,
          email: userRecord.email,
          firstName: firstName,
          lastName: lastName,
        },
      };

      console.log(
        '📦 Sending successful response payload to frontend:',
        JSON.stringify(responsePayload, null, 2)
      );

      // Return the new user's data to the frontend
      return res.json(responsePayload);
    } catch (firebaseError) {
      verificationTokens.delete(token);
      if (firebaseError.code === 'auth/email-already-exists') {
        return res
          .status(409)
          .json({ error: 'This email is already registered.' });
      }
      console.error('❌ Firebase error during user creation:', firebaseError);
      console.error('❌ Firebase error code:', firebaseError.code);
      console.error('❌ Firebase error message:', firebaseError.message);
      return res.status(500).json({ error: 'Failed to create account.' });
    }
  } catch (error) {
    console.error('❌ Top-level verify email error:', error);
    console.error('❌ Error message:', error.message);
    console.error('❌ Error stack:', error.stack);
    res.status(500).json({ error: 'Failed to verify email' });
  }
});

// Send welcome email endpoint (called after successful user creation)
app.post('/api/send-welcome-email', async (req, res) => {
  try {
    const { email, firstName } = req.body;

    if (!email || !firstName) {
      return res
        .status(400)
        .json({ error: 'Email and firstName are required' });
    }

    console.log('📧 Sending welcome email to:', email);

    // Send welcome email
    await sendWelcomeEmail(email, firstName);

    res.json({
      success: true,
      message: 'Welcome email sent successfully',
      email,
      firstName,
    });
  } catch (error) {
    console.error('Send welcome email error:', error);
    res.status(500).json({ error: 'Failed to send welcome email' });
  }
});

// Verify email new endpoint
app.post('/api/verify-email-new', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ error: 'Token is required' });
    }

    console.log('🔍 Verifying new email token:', token);

    if (token && token.length > 10) {
      res.json({
        success: true,
        message: 'Email verified successfully',
        verified: true,
      });
    } else {
      res.status(400).json({
        error: 'Invalid verification token',
        verified: false,
      });
    }
  } catch (error) {
    console.error('Verify email new error:', error);
    res.status(500).json({ error: 'Failed to verify email' });
  }
});

// Verify email admin endpoint
app.post('/api/verify-email-admin', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ error: 'Token is required' });
    }

    console.log('🔍 Verifying admin email token:', token);

    if (token && token.length > 10) {
      res.json({
        success: true,
        message: 'Admin email verified successfully',
        verified: true,
      });
    } else {
      res.status(400).json({
        error: 'Invalid verification token',
        verified: false,
      });
    }
  } catch (error) {
    console.error('Verify admin email error:', error);
    res.status(500).json({ error: 'Failed to verify admin email' });
  }
});

// Upload profile image endpoint (mock)
app.post('/api/upload-profile-image', async (req, res) => {
  try {
    const { userId, imageData } = req.body;
    if (!userId || !imageData) {
      return res
        .status(400)
        .json({ error: 'UserId and imageData are required' });
    }

    // For demo purposes, return success
    // In production, you'd upload to Firebase Storage
    res.json({
      success: true,
      message: 'Profile image uploaded successfully',
      imageUrl: 'https://example.com/profile-image.jpg',
      userId,
    });
  } catch (error) {
    console.error('Upload profile image error:', error);
    res.status(500).json({ error: 'Failed to upload profile image' });
  }
});

// Upload KYC documents endpoint (mock)
app.post('/api/upload-kyc-documents', async (req, res) => {
  try {
    const { userId, documents } = req.body;
    if (!userId || !documents) {
      return res
        .status(400)
        .json({ error: 'UserId and documents are required' });
    }

    res.json({
      success: true,
      message: 'KYC documents uploaded successfully',
      documentsCount: documents.length,
      userId,
    });
  } catch (error) {
    console.error('Upload KYC documents error:', error);
    res.status(500).json({ error: 'Failed to upload KYC documents' });
  }
});

// Test endpoints for development
app.post('/api/test-simple', async (req, res) => {
  res.json({
    success: true,
    message: 'Test endpoint working',
    timestamp: new Date().toISOString(),
  });
});

app.post('/api/test-upload', async (req, res) => {
  res.json({
    success: true,
    message: 'Test upload endpoint working',
    timestamp: new Date().toISOString(),
  });
});

app.post('/api/test-email', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // Send a test email
    await transporter.sendMail({
      from: 'seadahassen459@gmail.com',
      to: email,
      subject: '🧪 Test Email - KiseTrust API Service',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #007bff;">Test Email Success!</h2>
          <p>This is a test email from your new Render API service.</p>
          <p>✅ Email service is working correctly</p>
          <p>✅ CORS is properly configured</p>
          <p>✅ All systems are operational</p>
          <p>Best regards,<br>KiseTrust Team</p>
        </div>
      `,
    });

    res.json({
      success: true,
      message: 'Test email sent successfully',
      email,
    });
  } catch (error) {
    console.error('Test email error:', error);
    res.status(500).json({ error: 'Failed to send test email' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Kise API Service running on port ${PORT}`);
  console.log(`📡 CORS enabled for all origins`);
  console.log(`🔗 Test URL: http://localhost:${PORT}`);
  console.log(`📋 Available endpoints:`);
  console.log(`   - GET  / (health check)`);
  console.log(`   - POST /api/auth-check`);
  console.log(`   - POST /api/sso-token`);
  console.log(`   - POST /api/sso-token-for-sync`);
  console.log(`   - POST /api/send-verification-email`);
  console.log(`   - POST /api/send-verification-email-new`);
  console.log(`   - POST /api/send-verification-email-admin`);
  console.log(`   - POST /api/send-password-reset`);
  console.log(`   - POST /api/kyc-notifications`);
  console.log(`   - POST /api/loan-notifications`);
  console.log(`   - POST /api/share-notifications`);
  console.log(`   - POST /api/check-email`);
  console.log(`   - POST /api/check-email-new`);
  console.log(`   - POST /api/verify-email`);
  console.log(`   - POST /api/verify-email-new`);
  console.log(`   - POST /api/verify-email-admin`);
  console.log(`   - POST /api/upload-profile-image`);
  console.log(`   - POST /api/upload-kyc-documents`);
  console.log(`   - POST /api/test-simple`);
  console.log(`   - POST /api/test-upload`);
  console.log(`   - POST /api/test-email`);
});

// Catch-all OPTIONS handler for CORS
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-Requested-With, Origin, Accept'
  );
  res.header('Access-Control-Allow-Credentials', 'true');
  res.status(200).end();
});

// Error handling middleware with CORS headers
app.use((err, req, res, next) => {
  console.error('Error:', err);

  // Ensure CORS headers are set even on errors
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-Requested-With, Origin, Accept'
  );
  res.header('Access-Control-Allow-Credentials', 'true');

  res.status(500).json({ error: 'Internal server error' });
});

module.exports = app;
