const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const nodemailer = require('nodemailer');
const multer = require('multer');
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
      'x-user-id',
    ],
    preflightContinue: false,
    optionsSuccessStatus: 204,
  })
);

app.use(express.json());

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Accept only PDF, JPG, PNG files
    if (
      file.mimetype === 'application/pdf' ||
      file.mimetype === 'image/jpeg' ||
      file.mimetype === 'image/jpg' ||
      file.mimetype === 'image/png'
    ) {
      cb(null, true);
    } else {
      cb(
        new Error(
          'Invalid file type. Only PDF, JPG, and PNG files are allowed.'
        )
      );
    }
  },
});

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
    storageBucket: `${
      process.env.FIREBASE_PROJECT_ID || 'kise-test'
    }.appspot.com`,
  });
}

// Email configuration
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.GMAIL_USER || 'kisemfsocials@gmail.com',
    pass: process.env.GMAIL_PASS || 'iyyp dobl ehco ftlz',
  },
});

// Helper function to send verification email
async function sendVerificationEmail(email, firstName, verificationUrl) {
  const emailTemplate = {
    from: 'kisemfsocials@gmail.com',
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
    from: 'kisemfsocials@gmail.com',
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
    from: 'kisemfsocials@gmail.com',
    to: email,
    subject,
    html,
    text: html.replace(/<[^>]*>/g, ''),
  });
}

// Helper function to send welcome email
async function sendWelcomeEmail(email, firstName) {
  const emailTemplate = {
    from: 'kisemfsocials@gmail.com',
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

    // Validate role - now includes 'agent'
    const validRoles = ['admin', 'manager', 'loan_officer', 'agent'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: 'Invalid role specified' });
    }

    // Generate reference ID for agents
    let referenceId = '';
    if (role === 'agent') {
      try {
        // Simulate reference ID generation logic
        referenceId = `AGT${Math.floor(100 + Math.random() * 900)}`;
        console.log(`🏪 Generated agent reference ID: ${referenceId}`);
      } catch (error) {
        console.error('Error generating agent reference ID:', error);
        return res
          .status(500)
          .json({ error: 'Failed to generate agent reference ID' });
      }
    }

    console.log(
      `🔐 Processing admin verification email for: ${email} (Role: ${role}${
        referenceId ? `, Ref: ${referenceId}` : ''
      })`
    );

    // Create verification token with admin role
    // For simplicity, token is a random string here
    const token =
      Math.random().toString(36).substring(2, 15) +
      Math.random().toString(36).substring(2, 15);

    const baseUrl =
      process.env.NEXT_PUBLIC_APP_URL || 'https://kise-test.web.app';
    const verificationUrl = `${baseUrl}/verify-email-admin?token=${token}`;

    // Use specialized email sending function for admin verification
    // For now, reuse sendVerificationEmail but log role and referenceId
    try {
      console.log(
        `Sending admin verification email to ${email} with role ${role} and referenceId ${referenceId}`
      );
      await sendVerificationEmail(email, firstName, verificationUrl);
      console.log('✅ Admin verification email sent successfully');

      res.json({
        success: true,
        message: `Admin verification email sent successfully for role: ${role}${
          referenceId ? ` (Agent ID: ${referenceId})` : ''
        }`,
        emailSent: true,
        ...(referenceId && { agentReferenceId: referenceId }),
        verificationUrl:
          process.env.NODE_ENV === 'development' ? verificationUrl : undefined,
      });
    } catch (emailError) {
      console.error('❌ Admin email sending failed:', emailError);
      console.log('🔗 Use this verification URL instead:', verificationUrl);

      // Return success with console URL when email fails
      res.json({
        success: true,
        emailSent: false,
        message: 'Admin verification token created successfully',
        warning:
          'Email sending failed due to SMTP timeout. Use the console verification URL below.',
        verificationUrl,
        ...(referenceId && { agentReferenceId: referenceId }),
        instructions:
          'Copy the URL above and paste it in your browser to complete admin verification.',
      });
    }
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
      from: 'kisemfsocials@gmail.com',
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

// Upload KYC documents endpoint (simplified version)
app.post(
  '/api/upload-kyc-documents',
  upload.array('documents', 10),
  async (req, res) => {
    try {
      console.log(' KYC Upload Request received');
      console.log('Headers:', req.headers);
      console.log('Files:', req.files ? req.files.length : 'No files');

      // Get userId from headers or body
      const userId = req.headers['x-user-id'] || req.body.userId;
      if (!userId) {
        console.log('❌ No userId provided');
        return res.status(400).json({ error: 'UserId is required' });
      }

      console.log('👤 User ID:', userId);

      // Check if files were uploaded
      if (!req.files || req.files.length === 0) {
        console.log('❌ No files uploaded');
        return res.status(400).json({ error: 'No files uploaded' });
      }

      const files = req.files;
      const uploadedFiles = [];

      console.log(` Processing ${files.length} files`);

      // Process uploaded files (simplified - no Firebase Storage for now)
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const fileId = `file_${Date.now()}_${i}`;
        const fileName = `${fileId}_${file.originalname}`;

        console.log(
          ` Processing file ${i + 1}: ${file.originalname} (${file.size} bytes)`
        );

        // For now, just store file metadata without actual upload
        uploadedFiles.push({
          id: fileId,
          name: file.originalname,
          type: file.mimetype,
          size: file.size,
          url: `mock://kyc-documents/${userId}/${fileName}`,
          uploadedAt: new Date().toISOString(),
          verified: false,
          note: 'File received successfully - storage integration pending',
        });

        console.log(`✅ File processed: ${file.originalname}`);
      }

      console.log(
        `📁 Successfully processed ${uploadedFiles.length} KYC documents for user ${userId}`
      );

      res.json({
        success: true,
        message: 'KYC documents uploaded successfully',
        files: uploadedFiles,
        count: uploadedFiles.length,
        userId,
      });
    } catch (error) {
      console.error('❌ Upload KYC documents error:', error);
      console.error('❌ Error stack:', error.stack);
      res.status(500).json({
        error: 'Failed to upload KYC documents',
        details: error.message,
      });
    }
  }
);

// Simple test upload endpoint (without multer)
app.post('/api/test-upload-simple', async (req, res) => {
  try {
    console.log('🧪 Test upload endpoint called');
    console.log('Headers:', req.headers);
    console.log('Body keys:', Object.keys(req.body || {}));

    res.json({
      success: true,
      message: 'Test upload endpoint working',
      timestamp: new Date().toISOString(),
      headers: req.headers,
    });
  } catch (error) {
    console.error('Test upload error:', error);
    res.status(500).json({ error: 'Test upload failed' });
  }
});

// Simplified KYC upload endpoint (without Firebase Storage)
app.post('/api/upload-kyc-simple', async (req, res) => {
  try {
    console.log('📁 Simple KYC Upload Request received');

    const userId = req.headers['x-user-id'];
    if (!userId) {
      return res
        .status(400)
        .json({ error: 'UserId is required in x-user-id header' });
    }

    // For now, just return success without actual file processing
    const mockFiles = [
      {
        id: `file_${Date.now()}`,
        name: 'mock-document.pdf',
        type: 'application/pdf',
        size: 1024,
        url: `mock://kyc-documents/${userId}/mock-document.pdf`,
        uploadedAt: new Date().toISOString(),
        verified: false,
        note: 'Mock upload - file processing pending',
      },
    ];

    console.log(`📁 Mock upload completed for user ${userId}`);

    res.json({
      success: true,
      message: 'KYC documents uploaded successfully (mock)',
      files: mockFiles,
      count: mockFiles.length,
      userId,
    });
  } catch (error) {
    console.error('❌ Simple KYC upload error:', error);
    res.status(500).json({
      error: 'Failed to upload KYC documents',
      details: error.message,
    });
  }
});

// AI Onboarding endpoint
app.post('/api/onboarding', async (req, res) => {
  try {
    const { name, email, financialSituation, goals, riskTolerance } = req.body;

    // Validate required fields
    if (!name || !email || !financialSituation || !goals || !riskTolerance) {
      return res.status(400).json({
        error:
          'Missing required fields: name, email, financialSituation, goals, riskTolerance',
      });
    }

    // Validate risk tolerance
    const validRiskTolerances = ['low', 'medium', 'high'];
    if (!validRiskTolerances.includes(riskTolerance)) {
      return res.status(400).json({
        error: 'Invalid risk tolerance. Must be one of: low, medium, high',
      });
    }

    console.log(`🤖 Processing AI onboarding for: ${name} (${email})`);

    // For now, we'll return a mock response since the AI flow isn't set up in the backend
    // In production, you would integrate with your AI service here
    const mockOnboardingResponse = {
      kycGuidance: `Hello ${name}! To complete your KYC verification, please prepare the following documents:

1. **National ID Card** - A clear photo of your government-issued ID
2. **Proof of Address** - Utility bill or bank statement (not older than 3 months)
3. **Income Verification** - Recent pay stub or bank statement showing income

**Next Steps:**
- Upload these documents through your dashboard
- Our team will review them within 24-48 hours
- You'll receive an email notification once approved

**Important:** Make sure all documents are clear, readable, and not expired.`,

      accountSetupInstructions: `Welcome to KiseTrust! Here's how to set up your account:

1. **Complete KYC Verification** (see guidance above)
2. **Set Up Your Profile** - Add your personal and contact information
3. **Configure Security Settings** - Enable two-factor authentication
4. **Set Payment Preferences** - Add your bank account details
5. **Explore Products** - Browse our savings and loan options

**Your Dashboard Features:**
- Real-time account balance
- Transaction history
- Investment tracking
- Loan applications
- Customer support chat`,

      recommendedProducts: [
        `**Emergency Savings Account** - Perfect for your risk tolerance (${riskTolerance})`,
        `**KiseTrust MFI Shares** - Investment opportunity with competitive returns`,
        `**Personal Loan** - Based on your financial goals: ${goals.substring(
          0,
          50
        )}...`,
      ],
    };

    // In a real implementation, you would call your AI service here:
    // const aiResponse = await callAIService({
    //   name, email, financialSituation, goals, riskTolerance
    // });

    console.log(`✅ AI onboarding completed for ${name}`);

    res.json({
      success: true,
      message: 'Onboarding plan generated successfully',
      result: mockOnboardingResponse,
    });
  } catch (error) {
    console.error('AI onboarding error:', error);
    res.status(500).json({
      error: 'Failed to generate onboarding plan',
      details: error.message,
    });
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
      from: 'kisemfsocials@gmail.com',
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

// ================================
// COMPREHENSIVE NOTIFICATION SYSTEM
// ================================

// Enhanced KYC notifications endpoint with Firestore integration
app.post('/api/kyc-notifications', async (req, res) => {
  try {
    const { type, userId, reviewNotes } = req.body;

    if (!type || !userId) {
      return res.status(400).json({ error: 'Type and userId are required' });
    }

    console.log(
      `📧 Sending ${type} KYC email notification for user: ${userId}`
    );

    // Fetch user data from Firestore
    const db = admin.firestore();
    const userDoc = await db.collection('users').doc(userId).get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userDoc.data();
    const userEmail = user.email;
    const userName =
      `${user.firstName || ''} ${user.lastName || ''}`.trim() || 'User';

    if (!userEmail) {
      return res.status(400).json({ error: 'User email not found' });
    }

    // Send email based on type
    try {
      await sendKYCNotificationEmail(userEmail, userName, type, reviewNotes);

      console.log(`✅ ${type} KYC email sent successfully to ${userEmail}`);
      return res.json({ success: true });
    } catch (emailError) {
      console.error(`❌ Failed to send ${type} KYC email:`, emailError);
      return res.json({
        success: false,
        error: 'Email sending failed',
        details: emailError.message,
      });
    }
  } catch (error) {
    console.error('❌ Error in KYC notifications API:', error);
    return res.status(500).json({
      error: 'Failed to process KYC notification',
      details: error.message,
    });
  }
});

// Enhanced Loan notifications endpoint with comprehensive functionality
app.post('/api/loan-notifications', async (req, res) => {
  try {
    const { type, applicationId, userId, reviewNotes } = req.body;

    if (!type || !applicationId || !userId) {
      return res.status(400).json({
        error: 'Type, applicationId, and userId are required',
      });
    }

    console.log(
      `📧 Processing ${type} loan notification for application: ${applicationId}`
    );

    const db = admin.firestore();

    // Get user details
    const userDoc = await db.collection('users').doc(userId).get();
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userDoc.data();
    if (!user || !user.email) {
      return res.status(404).json({ error: 'User email not available' });
    }

    // Get application details
    const applicationDoc = await db
      .collection('loanApplications')
      .doc(applicationId)
      .get();
    if (!applicationDoc.exists) {
      return res.status(404).json({ error: 'Loan application not found' });
    }

    const application = applicationDoc.data();
    const userName = user.firstName || user.name || 'Valued Customer';

    let additionalData = {};

    if (type === 'approved') {
      const interestRate = application.loanType === 'emergency' ? 20 : 15;
      const monthlyRate = interestRate / 100 / 12;
      const monthlyPayment =
        (application.amount *
          monthlyRate *
          Math.pow(1 + monthlyRate, application.term)) /
        (Math.pow(1 + monthlyRate, application.term) - 1);

      additionalData = { interestRate, term: application.term, monthlyPayment };
    } else if (type === 'rejected') {
      additionalData = {
        reviewNotes:
          reviewNotes || 'Application did not meet our current criteria',
      };
    }

    try {
      await sendLoanNotificationEmail(
        user.email,
        userName,
        type,
        applicationId,
        application.loanType,
        application.amount,
        additionalData
      );

      console.log(`✅ ${type} email notification sent successfully`);
      return res.json({
        success: true,
        message: 'Email notification sent successfully',
      });
    } catch (emailError) {
      console.error(`❌ Email sending failed for ${type}:`, emailError);
      return res.json({
        success: true,
        message: 'Loan notification processed successfully',
        warning: 'Email sending failed, but notification was processed',
        error: emailError.message,
      });
    }
  } catch (error) {
    console.error('❌ Loan notification API error:', error);
    return res.status(500).json({
      error: 'Failed to process loan notification request',
      details: error.message,
    });
  }
});

// Enhanced Share notifications endpoint
app.post('/api/share-notifications', async (req, res) => {
  try {
    const {
      type,
      transactionId,
      userId,
      shares,
      amount,
      purchaseDate,
      rejectionReason,
    } = req.body;

    if (!type || !userId) {
      return res.status(400).json({ error: 'Type and userId are required' });
    }

    console.log(
      `📧 Processing ${type} share notification for transaction: ${transactionId}`
    );

    const db = admin.firestore();

    // Get user details
    const userDoc = await db.collection('users').doc(userId).get();
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userDoc.data();
    if (!user || !user.email) {
      return res.status(404).json({ error: 'User email not available' });
    }

    try {
      const investorName = user.firstName || user.name || 'Valued Investor';
      const purchaseDateObj = purchaseDate
        ? new Date(purchaseDate)
        : new Date();

      // For now, we'll use the basic email system since SharesEmailService isn't available
      // In production, you'd integrate the SharesEmailService here
      let subject, html;

      switch (type) {
        case 'pending':
          subject = '⏳ Share Purchase Pending';
          html = `<h2>Share Purchase Submitted</h2>
                  <p>Hello ${investorName},</p>
                  <p>Your purchase of ${shares} shares for ${amount} ETB is being processed.</p>
                  <p>Transaction ID: ${transactionId}</p>`;
          break;
        case 'confirmed':
          subject = '🎉 Share Purchase Confirmed';
          html = `<h2>Share Purchase Confirmed</h2>
                  <p>Hello ${investorName},</p>
                  <p>Your purchase of ${shares} shares for ${amount} ETB has been confirmed!</p>
                  <p>Transaction ID: ${transactionId}</p>`;
          break;
        case 'rejected':
          subject = '❌ Share Purchase Rejected';
          html = `<h2>Share Purchase Rejected</h2>
                  <p>Hello ${investorName},</p>
                  <p>Your share purchase has been rejected.</p>
                  <p>Reason: ${
                    rejectionReason || 'Payment verification failed'
                  }</p>`;
          break;
      }

      await transporter.sendMail({
        from: 'seadahassen459@gmail.com',
        to: user.email,
        subject,
        html,
      });

      console.log(`✅ ${type} share email sent successfully to ${user.email}`);
      return res.json({ success: true });
    } catch (emailError) {
      console.error(`❌ Failed to send ${type} share email:`, emailError);
      return res.json({
        success: false,
        error: 'Email sending failed',
        details: emailError.message,
      });
    }
  } catch (error) {
    console.error('❌ Error in share notifications API:', error);
    return res.status(500).json({
      error: 'Failed to process share notification',
      details: error.message,
    });
  }
});

// ================================
// ADMIN ENDPOINTS
// ================================

// Admin KYC Approve endpoint
app.post('/api/admin/kyc/approve', async (req, res) => {
  try {
    const { userId, reviewNotes } = req.body;

    if (!userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }

    console.log(`🔄 Attempting to approve KYC for user: ${userId}`);

    const db = admin.firestore();

    // Update user KYC status
    try {
      await db.collection('users').doc(userId).update({
        kycStatus: 'verified',
        accountStatus: 'active',
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      console.log(`✅ User ${userId} KYC status updated successfully`);
    } catch (updateError) {
      console.error('❌ Error updating user:', updateError);
      return res.status(500).json({
        error: 'Failed to update user KYC status',
        details: updateError.message,
      });
    }

    // Create notification for user
    try {
      await db.collection('notifications').add({
        userId: userId,
        title: 'KYC Approved! 🎉',
        message:
          'Your KYC verification has been approved. You can now access all platform features.',
        type: 'success',
        read: false,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      console.log(`✅ Notification created for user ${userId}`);
    } catch (notificationError) {
      console.error('❌ Error creating notification:', notificationError);
      // Don't fail the approval if notification fails
    }

    // Send email notification
    try {
      await fetch(
        `${
          process.env.API_URL || 'http://localhost:3000'
        }/api/kyc-notifications`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ type: 'approved', userId, reviewNotes }),
        }
      );
    } catch (emailError) {
      console.error('❌ Error sending approval email:', emailError);
    }

    return res.json({
      success: true,
      message: 'KYC approved successfully',
      userId,
      approvedAt: new Date(),
    });
  } catch (error) {
    console.error('❌ Error approving KYC:', error);
    return res.status(500).json({
      error: 'Failed to approve KYC',
      details: error.message,
    });
  }
});

// Admin KYC Reject endpoint
app.post('/api/admin/kyc/reject', async (req, res) => {
  try {
    const { userId, reviewNotes } = req.body;

    if (!userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }

    console.log(`🔄 Attempting to reject KYC for user: ${userId}`);

    const db = admin.firestore();

    // Update user KYC status
    await db.collection('users').doc(userId).update({
      kycStatus: 'rejected',
      accountStatus: 'pending_verification',
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // Create notification for user
    await db.collection('notifications').add({
      userId: userId,
      title: 'KYC Application Rejected',
      message: `Your KYC application has been rejected. ${
        reviewNotes
          ? `Reason: ${reviewNotes}`
          : 'Please review your information and try again.'
      }`,
      type: 'error',
      read: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // Send email notification
    try {
      await fetch(
        `${
          process.env.API_URL || 'http://localhost:3000'
        }/api/kyc-notifications`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ type: 'rejected', userId, reviewNotes }),
        }
      );
    } catch (emailError) {
      console.error('❌ Error sending rejection email:', emailError);
    }

    console.log(`❌ KYC rejected for user ${userId}`);
    if (reviewNotes) {
      console.log(`📝 Rejection reason: ${reviewNotes}`);
    }

    return res.json({
      success: true,
      message: 'KYC rejected successfully',
      userId,
      rejectedAt: new Date(),
    });
  } catch (error) {
    console.error('❌ Error rejecting KYC:', error);
    return res.status(500).json({
      error: 'Failed to reject KYC',
      details: error.message,
    });
  }
});

// Admin KYC Request Info endpoint
app.post('/api/admin/kyc/request-info', async (req, res) => {
  try {
    const { userId, requestedInfo, reviewNotes } = req.body;

    if (!userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }

    console.log(`🔄 Attempting to request more info for user: ${userId}`);

    const db = admin.firestore();

    // Update user KYC status
    await db.collection('users').doc(userId).update({
      kycStatus: 'incomplete',
      accountStatus: 'pending_verification',
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // Create notification for user
    await db.collection('notifications').add({
      userId: userId,
      title: 'Additional Information Required',
      message: `Your KYC application requires additional information. ${
        requestedInfo ||
        reviewNotes ||
        'Please provide the requested documents and information.'
      }`,
      type: 'warning',
      read: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // Send email notification
    try {
      await fetch(
        `${
          process.env.API_URL || 'http://localhost:3000'
        }/api/kyc-notifications`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: 'additional_info',
            userId,
            reviewNotes: requestedInfo || reviewNotes,
          }),
        }
      );
    } catch (emailError) {
      console.error('❌ Error sending info request email:', emailError);
    }

    console.log(`⚠️ Additional info requested for user ${userId}`);
    if (requestedInfo || reviewNotes) {
      console.log(`📝 Requested info: ${requestedInfo || reviewNotes}`);
    }

    return res.json({
      success: true,
      message: 'Additional information requested successfully',
      userId,
      requestedAt: new Date(),
    });
  } catch (error) {
    console.error('❌ Error requesting additional info:', error);
    return res.status(500).json({
      error: 'Failed to request additional information',
      details: error.message,
    });
  }
});

// Admin Loan Approve endpoint
app.post('/api/admin/loans/approve', async (req, res) => {
  try {
    const {
      applicationId,
      approvedAmount,
      approvedTerm,
      approvedInterestRate,
      reviewNotes,
    } = req.body;

    if (
      !applicationId ||
      !approvedAmount ||
      !approvedTerm ||
      !approvedInterestRate
    ) {
      return res.status(400).json({
        error:
          'Application ID, approved amount, term, and interest rate are required',
      });
    }

    const db = admin.firestore();

    // Get the loan application
    const applicationDoc = await db
      .collection('loanApplications')
      .doc(applicationId)
      .get();
    if (!applicationDoc.exists) {
      return res.status(404).json({ error: 'Loan application not found' });
    }

    const application = applicationDoc.data();

    // Update loan application status
    await db.collection('loanApplications').doc(applicationId).update({
      status: 'approved',
      approvedAmount,
      approvedTerm,
      approvedInterestRate,
      reviewNotes,
      approvedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // Create notification for user
    await db.collection('notifications').add({
      userId: application.userId,
      title: 'Loan Application Approved! 🎉',
      message: `Your ${
        application.loanType
      } loan application for ${approvedAmount.toLocaleString()} ETB has been approved. The funds will be disbursed shortly.`,
      type: 'success',
      read: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // Send email notification
    try {
      await fetch(
        `${
          process.env.API_URL || 'http://localhost:3000'
        }/api/loan-notifications`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: 'approved',
            applicationId,
            userId: application.userId,
            reviewNotes,
          }),
        }
      );
    } catch (emailError) {
      console.error('❌ Error sending approval email:', emailError);
    }

    console.log(`✅ Loan approved for application ${applicationId}`);
    console.log(`💰 Approved amount: ${approvedAmount} ETB`);
    console.log(`📅 Term: ${approvedTerm} months`);
    console.log(`📊 Interest rate: ${approvedInterestRate}%`);

    return res.json({
      success: true,
      message: 'Loan application approved successfully',
      applicationId,
      approvedAt: new Date(),
      approvedAmount,
      approvedTerm,
      approvedInterestRate,
    });
  } catch (error) {
    console.error('❌ Error approving loan:', error);
    return res.status(500).json({
      error: 'Failed to approve loan application',
      details: error.message,
    });
  }
});

// Admin Loan Reject endpoint
app.post('/api/admin/loans/reject', async (req, res) => {
  try {
    const { applicationId, rejectionReason, reviewNotes } = req.body;

    if (!applicationId || !rejectionReason) {
      return res.status(400).json({
        error: 'Application ID and rejection reason are required',
      });
    }

    const db = admin.firestore();

    // Get the loan application
    const applicationDoc = await db
      .collection('loanApplications')
      .doc(applicationId)
      .get();
    if (!applicationDoc.exists) {
      return res.status(404).json({ error: 'Loan application not found' });
    }

    const application = applicationDoc.data();

    // Update loan application status
    await db.collection('loanApplications').doc(applicationId).update({
      status: 'rejected',
      rejectionReason,
      reviewNotes,
      rejectedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // Create notification for user
    await db.collection('notifications').add({
      userId: application.userId,
      title: 'Loan Application Rejected',
      message: `Your ${application.loanType} loan application has been rejected. Reason: ${rejectionReason}. You may reapply after addressing the concerns.`,
      type: 'error',
      read: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // Send email notification
    try {
      await fetch(
        `${
          process.env.API_URL || 'http://localhost:3000'
        }/api/loan-notifications`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: 'rejected',
            applicationId,
            userId: application.userId,
            reviewNotes: rejectionReason,
          }),
        }
      );
    } catch (emailError) {
      console.error('❌ Error sending rejection email:', emailError);
    }

    console.log(`❌ Loan rejected for application ${applicationId}`);
    console.log(`📝 Rejection reason: ${rejectionReason}`);

    return res.json({
      success: true,
      message: 'Loan application rejected successfully',
      applicationId,
      rejectedAt: new Date(),
      rejectionReason,
    });
  } catch (error) {
    console.error('❌ Error rejecting loan:', error);
    return res.status(500).json({
      error: 'Failed to reject loan application',
      details: error.message,
    });
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
  console.log(`   - POST /api/onboarding`);
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
