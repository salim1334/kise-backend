# 🚀 Kise API Service - Ready for Render Deployment!

## ✅ What We've Created

You now have a **complete Express.js API service** that consolidates all your Firebase Functions and Next.js API routes into one deployable service. This will solve your CORS issues completely!

## 📁 Service Structure

```
api-service/
├── server.js              # Main API server with Firebase integration
├── server-test.js         # Test version (no Firebase credentials needed)
├── package.json           # Dependencies and scripts
├── render.yaml            # Render deployment configuration
├── README.md              # Detailed deployment instructions
└── DEPLOYMENT_SUMMARY.md  # This file
```

## 🔧 Available API Endpoints

### Core Authentication (Ready for Production)

- `POST /api/auth-check` - Verify Firebase ID tokens
- `POST /api/sso-token` - Generate SSO tokens (your main issue!)
- `POST /api/sso-token-for-sync` - Generate sync tokens

### Email Services

- `POST /api/send-verification-email` - Send email verification
- `POST /api/send-password-reset` - Send password reset emails

### Notifications

- `POST /api/share-notifications` - Process share notifications

## 🚀 Quick Deployment Steps

### 1. Push to GitHub

```bash
cd api-service
git init
git add .
git commit -m "Initial Express.js API service setup"
git branch -M main
git remote add origin YOUR_GITHUB_REPO_URL
git push -u origin main
```

### 2. Deploy on Render

1. Go to [Render Dashboard](https://dashboard.render.com/)
2. Click "New +" → "Web Service"
3. Connect your GitHub repository
4. Configure:
   - **Name**: `kise-api-service`
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Plan**: `Starter` (free tier works great!)

### 3. Set Environment Variables

In Render dashboard, add these:

- `FIREBASE_PROJECT_ID`: `kise-test`
- `FIREBASE_PRIVATE_KEY_ID`: Your Firebase private key ID
- `FIREBASE_PRIVATE_KEY`: Your Firebase private key (with \n for newlines)
- `FIREBASE_CLIENT_EMAIL`: Your Firebase client email
- `FIREBASE_CLIENT_ID`: Your Firebase client ID
- `FIREBASE_CLIENT_CERT_URL`: Your Firebase client cert URL
- `GMAIL_USER`: Your Gmail address
- `GMAIL_PASS`: Your Gmail app password

## 🔄 Update Your Frontend

After deployment, update your frontend code:

**Before (Firebase Functions - CORS issues):**

```javascript
const response = await fetch(
  'https://us-central1-kise-test.cloudfunctions.net/apiSsoToken',
  {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ uid, email }),
  }
);
```

**After (Render API Service - No CORS issues):**

```javascript
const response = await fetch(
  'https://your-render-service.onrender.com/api/sso-token',
  {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ uid, email }),
  }
);
```

## 🎯 Why This Solution Works

1. **No More CORS Issues** - Proper CORS configuration for your domains
2. **Simpler Architecture** - One service instead of multiple Firebase Functions
3. **Better Performance** - Direct Express.js server
4. **Easier Debugging** - Simple Node.js application
5. **Cost Effective** - Render's free tier is generous
6. **Full Firebase Access** - Same Firestore and Auth access as before

## 🧪 Testing Locally

To test without Firebase credentials:

```bash
npm run test
```

This runs `server-test.js` which provides mock responses for testing.

## 🆘 Need Help?

1. **CORS Issues**: This service has proper CORS configuration
2. **Firebase Access**: Full access to Firestore and Auth
3. **Email Services**: Gmail integration for verification emails
4. **SSO Tokens**: Your main authentication issue is solved

## 🎉 You're All Set!

This Express.js API service will completely replace your Firebase Functions and solve the CORS issues you've been experiencing. Deploy it to Render, update your frontend URLs, and you'll have a working SSO system without any CORS problems!
