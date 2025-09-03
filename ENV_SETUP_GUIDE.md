# 🔧 Environment Variables Setup Guide

## 📋 **What You Need to Do**

### **Step 1: Create .env file in api-service folder**

1. In the `api-service` folder, create a new file called `.env`
2. Copy the contents from `env-template.txt` into it
3. Fill in the missing values

### **Step 2: Get Missing Firebase Values**

You need to get these from **Firebase Console > Project Settings > Service Accounts**:

1. **FIREBASE_PRIVATE_KEY_ID**: Found in your service account JSON
2. **FIREBASE_CLIENT_ID**: Found in your service account JSON
3. **FIREBASE_CLIENT_CERT_URL**: Auto-generated URL

### **Step 3: Your Complete .env File Should Look Like This**

```bash
# Firebase Admin SDK Configuration
FIREBASE_PROJECT_ID=kise-test
FIREBASE_PRIVATE_KEY_ID=1234567890abcdef1234567890abcdef12345678
FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDebKCQHxWh9/G8\nTH7BM0opAM3dF/vD6t1MAcDxvdIFKEHyaMQqEdDE9IqfTc0MMOVn4dKedKMbV4fV\nUCTFBhpu8o5aaySlkVbrMvKsX5IsDQ6EnwHbRjyF0/1s+wMREXWfCco55J39pcUz\nvGXCav1IwxHDIAdkNNuhAyJDWWhqEsiKgPDoFCS0D2tF7MrRWro4ECHUphPnCMiv\n31k4BPHWDKvA+pRa3zHJ4fyrLe+KhV8HsZ2v+kYuT60Y6bDEKhfLBoj9FJ9Ttn0n\nBX9Aualaq274+3lvc9tnHYiFq2LXarcYcBk5p+YnXkX0JI1x7KF6e6ZSLrV0hOqQ\nc/SDZCiXAgMBAAECggEAA9jSIBwBhkchDbYu/Q1zi2kBpoDLMHTH9hATs7qqPr+X\nAGfSeL3NJBLssNuqH7taxGSx/V6cEZV+enCD6kp0O5YDY0n2HMz6OWAstVGD2DIz\nnZSYdh/tXQ0xFWj0ASARrjn/nue22dO7qOzpv6aVEeSZ0oujxRZq9Ap3Vb3eofL/\n8v+jA8JtqMKsJPJwZLZ0EJ04OG4OVQsOIZVG6UvFiYv1jxr4S5+YEbzpSMDayZEy\nIWQJJu425j+0eqB/mynuuWdtF30+/J7rlh06QMIxfH2Grov7jwty+6fC4uTk9CoL\nYdrt+EykvqQ/BuBcHE3ZuOq1htNWACBI24maISz6TQKBgQD9bkcK9ey/xdRXOMlX\nCZW5mqGqQJGDRD5pNpIZGhPvSX2fZxSM0OlLr4fFug76vUAWNLsAi5XeQT/HjaNl\nc9jCsqdrcdpNci7SjOaGygSgPB30Hf19W62ADNuh+5RLeQgvKgYwUy66Mza3h0kW\nXxFal62UskHpXaxyncoTXMXVGwKBgQDgreEi8tgjuwBEIVVJvPagY1LzbES5fgCm\neN7spjM4rlLy0M01XX5EqKRJw1ro9mEE79WhU/augx2CUkC1UDIwxTmgGpDTUpaj\neuIFdAJVajWV8NzC0Xx/dv990sAPkExGO1ubm7EPNNzDIiB3CWEzEFQ8alEdEJIB\n3nWOxB++NQKBgQDtqz7623lEu+2QQtQnSPjeUFLujJEqbpStLR1EZz1suhoSpKQU\nD1PKw/nrh7rGkTcJ3DfHoiBRiBWdOoqS+Vq99LenvuVAniWlFbiXjdtaviZFKt7w\nckq6/NP5DCudwArZ2GpnZYs72g2lfj0futZWhEqoWagQh+XSs4GwON/bIwKBgQCW\nStnh5e49IHcSG/YQSE31hdtUJ+Vk62uF8C62wIpc7Qdhk9jhTLQNO34CNaKXWVAW\n3FPcAe1uWRihN2I/pvCb/SIJ/htIsONBYg7VNP/moRBNR3x0+Wq9XR2UzihZgN30\n0Pn7gk8Ta/oMscRjvCt/2/ltHHU76vywMV4T7Q+KzQKBgG6t//tScYKNZcdDJLyX\nE2FTHxHsDcvA22G3UvxA0zoaHdwGDY4Y+HYYX3o8gDMG7oRJqHrCAIeZ4C7ASKht\nRptaGlzpc1SMZXxAIBudvJwObV531RY1Lq+W+gmTTW18TLnbuAAa2otNVwCMvRV7\nYXJjkSARFYPP4YO8Z7mTiKqT\n-----END PRIVATE KEY-----\n"
FIREBASE_CLIENT_EMAIL=firebase-adminsdk-fbsvc@kise-test.iam.gserviceaccount.com
FIREBASE_CLIENT_ID=123456789012345678901
FIREBASE_CLIENT_CERT_URL=https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40kise-test.iam.gserviceaccount.com

# Gmail Configuration for sending emails
GMAIL_USER=seadahassen459@gmail.com
GMAIL_PASS=haqm lfor zmxr jtxe

# Server Configuration
NODE_ENV=production
PORT=3000
```

## 🔍 **Where to Find Missing Values**

### **Firebase Console Steps:**

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Select your `kise-test` project
3. Click the gear icon ⚙️ → **Project Settings**
4. Go to **Service Accounts** tab
5. Click **Generate new private key**
6. Download the JSON file
7. Copy these values:
   - `private_key_id` → `FIREBASE_PRIVATE_KEY_ID`
   - `client_id` → `FIREBASE_CLIENT_ID`

## ⚠️ **Important Notes**

1. **Keep your .env file private** - never commit it to Git
2. **The private key** should include the `\n` characters for newlines
3. **Gmail password** should be an "App Password" if you have 2FA enabled
4. **For Render deployment**, you'll set these same variables in the Render dashboard

## 🚀 **After Setting Up .env**

1. **Test locally:**

   ```bash
   npm start
   ```

2. **Deploy to Render** (see README.md for full instructions)

3. **Update your frontend** to use the new API URLs

## 🆘 **Need Help?**

- Check the `README.md` for deployment instructions
- Check `DEPLOYMENT_SUMMARY.md` for quick reference
- The Express.js service will solve your CORS issues completely!
