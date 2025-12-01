# VulnScan AI - Netlify Deployment Guide

## 🎯 What Gets Deployed Where

- **Frontend (React/Vite)** → Netlify ✅
- **Backend (Python/FastAPI with Nmap)** → Separate server (Railway, Render, or custom) ⚠️
- **Edge Functions & Database** → Supabase (already configured) ✅

---

## 📋 Prerequisites Checklist

Before you start, make sure you have:

- [ ] A GitHub account
- [ ] A Netlify account (free tier works)
- [ ] This project pushed to a GitHub repository
- [ ] Supabase project already set up (you have this)
- [ ] Backend deployment URL (we'll set this up in Step 2)

---

## 🚀 Step 1: Deploy Frontend to Netlify

### 1.1 Connect Repository

1. Go to [Netlify Dashboard](https://app.netlify.com/)
2. Click **"Add new site"** → **"Import an existing project"**
3. Choose **"Deploy with GitHub"**
4. Authorize Netlify to access your GitHub repositories
5. Select your VulnScan AI repository
6. Click **"Deploy site"**

### 1.2 Configure Build Settings

Netlify should auto-detect these settings, but verify:

| Setting | Value |
|---------|-------|
| **Build command** | `npm run build` |
| **Publish directory** | `dist` |
| **Node version** | 18 or higher |

### 1.3 Set Environment Variables

Click **"Site configuration"** → **"Environment variables"** → **"Add a variable"**

Add these variables:

```
VITE_SUPABASE_URL = https://bliwnrikjfzcialoznur.supabase.co
VITE_SUPABASE_PUBLISHABLE_KEY = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJsaXducmlramZ6Y2lhbG96bnVyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDk1MDkwNDYsImV4cCI6MjA2NTA4NTA0Nn0.KVx5uaBmj5_IESBMgB7H72tWCBKWuj2-IU-9HpunCC4
VITE_BACKEND_URL = [YOU'LL ADD THIS IN STEP 2]
```

### 1.4 Deploy

1. Click **"Deploy site"**
2. Wait 2-3 minutes for build to complete
3. Your site will be live at: `https://random-name-123456.netlify.app`

### 1.5 Configure Custom Domain (Optional)

1. Click **"Domain management"** → **"Add custom domain"**
2. Follow Netlify's instructions to configure DNS
3. Netlify automatically provisions free SSL certificate

---

## 🖥️ Step 2: Deploy Backend

**Important:** The Python backend requires Nmap with raw socket capabilities, which Netlify doesn't support.

### Option A: Railway (Recommended - Easiest)

1. **Go to [Railway.app](https://railway.app/)**
2. Click **"Start a New Project"** → **"Deploy from GitHub repo"**
3. Select your repository
4. Railway will detect it's a Python project

5. **Add Environment Variables:**
   ```
   VITE_SUPABASE_URL=https://bliwnrikjfzcialoznur.supabase.co
   VITE_SUPABASE_PUBLISHABLE_KEY=your_anon_key
   ```

6. **Configure Start Command:**
   - Go to **Settings** → **Deploy**
   - Set start command: `python start_backend.py`

7. **Install Nmap in Railway:**
   - Add a `nixpacks.toml` file to your repo:
   ```toml
   [phases.setup]
   aptPkgs = ["nmap"]
   ```

8. **Get Your Backend URL:**
   - Railway will provide a URL like: `https://your-app.up.railway.app`
   - Copy this URL

9. **Update Netlify Environment Variable:**
   - Go back to Netlify → Environment variables
   - Set `VITE_BACKEND_URL` to your Railway URL
   - Redeploy: **Deploys** → **Trigger deploy** → **Deploy site**

### Option B: Render.com

1. Go to [Render Dashboard](https://dashboard.render.com/)
2. Click **"New"** → **"Web Service"**
3. Connect your GitHub repository
4. Configure:
   - **Name:** vulnscan-backend
   - **Environment:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python start_backend.py`
5. Add environment variables (same as Railway)
6. Click **"Create Web Service"**
7. Copy your Render URL and update Netlify's `VITE_BACKEND_URL`

### Option C: Local Backend (For Testing Only)

If you're just testing, you can run the backend locally:

1. On your local machine:
   ```bash
   cd path/to/vulnscan
   python start_backend.py
   ```

2. Use ngrok to expose it:
   ```bash
   ngrok http 8000
   ```

3. Copy the ngrok URL to Netlify's `VITE_BACKEND_URL`

**Note:** This only works while your computer is running!

---

## 🔐 Step 3: Configure Supabase Authentication

Your frontend is now deployed, so you need to tell Supabase about the new URL:

1. Go to [Supabase Dashboard](https://supabase.com/dashboard/project/bliwnrikjfzcialoznur)
2. Navigate to **Authentication** → **URL Configuration**
3. Add your Netlify URL to **Redirect URLs**:
   ```
   https://your-site-name.netlify.app/**
   ```
4. Update **Site URL** to:
   ```
   https://your-site-name.netlify.app
   ```
5. Click **"Save"**

---

## ✅ Step 4: Test Your Deployment

### 4.1 Test Frontend
1. Visit your Netlify URL
2. You should see the login page
3. Try registering a new account
4. Check that you receive a confirmation email

### 4.2 Test Backend Connection
1. After logging in, try to create a new scan
2. Open browser DevTools (F12) → **Network** tab
3. Look for requests to your `VITE_BACKEND_URL`
4. Should see status `200 OK`

### 4.3 Test Edge Functions
1. Try the **AI Chat** feature (Gemini Chat)
2. Try the **CVE Lookup** feature
3. Run a scan and generate a report

### 4.4 Verify Database
1. Check **Scan History** shows your scans
2. Verify data is saving in Supabase dashboard

---

## 🔧 Troubleshooting

### Frontend shows "Failed to fetch"
- **Cause:** Backend URL not set or incorrect
- **Fix:** Check `VITE_BACKEND_URL` in Netlify environment variables
- **Fix:** Verify backend is running (visit backend URL in browser)

### "Invalid login credentials" error
- **Cause:** Supabase redirect URLs not configured
- **Fix:** Add Netlify URL to Supabase → Authentication → URL Configuration

### Scans failing with "Operation not permitted"
- **Cause:** Nmap doesn't have raw socket capabilities
- **Fix:** On Railway, add `nixpacks.toml` with nmap package
- **Fix:** On Render, add install script in build command

### Backend deployment fails
- **Cause:** Missing dependencies or environment variables
- **Fix:** Ensure `requirements.txt` exists
- **Fix:** Verify all environment variables are set

### SSL/HTTPS errors
- **Cause:** Mixed content (HTTPS frontend calling HTTP backend)
- **Fix:** Ensure backend URL uses `https://`
- **Fix:** Railway and Render provide HTTPS by default

---

## 🎉 Step 5: Create Your First Admin User

After deployment, you need an admin user:

1. Register a normal user account via the `/auth` page
2. Go to [Supabase SQL Editor](https://supabase.com/dashboard/project/bliwnrikjfzcialoznur/sql/new)
3. Run this query (replace with your user's email):
   ```sql
   -- First, find your user ID
   SELECT id, email FROM auth.users WHERE email = 'your-email@example.com';
   
   -- Then add admin role (use the ID from above)
   INSERT INTO public.user_roles (user_id, role)
   VALUES ('your-user-id-here', 'admin');
   ```
4. Refresh the page - you should now see the admin menu

---

## 📊 Monitoring Your Deployment

### Netlify
- **Build logs:** Netlify Dashboard → Deploys → Click on latest deploy
- **Function logs:** Netlify Dashboard → Functions → Select function
- **Analytics:** Netlify Dashboard → Analytics

### Supabase
- **Database:** [Database Tables](https://supabase.com/dashboard/project/bliwnrikjfzcialoznur/editor)
- **Auth users:** [User Management](https://supabase.com/dashboard/project/bliwnrikjfzcialoznur/auth/users)
- **Edge function logs:** [Functions](https://supabase.com/dashboard/project/bliwnrikjfzcialoznur/functions)

### Railway/Render
- **Application logs:** Available in the dashboard
- **Metrics:** CPU, memory usage shown in dashboard

---

## 🔄 Updating Your Deployment

### Frontend Updates
1. Push changes to GitHub
2. Netlify automatically rebuilds and deploys
3. No manual action needed!

### Backend Updates
1. Push changes to GitHub
2. Railway/Render automatically rebuilds
3. No manual action needed!

### Manual Redeploy
- **Netlify:** Deploys → Trigger deploy → Clear cache and deploy site
- **Railway:** Deployments → Deploy latest commit
- **Render:** Manual Deploy → Deploy latest commit

---

## 💰 Cost Estimate

| Service | Free Tier | Paid Plan |
|---------|-----------|-----------|
| **Netlify** | 100GB bandwidth/month | $19/month |
| **Railway** | $5 free credit/month | Pay as you go (~$5-10/month) |
| **Render** | 750 hours/month free | $7/month for always-on |
| **Supabase** | 500MB database, 1GB storage | $25/month for Pro |

**Total Free Tier:** Suitable for development and light usage  
**Total Paid (recommended for production):** ~$50-60/month

---

## 🆘 Need Help?

- **Netlify Docs:** https://docs.netlify.com/
- **Railway Docs:** https://docs.railway.app/
- **Supabase Docs:** https://supabase.com/docs
- **Project Issues:** Create an issue on GitHub

---

## 🎯 Quick Reference

### Essential URLs
- **Frontend:** `https://your-site.netlify.app`
- **Backend:** `https://your-app.railway.app` or `https://your-app.onrender.com`
- **Supabase:** `https://bliwnrikjfzcialoznur.supabase.co`

### Key Files for Deployment
- `netlify.toml` - Netlify build configuration
- `public/_redirects` - SPA routing for Netlify
- `requirements.txt` - Python dependencies
- `start_backend.py` - Backend entry point
- `supabase/config.toml` - Edge function configuration

---

**🎊 Congratulations!** Your VulnScan AI platform is now deployed and ready for production use!
