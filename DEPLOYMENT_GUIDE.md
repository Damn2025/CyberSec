# Step-by-Step Deployment Guide: GitHub + Netlify

This guide will walk you through deploying your CyberSec project to Netlify using GitHub.

## Prerequisites
- A GitHub account
- A Netlify account (free tier works)
- Git installed on your computer
- Node.js and npm installed

---

## Part 1: Setting Up GitHub Repository

### Step 1: Initialize Git Repository (if not already done)
Open your terminal in the project directory and run:

```bash
# Check if git is already initialized
git status

# If not initialized, run:
git init
```

### Step 2: Create a .gitignore file (if needed)
Ensure your `.gitignore` includes:
- `node_modules/`
- `dist/`
- `.env` files
- Build artifacts

### Step 3: Stage and Commit Your Code
```bash
# Add all files to staging
git add .

# Create your first commit
git commit -m "Initial commit: CyberSec project"
```

### Step 4: Create GitHub Repository
1. Go to [GitHub.com](https://github.com) and sign in
2. Click the **"+"** icon in the top right → **"New repository"**
3. Repository name: `cybersec` (or your preferred name)
4. Description: "Advanced Security Vulnerability Scanner"
5. Choose **Public** or **Private**
6. **DO NOT** initialize with README, .gitignore, or license (you already have code)
7. Click **"Create repository"**

### Step 5: Connect Local Repository to GitHub
GitHub will show you commands. Run these in your terminal:

```bash
# Add the remote repository (replace YOUR_USERNAME with your GitHub username)
git remote add origin https://github.com/YOUR_USERNAME/cybersec.git

# Rename your branch to main (if needed)
git branch -M main

# Push your code to GitHub
git push -u origin main
```

**Note:** You may be prompted to enter your GitHub credentials. Use a Personal Access Token if password authentication fails.

---

## Part 2: Setting Up Netlify Deployment

### Step 6: Create Netlify Account
1. Go to [Netlify.com](https://netlify.com)
2. Click **"Sign up"**
3. Choose **"Sign up with GitHub"** (recommended for easier integration)
4. Authorize Netlify to access your GitHub account

### Step 7: Create New Site from Git
1. In Netlify dashboard, click **"Add new site"** → **"Import an existing project"**
2. Click **"Deploy with GitHub"**
3. Authorize Netlify if prompted
4. Select your repository: `cybersec` (or whatever you named it)

### Step 8: Configure Build Settings
Netlify should auto-detect Vite, but verify these settings:

**Build command:**
```
npm run build
```

**Publish directory:**
```
dist/client
```

**Base directory:**
```
(leave empty or use root)
```

### Step 9: Environment Variables (if needed)
If your app uses environment variables (like Supabase keys):

1. In Netlify dashboard, go to **Site settings** → **Environment variables**
2. Click **"Add variable"**
3. Add each variable:
   - **Key:** `VITE_SUPABASE_URL` (or your variable name)
   - **Value:** Your actual value
4. Click **"Save"**

**Important:** For Vite projects, environment variables must start with `VITE_` to be accessible in the browser.

### Step 10: Deploy
1. Click **"Deploy site"**
2. Netlify will:
   - Clone your repository
   - Install dependencies (`npm install`)
   - Run the build command (`npm run build`)
   - Deploy the `dist/client` folder

### Step 11: Wait for Deployment
- Watch the build logs in real-time
- First deployment may take 2-5 minutes
- You'll see a success message when done
- Your site will be live at: `https://random-name-123.netlify.app`

---

## Part 3: Post-Deployment Configuration

### Step 12: Configure Custom Domain (Optional)
1. In Netlify dashboard → **Site settings** → **Domain management**
2. Click **"Add custom domain"**
3. Enter your domain name
4. Follow DNS configuration instructions

### Step 13: Set Up Continuous Deployment
✅ **Already enabled!** Every time you push to GitHub:
- Netlify automatically detects changes
- Runs a new build
- Deploys the updated site

### Step 14: Configure Redirects (if using React Router)
Create a `netlify.toml` file in your project root:

```toml
[[redirects]]
  from = "/*"
  to = "/index.html"
  status = 200
```

This ensures React Router works correctly with Netlify's hosting.

### Step 15: Update and Redeploy
To make changes:

```bash
# Make your changes
# Stage them
git add .

# Commit
git commit -m "Your commit message"

# Push to GitHub
git push origin main
```

Netlify will automatically deploy the changes!

---

## Troubleshooting

### Build Fails
- Check build logs in Netlify dashboard
- Ensure all dependencies are in `package.json`
- Verify build command is correct
- Check for TypeScript errors locally first

### Site Shows 404
- Verify publish directory is `dist/client`
- Check that `index.html` exists in the publish directory
- Add the redirect rule in `netlify.toml`

### Environment Variables Not Working
- Ensure variables start with `VITE_` prefix
- Redeploy after adding variables
- Check variable names match exactly

### Routing Issues
- Add the redirect rule in `netlify.toml`
- Ensure React Router is configured correctly

---

## Quick Reference Commands

```bash
# Check git status
git status

# Add all changes
git add .

# Commit changes
git commit -m "Your message"

# Push to GitHub
git push origin main

# Build locally (test before deploying)
npm run build

# Check build output
ls -la dist/client
```

---

## Summary Checklist

- [ ] Git repository initialized
- [ ] Code committed locally
- [ ] GitHub repository created
- [ ] Code pushed to GitHub
- [ ] Netlify account created
- [ ] Site connected to GitHub repository
- [ ] Build settings configured (`npm run build`, `dist/client`)
- [ ] Environment variables added (if needed)
- [ ] Initial deployment successful
- [ ] `netlify.toml` created for routing (if needed)
- [ ] Custom domain configured (optional)

---

**Your site is now live! 🎉**

Every push to GitHub will automatically trigger a new deployment on Netlify.



