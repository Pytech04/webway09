# Deploy to Render NOW

## Simple 3-Step Deploy

### 1. Commit and Push
```bash
git add .
git commit -m "Ready for Render"
git push
```

### 2. Go to Render Dashboard
- Visit https://render.com/dashboard
- Click "New Web Service"
- Select your GitHub repository (Pytech04/WayBackLook)
- Render will auto-detect `render.yaml` configuration

### 3. Click Deploy
- Render will automatically use the settings from `render.yaml`
- Build: `npm ci && npm run build`
- Start: `bash start.sh`
- Your app lives at `your-service-name.onrender.com`

## What's Different Now

✅ **render.yaml** - Configuration is now in code (not manual setup)
✅ **Node environment** - Render will use Node.js, not Python for build
✅ **Auto-detected** - Render reads render.yaml automatically

## Why Previous Deploy Failed

Render saw Python files and tried to use Python/Poetry instead of Node/npm. Now it knows to use Node!

## Monitoring Deployment

Once you click "Deploy" on Render:
1. **Build Phase** - Render runs `npm ci && npm run build` (~2-3 min)
   - Installs Node dependencies (vite, esbuild, etc.)
   - Builds React frontend
   - Bundles Node proxy

2. **Start Phase** - Render runs `bash start.sh`
   - Starts Flask backend (Python)
   - Waits for Flask to initialize
   - Starts Node proxy on assigned PORT

3. **Live** - Your app is available!

## Troubleshooting

If build still fails, check:
- Do you have `render.yaml` in your repo root? ✓
- Did you push to GitHub? (`git push`)
- Did Render detect the config? (Check deploy settings)

If app crashes:
- Check "Logs" tab in Render dashboard
- Look for Flask or Node startup errors

## Done! 🚀

Your Python Wayback forensic scraper is ready to deploy!
