# Deploying to Render

## Quick Start

1. **Push to GitHub** (Render pulls from GitHub)
   ```bash
   git add .
   git commit -m "Ready for Render deployment"
   git push
   ```

2. **Create New Web Service on Render**
   - Go to [render.com](https://render.com)
   - Click "New +"
   - Select "Web Service"
   - Connect your GitHub repository
   - Select the branch to deploy

3. **Configure Service**
   - **Environment**: Node
   - **Build Command**: `npm run build`
   - **Start Command**: `bash start.sh`
   - **Region**: Choose closest to your users

4. **Set Environment Variables** (optional)
   - No required environment variables
   - Optional: `NODE_ENV=production` (already set in start.sh)

5. **Deploy**
   - Click "Create Web Service"
   - Render will build and deploy automatically
   - Your app will be live at `your-app-name.onrender.com`

## How It Works

The app uses a **Python/Flask backend** with a **Node.js proxy frontend**:

- **Flask** (port 5001): Handles Wayback Machine API requests, searches archived snapshots
- **Node.js Proxy** (Render-assigned PORT): Serves React frontend, proxies `/api/*` to Flask

The `start.sh` script automatically:
1. Starts Flask backend on port 5001
2. Waits 3 seconds for Flask to initialize
3. Starts Node.js proxy on Render's assigned PORT
4. Handles graceful shutdown of both processes

## Architecture

```
Browser (onrender.com)
    ↓
Node.js Proxy (port 5000/Render PORT)
    ├── Serves: React frontend, Vite assets
    └── Proxies: /api/* → Flask backend
    ↓
Flask Backend (port 5001, internal only)
    └── Processes: Wayback CDX API, HTML parsing, keyword matching
```

## Build Output

- **Frontend**: React app compiled to `dist/public/` (Vite)
- **Backend**: Node.js proxy bundled to `dist/index.js` (esbuild)
- **Python**: `server.py` runs directly in the container

## Troubleshooting

### Build fails?
- Ensure `npm run build` works locally: `npm run build`
- Check build output in Render dashboard

### App crashes on startup?
- Check Render "Logs" tab for errors
- Ensure start.sh is executable: `chmod +x start.sh`
- Flask needs Python 3 (included in Node buildpack)

### Scans timeout (Pro tier issue)?
- Render free tier has 30s timeout
- Upgrade to Pro tier for unlimited connection time
- Or deploy to a platform with longer timeouts

## File Structure for Deployment

```
.
├── Procfile              ← Tells Render how to start the app
├── start.sh              ← Starts Flask + Node proxy
├── server.py             ← Flask backend (Python)
├── server/               ← Node.js code
│   ├── app.ts
│   ├── routes.ts         ← Spawns Flask, proxies requests
│   └── ...
├── client/               ← React frontend
├── dist/                 ← Built for production
│   ├── index.js          ← Node proxy bundle
│   └── public/           ← Vite frontend assets
└── package.json
```

## What You Get

✅ Python backend for your portfolio  
✅ Real-time Wayback Machine searching  
✅ Professional web interface  
✅ SSE streaming for live updates  
✅ Exhaustive keyword matching (text, JS, HTML comments)  
✅ Downloadable forensic reports  
✅ Production-ready deployment  

## After Deployment

1. Your app is live at `your-app-name.onrender.com`
2. Share the link with anyone
3. No installation needed - just open in browser
4. Python code running on the backend

Enjoy your Wayback forensic scraper! 🔍
