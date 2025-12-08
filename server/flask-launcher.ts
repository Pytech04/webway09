import { spawn } from 'child_process';
import { setupVite } from "./index-dev";
import express from "express";
import { createServer } from "http";

const app = express();

// Start Flask backend
console.log("Starting Flask backend on port 5001...");
const flaskProcess = spawn('python', ['server.py'], {
  stdio: 'inherit',
  detached: false
});

flaskProcess.on('error', (err) => {
  console.error('Failed to start Flask:', err);
  process.exit(1);
});

// Give Flask time to start
await new Promise(resolve => setTimeout(resolve, 2000));

// Proxy API requests to Flask backend
app.use("/api/*", async (req, res) => {
  const flaskUrl = `http://localhost:5001${req.originalUrl}`;
  
  try {
    const fetch = (await import('node-fetch')).default;
    const response = await fetch(flaskUrl, {
      method: req.method,
      headers: req.headers as any,
    });
    
    // Forward SSE headers
    res.status(response.status);
    response.headers.forEach((value, key) => {
      res.setHeader(key, value);
    });
    
    // Stream the response
    if (response.body) {
      response.body.pipe(res);
    } else {
      res.end();
    }
  } catch (error) {
    console.error("[Proxy Error]:", error);
    res.status(500).json({ error: "Failed to connect to Flask backend. Make sure Flask is running on port 5001." });
  }
});

const server = createServer(app);

// Set up Vite for frontend
await setupVite(app, server);

const port = 5000;
server.listen(port, "0.0.0.0", () => {
  console.log(`\n===========================================`);
  console.log(`✓ Flask backend running on http://localhost:5001`);
  console.log(`✓ Vite + Proxy running on http://0.0.0.0:${port}`);
  console.log(`===========================================\n`);
});

// Cleanup on exit
process.on('SIGINT', () => {
  console.log('\nShutting down...');
  flaskProcess.kill();
  process.exit();
});

process.on('SIGTERM', () => {
  flaskProcess.kill();
  process.exit();
});
