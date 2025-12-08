import type { Express } from "express";
import { createServer, type Server } from "http";
import { spawn, type ChildProcess } from "child_process";
import fetch from "node-fetch";

let flaskProcess: ChildProcess | null = null;
const FLASK_PORT = 5001;
const FLASK_URL = `http://localhost:${FLASK_PORT}`;

async function waitForFlask(maxAttempts = 20): Promise<boolean> {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const response = await fetch(`${FLASK_URL}/api/scan?domain=test&keyword=test`, {
        method: 'HEAD',
        signal: AbortSignal.timeout(1000)
      });
      if (response.ok || response.status === 400) {
        console.log(`[Flask] Backend ready on port ${FLASK_PORT}`);
        return true;
      }
    } catch (error) {
      // Flask not ready yet, wait and retry
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }
  return false;
}

async function startFlask(): Promise<void> {
  console.log(`[Flask] Starting Python backend on port ${FLASK_PORT}...`);
  
  flaskProcess = spawn('python', ['server.py'], {
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: false
  });

  if (flaskProcess.stdout) {
    flaskProcess.stdout.on('data', (data) => {
      console.log(`[Flask] ${data.toString().trim()}`);
    });
  }

  if (flaskProcess.stderr) {
    flaskProcess.stderr.on('data', (data) => {
      const msg = data.toString().trim();
      // Filter out Flask's normal startup messages
      if (!msg.includes('WARNING') && !msg.includes('* Running on')) {
        console.error(`[Flask] ${msg}`);
      }
    });
  }

  flaskProcess.on('error', (err) => {
    console.error('[Flask] Failed to start:', err);
    process.exit(1);
  });

  flaskProcess.on('exit', (code) => {
    if (code !== null && code !== 0) {
      console.error(`[Flask] Process exited with code ${code}`);
    }
  });

  // Wait for Flask to be ready
  const isReady = await waitForFlask();
  if (!isReady) {
    console.error('[Flask] Backend failed to start within timeout');
    process.exit(1);
  }
}

function setupFlaskProxy(app: Express): void {
  // Proxy all /api requests to Flask
  app.use("/api/*", async (req, res) => {
    const flaskUrl = `${FLASK_URL}${req.originalUrl}`;
    
    try {
      const response = await fetch(flaskUrl, {
        method: req.method,
        headers: req.headers as any,
        signal: AbortSignal.timeout(120000) // 2 minute timeout for long scans
      });

      // Copy response headers
      res.status(response.status);
      response.headers.forEach((value, key) => {
        res.setHeader(key, value);
      });

      // Stream the response (important for SSE)
      if (response.body) {
        response.body.pipe(res);
      } else {
        res.end();
      }
    } catch (error) {
      console.error("[Proxy Error]:", error);
      res.status(500).json({ 
        error: "Failed to connect to Flask backend",
        details: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
}

function setupCleanupHandlers(): void {
  const cleanup = () => {
    if (flaskProcess) {
      console.log('\n[Flask] Shutting down backend...');
      flaskProcess.kill('SIGTERM');
      
      // Force kill after 2 seconds if still running
      setTimeout(() => {
        if (flaskProcess && !flaskProcess.killed) {
          flaskProcess.kill('SIGKILL');
        }
      }, 2000);
    }
  };

  process.on('SIGINT', () => {
    cleanup();
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    cleanup();
    process.exit(0);
  });

  process.on('exit', cleanup);
}

export async function registerRoutes(app: Express): Promise<Server> {
  // Start Flask backend
  await startFlask();

  // Set up proxy to Flask
  setupFlaskProxy(app);

  // Set up cleanup handlers
  setupCleanupHandlers();

  const httpServer = createServer(app);
  return httpServer;
}
