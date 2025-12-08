import express from "express";
import { createServer } from "http";
import { setupVite } from "./index-dev";

const app = express();

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
    res.status(500).json({ error: "Failed to connect to Flask backend" });
  }
});

const server = createServer(app);

// Set up Vite for frontend
setupVite(app, server).then(() => {
  const port = 5000;
  server.listen(port, "0.0.0.0", () => {
    console.log(`Proxy server running on http://0.0.0.0:${port}`);
    console.log(`Make sure Flask is running on http://localhost:5001`);
  });
});
