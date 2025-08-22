const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

// Security middleware
app.use(helmet()); // Adds security headers
app.use(cors()); // Enable CORS for iframe compatibility
app.use(express.static('public')); // Serve static files (e.g., index.html)

// Proxy middleware
app.use('/proxy', createProxyMiddleware({
  target: 'https://', // Dynamic target based on query param
  changeOrigin: true, // Changes Host header to match target
  pathRewrite: (path, req) => {
    const url = new URL(req.query.url);
    return url.pathname + url.search; // Forward only path and query
  },
  onProxyReq: (proxyReq, req, res) => {
    // Set headers to mimic browser behavior
    proxyReq.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
    proxyReq.setHeader('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8');
  },
  onError: (err, req, res) => {
    res.status(500).send('Proxy error: Unable to load content');
  },
  secure: true, // Enforce HTTPS
  ws: true, // Support WebSockets for dynamic sites
  router: (req) => {
    return req.query.url; // Dynamically route to the requested URL
  }
}));

// Basic route for health check
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Start server
app.listen(port, () => {
  console.log(`Proxy server running on port ${port}`);
});
