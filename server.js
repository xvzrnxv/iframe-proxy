const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

// Security middleware (disable frameguard so iframes work)
app.use(
  helmet({
    frameguard: false, // 🔥 allow embedding in iframes
  })
);
app.use(cors()); // Enable CORS for iframe compatibility
app.use(express.static('public')); // Serve static files (e.g., index.html)

// Proxy middleware
app.use(
  '/proxy',
  createProxyMiddleware({
    target: 'https://',
    changeOrigin: true,
    pathRewrite: (path, req) => {
      const url = new URL(req.query.url);
      return url.pathname + url.search;
    },
    onProxyReq: (proxyReq, req, res) => {
      proxyReq.setHeader(
        'User-Agent',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      );
      proxyReq.setHeader(
        'Accept',
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      );
    },
    onProxyRes: (proxyRes, req, res) => {
      // 🔥 Strip iframe-blocking headers
      delete proxyRes.headers['x-frame-options'];
      delete proxyRes.headers['content-security-policy'];
    },
    onError: (err, req, res) => {
      res.status(500).send('Proxy error: Unable to load content');
    },
    secure: true,
    ws: true,
    router: (req) => {
      return req.query.url;
    },
  })
);

// Basic route for health check
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Start server
app.listen(port, () => {
  console.log(`Proxy server running on port ${port}`);
});
