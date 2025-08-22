const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

// Disable X-Frame-Options from helmet
app.use(
  helmet({
    frameguard: false,
  })
);

app.use(cors());

// 🔥 Serve static (your index.html)
app.use(express.static('public'));

// 🔥 Catch ALL routes and proxy them
app.use(
  '/',
  createProxyMiddleware({
    target: 'https://hdtodayz.to', // <-- default site
    changeOrigin: true,
    selfHandleResponse: false,
    ws: true,
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
      // Strip iframe-breaking headers
      delete proxyRes.headers['x-frame-options'];
      delete proxyRes.headers['content-security-policy'];
    },
    pathRewrite: (path, req) => {
      // Keep the same path the user clicks
      return path;
    },
  })
);

// Start server
app.listen(port, () => {
  console.log(`Proxy server running on port ${port}`);
});
