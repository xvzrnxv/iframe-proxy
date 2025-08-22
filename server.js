const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

// Security middleware (disable frameguard so iframe works)
app.use(
  helmet({
    frameguard: false,
  })
);

app.use(cors());

// Serve frontend files (index.html, etc.)
app.use(express.static('public'));

// Proxy middleware for all /proxy/* requests
app.use(
  '/proxy',
  createProxyMiddleware({
    target: 'https://hdtodayz.to',
    changeOrigin: true,
    ws: true,
    pathRewrite: (path, req) => path.replace(/^\/proxy/, ''), // strip /proxy
    onProxyRes: (proxyRes) => {
      // remove iframe-blocking headers
      delete proxyRes.headers['x-frame-options'];
      delete proxyRes.headers['content-security-policy'];
    },
  })
);

// Health check
app.get('/health', (req, res) => res.send('OK'));

// Start server
app.listen(port, () => {
  console.log(`Proxy running on port ${port}`);
});
