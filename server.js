const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

// Security middleware (disable frameguard so we can iframe)
app.use(
  helmet({
    frameguard: false,
  })
);

app.use(cors());

// Serve your static files (index.html, etc.)
app.use(express.static('public'));

// ✅ Proxy everything under /proxy/ to HDToday
app.use(
  '/proxy',
  createProxyMiddleware({
    target: 'https://hdtodayz.to',
    changeOrigin: true,
    ws: true,
    pathRewrite: (path, req) => {
      // remove "/proxy" prefix so links keep working
      return path.replace(/^\/proxy/, '');
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
    onProxyRes: (proxyRes) => {
      delete proxyRes.headers['x-frame-options'];
      delete proxyRes.headers['content-security-policy'];
    },
  })
);

// Health check
app.get('/health', (req, res) => res.send('OK'));

app.listen(port, () => {
  console.log(`Proxy running on port ${port}`);
});
