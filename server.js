const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

// Security middleware (disable frameguard!)
app.use(
  helmet({
    contentSecurityPolicy: false,
    frameguard: false
  })
);

app.use(cors());
app.use(express.static('public'));

// Proxy middleware
app.use('/proxy', createProxyMiddleware({
  changeOrigin: true,
  secure: false,
  ws: true,
  pathRewrite: (path, req) => {
    const url = new URL(req.query.url);
    return url.pathname + url.search;
  },
  router: (req) => req.query.url,
  onProxyReq: (proxyReq) => {
    proxyReq.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)');
    proxyReq.setHeader('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8');
  },
  onProxyRes: (proxyRes) => {
    // 🔥 Strip iframe-blocking headers
    delete proxyRes.headers['x-frame-options'];
    delete proxyRes.headers['content-security-policy'];
  },
  onError: (err, req, res) => {
    res.status(500).send('Proxy error: ' + err.message);
  }
}));

// Basic health check
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.listen(port, () => {
  console.log(`Proxy running on port ${port}`);
});
