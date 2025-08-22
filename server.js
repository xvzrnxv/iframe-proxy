const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cheerio = require('cheerio');
const { URL } = require('url');
const userAgent = require('user-agents'); // For random User-Agent generation
const sanitizeHtml = require('sanitize-html'); // For sanitizing HTML

const app = express();
const port = process.env.PORT || 3000;

// Middleware to disable identifying headers and enforce HTTPS
app.use(helmet({
  frameguard: false, // Allow iframe embedding
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      frameAncestors: ["'self'", '*'], // Allow framing from any origin
      upgradeInsecureRequests: true // Enforce HTTPS
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: false,
  crossOriginResourcePolicy: false,
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true } // Enforce HTTPS
}));
app.use(cors({ origin: '*' }));
app.disable('x-powered-by'); // Remove server fingerprint
app.set('trust proxy', true); // Handle reverse proxies (e.g., behind Cloudflare)

// Helper to inject client-side anti-tracking and rewriting script
function injectAntiTrackingScript(req) {
  const PREFIX = '/proxy?url=';
  return `
<script>
(function(){
  const PREFIX = '${PREFIX}';
  const abs = (u) => { try { return new URL(u, location.href).href } catch(e){ return u } };
  const prox = (u) => { const a = abs(u); return a ? (PREFIX + encodeURIComponent(a)) : u };

  // Rewrite URLs dynamically
  const rewriteNode = (el, attr) => {
    const v = el.getAttribute(attr);
    if (!v || /^(data|blob|javascript):/i.test(v)) return;
    el.setAttribute(attr, prox(v));
  };
  const scan = () => {
    document.querySelectorAll('[src],[href],form[action]').forEach(e => {
      if (e.hasAttribute('src')) rewriteNode(e, 'src');
      if (e.hasAttribute('href')) rewriteNode(e, 'href');
      if (e.hasAttribute('action')) rewriteNode(e, 'action');
    });
  };

  // Observe DOM changes
  new MutationObserver(muts => {
    muts.forEach(m => {
      if (m.type === 'childList') scan();
      if (m.type === 'attributes' && ['src','href','action'].includes(m.attributeName)) {
        rewriteNode(m.target, m.attributeName);
      }
    });
  }).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['src','href','action'] });

  // Anti-framebusting
  try {
    Object.defineProperty(window, 'top', { get: () => window });
    Object.defineProperty(window, 'parent', { get: () => window });
  } catch(e) {}

  // Rewrite navigation
  const wrapState = (fn) => new Proxy(fn, { apply: (t, th, [a,b,url]) => Reflect.apply(t, th, [a,b, url ? prox(url) : url]) });
  try {
    history.pushState = wrapState(history.pushState);
    history.replaceState = wrapState(history.replaceState);
  } catch(e) {}

  // Rewrite window.open
  window.open = (u, t) => { location.href = prox(u || location.href); return null; };

  // Disable tracking APIs
  Object.defineProperty(navigator, 'userAgent', { get: () => '${new userAgent().toString()}' });
  Object.defineProperty(navigator, 'webdriver', { get: () => false });
  window.localStorage && (window.localStorage.clear());
  window.sessionStorage && (window.sessionStorage.clear());
  Object.defineProperty(navigator, 'geolocation', { get: () => undefined });
  if (window.RTCPeerConnection) window.RTCPeerConnection = undefined;

  // Block cookies
  Object.defineProperty(document, 'cookie', {
    get: () => '',
    set: () => {}
  });

  // Initial scan
  document.addEventListener('DOMContentLoaded', scan);
})();
</script>`;
}

// Health check
app.get('/health', (req, res) => res.send('OK'));

// Proxy endpoint
app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  if (!target || !/^https?:\/\//.test(target)) {
    return res.status(400).send('Invalid or missing URL');
  }

  let upstream;
  try {
    upstream = await fetch(target, {
      redirect: 'follow',
      headers: {
        'User-Agent': new userAgent().toString(), // Randomize User-Agent
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Referer': '', // Strip Referer
        'Origin': new URL(target).origin // Match target origin
      }
    });
  } catch (e) {
    return res.status(502).send('Fetch failed');
  }

  const status = upstream.status;
  const ct = upstream.headers.get('content-type') || '';

  // Set headers to allow framing and prevent caching
  res.setHeader('X-Frame-Options', 'ALLOWALL');
  res.setHeader('Content-Security-Policy', "frame-ancestors *; upgrade-insecure-requests");
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Access-Control-Allow-Origin', '*');

  if (ct.includes('text/html')) {
    let html = await upstream.text();
    
    // Sanitize HTML to remove trackers and malicious scripts
    html = sanitizeHtml(html, {
      allowedTags: sanitizeHtml.defaults.allowedTags.concat(['iframe', 'meta']),
      allowedAttributes: {
        ...sanitizeHtml.defaults.allowedAttributes,
        iframe: ['src'],
        '*': ['href', 'src', 'action']
      },
      disallowedTagsMode: 'discard',
      transformTags: {
        '*': (tagName, attribs) => {
          if (attribs.src || attribs.href || attribs.action) {
            const attr = attribs.src ? 'src' : attribs.href ? 'href' : 'action';
            const value = attribs[attr];
            if (value && !/^(data|blob|javascript):/i.test(value)) {
              const baseURL = new URL(target);
              const abs = () => { try { return new URL(value, baseURL).toString(); } catch { return value; } };
              const prox = (u) => `/proxy?url=${encodeURIComponent(u)}`;
              attribs[attr] = prox(abs());
            }
          }
          return { tagName, attribs };
        }
      }
    });

    const $ = cheerio.load(html, { decodeEntities: false });

    // Remove tracking meta tags and scripts
    $('meta[http-equiv="Content-Security-Policy"]').remove();
    $('script').each((_, el) => {
      const src = $(el).attr('src');
      if (src && /google-analytics|doubleclick|adsense|tracker/i.test(src)) {
        $(el).remove();
      }
    });

    // Inject anti-tracking script
    $('head').prepend(injectAntiTrackingScript(req));

    res.status(status).type('html').send($.html());
    return;
  }

  // Non-HTML content (e.g., images, CSS, JS)
  const buf = Buffer.from(await upstream.arrayBuffer());
  res.status(status).set('Content-Type', ct || 'application/octet-stream').send(buf);
});

// Serve landing page
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Secure Proxy Browser</title>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <meta name="robots" content="noindex, nofollow">
    </head>
    <body>
      <h1>Secure Proxy Browser</h1>
      <p>Enter a URL to browse securely:</p>
      <form action="/proxy" method="GET">
        <input type="url" name="url" placeholder="https://example.com" required>
        <button type="submit">Go</button>
      </form>
    </body>
    </html>
  `);
});

app.listen(port, () => console.log(`Secure proxy running on http://localhost:${port}`));
