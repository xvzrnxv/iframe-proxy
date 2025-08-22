const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cheerio = require('cheerio');
const { URL } = require('url');
const userAgent = require('user-agents');
const sanitizeHtml = require('sanitize-html');
const HttpsProxyAgent = require('https-proxy-agent');

const app = express();
const port = process.env.PORT || 3000;
const agent = new HttpsProxyAgent('socks5h://127.0.0.1:9050'); // Tor proxy

app.disable('x-powered-by');
app.use(helmet({
  frameguard: false,
  contentSecurityPolicy: { directives: { frameAncestors: ["'self'", '*'], upgradeInsecureRequests: true } },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: false,
  crossOriginResourcePolicy: false,
  hsts: { maxAge: 31536000 }
}));
app.use(cors({ origin: '*' }));

function antiBustScript(req) {
  const PREFIX = '/proxy?url=';
  return `
<script>
(function(){
  const PREFIX='${PREFIX}';
  const abs = (u) => { try { return new URL(u, location.href).href } catch(e){ return u } };
  const prox = (u) => { const a = abs(u); return a ? (PREFIX + encodeURIComponent(a)) : u };

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

  new MutationObserver(muts => {
    muts.forEach(m => {
      if (m.type === 'childList') scan();
      if (m.type === 'attributes' && ['src','href','action'].includes(m.attributeName)) {
        rewriteNode(m.target, m.attributeName);
      }
    });
  }).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['src','href','action'] });

  try {
    Object.defineProperty(window,'top',{get:()=>window});
    Object.defineProperty(window,'parent',{get:()=>window});
  } catch(e){}
  const wrapState = (fn) => new Proxy(fn, { apply: (t, th, [a,b,url]) => Reflect.apply(t, th, [a,b, url ? prox(url) : url]) });
  try {
    history.pushState = wrapState(history.pushState);
    history.replaceState = wrapState(history.replaceState);
  } catch(e){}
  window.open = (u, t) => { location.href = prox(u || location.href); return null; };

  // Anti-tracking
  Object.defineProperty(navigator, 'userAgent', { get: () => '${new userAgent().toString()}' });
  Object.defineProperty(navigator, 'webdriver', { get: () => false });
  window.localStorage && window.localStorage.clear();
  window.sessionStorage && window.sessionStorage.clear();
  Object.defineProperty(document, 'cookie', { get: () => '', set: () => {} });

  document.addEventListener('DOMContentLoaded', scan);
})();
</script>`;
}

app.get('/health', (req, res) => res.send('OK'));

app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  if (!target || !/^https?:\/\//.test(target)) {
    return res.status(400).send('Invalid or missing URL');
  }

  let upstream;
  try {
    upstream = await fetch(target, {
      redirect: 'follow',
      agent, // Route through Tor
      headers: {
        'User-Agent': new userAgent().toString(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Referer': '',
        'Origin': new URL(target).origin
      }
    });
  } catch (e) {
    return res.status(502).send('Fetch failed');
  }

  const status = upstream.status;
  const ct = upstream.headers.get('content-type') || '';

  res.setHeader('X-Frame-Options', 'ALLOWALL');
  res.setHeader('Content-Security-Policy', "frame-ancestors *; upgrade-insecure-requests");
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');

  if (ct.includes('text/html')) {
    let html = await upstream.text();
    html = sanitizeHtml(html, {
      allowedTags: sanitizeHtml.defaults.allowedTags.concat(['iframe']),
      allowedAttributes: { '*': ['href', 'src', 'action'], iframe: ['src'] },
      transformTags: {
        '*': (tagName, attribs) => {
          const attr = attribs.src || attribs.href || attribs.action;
          if (attr && !/^(data|blob|javascript):/i.test(attr)) {
            const baseURL = new URL(target);
            const abs = () => { try { return new URL(attr, baseURL).toString(); } catch { return attr; } };
            attribs[attr.includes('action') ? 'action' : attribs.href ? 'href' : 'src'] = `/proxy?url=${encodeURIComponent(abs())}`;
          }
          return { tagName, attribs };
        }
      }
    });

    const $ = cheerio.load(html, { decodeEntities: false });
    $('meta[http-equiv="Content-Security-Policy"]').remove();
    $('script').each((_, el) => {
      const src = $(el).attr('src');
      if (src && /google-analytics|doubleclick|adsense|tracker/i.test(src)) $(el).remove();
    });

    $('head').prepend(antiBustScript(req));
    res.status(status).type('html').send($.html());
    return;
  }

  const buf = Buffer.from(await upstream.arrayBuffer());
  res.status(status).set('Content-Type', ct || 'application/octet-stream').send(buf);
});

app.use(express.static('public'));
app.listen(port, () => console.log('proxy listening on ' + port));
