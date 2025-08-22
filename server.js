const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cheerio = require('cheerio');
const { URL } = require('url');

const app = express();
const port = process.env.PORT || 3000;

app.disable('x-powered-by');

// Keep CSP/frame headers off so we can embed in <iframe>
app.use(helmet({
  frameguard: false,
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: false,
  crossOriginResourcePolicy: false
}));
app.use(cors());

// A tiny helper used inside the injected script
function antiBustScript(req) {
  // prefix used by the proxy itself
  const PREFIX = '/proxy?url=';
  return `
<script>
(function(){
  const PREFIX='${PREFIX}';
  const abs = (u) => { try { return new URL(u, location.href).href } catch(e){ return null } };
  const prox = (u) => { const a = abs(u); return a ? (PREFIX + encodeURIComponent(a)) : u };

  // Rewrite existing links/resources
  const rewriteNode = (el, attr) => {
    const v = el.getAttribute(attr);
    if (!v) return;
    if (/^(data|blob|javascript):/i.test(v)) return;
    el.setAttribute(attr, prox(v));
  };
  const scan = () => {
    document.querySelectorAll('[src]').forEach(e => rewriteNode(e,'src'));
    document.querySelectorAll('[href]').forEach(e => rewriteNode(e,'href'));
    document.querySelectorAll('form[action]').forEach(e => rewriteNode(e,'action'));
  };

  // Rewrite runtime changes too
  new MutationObserver(muts => {
    muts.forEach(m => {
      if (m.type === 'childList') m.addedNodes.forEach(n => { if (n.nodeType===1) scan(); });
      if (m.type === 'attributes' && (m.attributeName==='src'||m.attributeName==='href'||m.attributeName==='action')) {
        rewriteNode(m.target, m.attributeName);
      }
    });
  }).observe(document.documentElement, { childList:true, subtree:true, attributes:true, attributeFilter:['src','href','action'] });

  // Kill common frame-busters
  try {
    Object.defineProperty(window,'top',{get:()=>window});
    Object.defineProperty(window,'parent',{get:()=>window});
  } catch(e){}

  // Keep SPA navigations inside the proxy
  const wrapState = (fn) => new Proxy(fn, { apply: (t, th, [a,b,url]) => Reflect.apply(t, th, [a,b, url ? prox(url) : url]) });
  try {
    history.pushState = wrapState(history.pushState);
    history.replaceState = wrapState(history.replaceState);
  } catch(e){}

  // Rewrite window.open to stay proxied
  window.open = (u, t) => { location.href = prox(u || location.href); return null; };

  // One-time initial pass
  document.addEventListener('DOMContentLoaded', scan);
})();
</script>`;
}

app.get('/health', (req, res) => res.send('OK'));

// Main proxy endpoint
app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  if (!target) { res.status(400).send('missing url'); return; }

  let upstream;
  try {
    upstream = await fetch(target, {
      redirect: 'follow',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9'
      }
    });
  } catch (e) {
    res.status(502).send('fetch failed');
    return;
  }

  const status = upstream.status;
  const ct = upstream.headers.get('content-type') || '';

  // Always allow framing *here*
  res.setHeader('X-Frame-Options', 'ALLOWALL');
  res.setHeader('Content-Security-Policy', "frame-ancestors *; upgrade-insecure-requests");
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');

  if (ct.includes('text/html')) {
    const html = await upstream.text();
    const $ = cheerio.load(html, { decodeEntities: false });

    // Make relative URLs absolute and wrap with /proxy?url=
    const baseURL = new URL(target);
    const abs = (u) => { try { return new URL(u, baseURL).toString(); } catch { return null; } };
    const prox = (u) => { const a = abs(u); return a ? `/proxy?url=${encodeURIComponent(a)}` : u; };

    ['a[href]','link[href]','script[src]','img[src]','iframe[src]','source[src]','video[src]','audio[src]','track[src]','form[action]']
      .forEach(sel => $(sel).each((_, el) => {
        const $el = $(el);
        const attr = sel.includes('action') ? 'action' : (sel.includes('[href]') ? 'href' : 'src');
        const v = $el.attr(attr);
        if (!v || /^(data|blob|javascript):/i.test(v)) return;
        const p = prox(v);
        if (p) $el.attr(attr, p);
      }));

    // Remove CSP meta tags
    $('meta[http-equiv="Content-Security-Policy"]').remove();
    $('meta[http-equiv="content-security-policy"]').remove();

    // Inject anti-framebust + live-rewriter
    $('head').prepend(antiBustScript(req));

    res.status(status).type('html').send($.html());
    return;
  }

  // Non-HTML response (images, css, js, video, etc.)
  const buf = Buffer.from(await upstream.arrayBuffer());
  res.status(status).set('Content-Type', ct || 'application/octet-stream').send(buf);
});

// (optional) serve your landing/index if you host one here
app.use(express.static('public'));

app.listen(port, () => console.log('proxy listening on ' + port));
