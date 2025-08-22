const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cheerio = require('cheerio');
const { URL } = require('url');

const app = express();
const port = process.env.PORT || 3000;

app.disable('x-powered-by');

app.use(helmet({
  frameguard: false,
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: false,
  crossOriginResourcePolicy: false
}));
app.use(cors());

app.get('/health', (req, res) => res.send('OK'));

app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  if (!target) { res.status(400).send('missing url'); return; }
  let u;
  try { u = new URL(target); } catch (e) { res.status(400).send('bad url'); return; }

  let upstream;
  try {
    upstream = await fetch(u.toString(), {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9'
      },
      redirect: 'follow'
    });
  } catch (e) {
    res.status(502).send('fetch failed');
    return;
  }

  const ct = upstream.headers.get('content-type') || '';
  const status = upstream.status;

  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Origin', '*');

  if (ct.includes('text/html')) {
    const html = await upstream.text();
    const $ = cheerio.load(html, { decodeEntities: false });

    const absolutize = (val) => {
      try { return new URL(val, u).toString(); } catch { return null; }
    };
    const prox = (val) => {
      const abs = absolutize(val);
      if (!abs) return val;
      return '/proxy?url=' + encodeURIComponent(abs);
    };

    $('a[href]').each((_, el) => { const v = $(el).attr('href'); if (v) $(el).attr('href', prox(v)); });
    $('link[href]').each((_, el) => { const v = $(el).attr('href'); if (v) $(el).attr('href', prox(v)); });
    $('script[src]').each((_, el) => { const v = $(el).attr('src'); if (v) $(el).attr('src', prox(v)); });
    $('img[src]').each((_, el) => { const v = $(el).attr('src'); if (v) $(el).attr('src', prox(v)); });
    $('iframe[src]').each((_, el) => { const v = $(el).attr('src'); if (v) $(el).attr('src', prox(v)); });
    $('source[src]').each((_, el) => { const v = $(el).attr('src'); if (v) $(el).attr('src', prox(v)); });
    $('video[src]').each((_, el) => { const v = $(el).attr('src'); if (v) $(el).attr('src', prox(v)); });
    $('audio[src]').each((_, el) => { const v = $(el).attr('src'); if (v) $(el).attr('src', prox(v)); });
    $('track[src]').each((_, el) => { const v = $(el).attr('src'); if (v) $(el).attr('src', prox(v)); });
    $('form[action]').each((_, el) => { const v = $(el).attr('action'); if (v) $(el).attr('action', prox(v)); });
    $('meta[http-equiv="Content-Security-Policy"]').remove();
    $('meta[http-equiv="content-security-policy"]').remove();

    res.status(status);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.removeHeader('x-frame-options');
    res.removeHeader('content-security-policy');
    res.send($.html());
    return;
  } else {
    res.status(status);
    res.setHeader('Content-Type', ct || 'application/octet-stream');
    res.removeHeader('x-frame-options');
    res.removeHeader('content-security-policy');
    const buf = Buffer.from(await upstream.arrayBuffer());
    res.send(buf);
    return;
  }
});

app.use(express.static('public'));

app.listen(port, () => {
  console.log('proxy on ' + port);
});
