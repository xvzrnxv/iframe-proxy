import express from "express";
import fetch from "node-fetch";
import { JSDOM } from "jsdom";

const app = express();

// Rewrite links so all loads go through the proxy
function rewriteHtml(html, baseUrl, proxyUrl) {
  const dom = new JSDOM(html);
  const document = dom.window.document;

  // Update tag attributes to proxy
  ["a", "link", "img", "script", "iframe", "source"].forEach(tag => {
    document.querySelectorAll(tag).forEach(el => {
      ["href", "src"].forEach(attr => {
        const val = el.getAttribute(attr);
        if (!val) return;
        try {
          const absolute = new URL(val, baseUrl).href;
          el.setAttribute(attr, proxyUrl + encodeURIComponent(absolute));
        } catch {}
      });
    });
  });

  return dom.serialize();
}

app.get("/proxy", async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send("Missing ?url=");

  try {
    const resp = await fetch(target, {
      headers: { "User-Agent": "Mozilla/5.0" }
    });
    const contentType = resp.headers.get("content-type") || "";

    let body = await resp.text();

    res.setHeader("Content-Type", contentType);
    res.setHeader("Cache-Control", "no-cache");

    if (contentType.includes("text/html")) {
      body = rewriteHtml(body, target, `${req.protocol}://${req.get("host")}/proxy?url=`);
    }

    res.send(body);
  } catch (err) {
    res.status(500).send("Proxy error: " + err.message);
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Rewriting proxy running on port ${PORT}`));
