import express from "express";
import fetch from "node-fetch";
import { JSDOM } from "jsdom";

const app = express();

app.use(express.text({ type: "*/*" }));

// Helper: rewrite absolute & relative links to point back through proxy
function rewriteHtml(html, baseUrl, proxyUrl) {
  const dom = new JSDOM(html);
  const document = dom.window.document;

  // Rewrite <a>, <script>, <link>, <img>, <iframe>
  const selectors = ["a", "script", "link", "img", "iframe", "source"];
  selectors.forEach((sel) => {
    document.querySelectorAll(sel).forEach((el) => {
      let attr = "href";
      if (sel !== "a" && sel !== "link") attr = "src";
      const val = el.getAttribute(attr);
      if (!val) return;

      try {
        const url = new URL(val, baseUrl).href;
        el.setAttribute(attr, proxyUrl + encodeURIComponent(url));
      } catch (e) {
        // ignore invalid URLs
      }
    });
  });

  return dom.serialize();
}

app.get("/proxy", async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send("Missing ?url=");

  try {
    const response = await fetch(target, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119 Safari/537.36",
      },
    });

    let body = await response.text();

    const contentType = response.headers.get("content-type") || "text/html";
    res.setHeader("Content-Type", contentType);
    res.setHeader("Cache-Control", "no-cache");

    // If HTML → rewrite
    if (contentType.includes("text/html")) {
      body = rewriteHtml(
        body,
        target,
        `${req.protocol}://${req.get("host")}/proxy?url=`
      );
    }

    res.send(body);
  } catch (err) {
    res.status(500).send("Proxy error: " + err.message);
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Rewriting proxy running on ${port}`));
