import express from "express";
import fetch from "node-fetch";

const app = express();

app.get("/proxy", async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send("Missing ?url=");

  try {
    const response = await fetch(target, {
      headers: { "User-Agent": "Mozilla/5.0" } // spoof browser UA
    });

    let body = await response.text();
    const contentType = response.headers.get("content-type") || "text/html";

    // If HTML, rewrite relative links → proxied absolute links
    if (contentType.includes("text/html")) {
      const baseUrl = new URL(target).origin;

      body = body.replace(/href="\/(.*?)"/g, `href="/proxy?url=${baseUrl}/$1"`);
      body = body.replace(/src="\/(.*?)"/g, `src="/proxy?url=${baseUrl}/$1"`);
      body = body.replace(/action="\/(.*?)"/g, `action="/proxy?url=${baseUrl}/$1"`);
    }

    res.setHeader("Content-Type", contentType);
    res.setHeader("Cache-Control", "no-cache");

    res.send(body);
  } catch (err) {
    res.status(500).send("Error proxying: " + err.message);
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Proxy running on ${port}`));
