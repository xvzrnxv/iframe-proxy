import express from "express";
import fetch from "node-fetch";

const app = express();

app.get("/proxy", async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send("Missing ?url=");

  try {
    const response = await fetch(target);
    const body = await response.text();

    res.setHeader("Content-Type", response.headers.get("content-type") || "text/html");
    res.setHeader("Cache-Control", "no-cache");

    // 🔥 don’t forward iframe-blocking headers
    res.removeHeader?.("x-frame-options");
    res.removeHeader?.("content-security-policy");

    res.send(body);
  } catch (err) {
    res.status(500).send("Error proxying: " + err.message);
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Proxy running on ${port}`));
