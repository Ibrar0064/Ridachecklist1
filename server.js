const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

const port = Number(process.env.PORT || 10000);
const indexFile = path.join(__dirname, "index.html");

const server = http.createServer((req, res) => {
  const pathname = new URL(req.url || "/", "http://localhost").pathname;

  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://mlaeaeuwxzavdioozxgi.supabase.co https://formspree.io; form-action 'self' https://formspree.io; base-uri 'self'; frame-ancestors 'none'"
  );

  if (req.method !== "GET" && req.method !== "HEAD") {
    res.writeHead(405, { "Content-Type": "text/plain; charset=utf-8", "Allow": "GET, HEAD" });
    res.end("Method Not Allowed");
    return;
  }

  if (pathname !== "/" && pathname !== "/index.html") {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not Found");
    return;
  }

  fs.readFile(indexFile, (error, content) => {
    if (error) {
      res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Unable to load checklist.");
      return;
    }

    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store"
    });
    if (req.method === "HEAD") {
      res.end();
    } else {
      res.end(content);
    }
  });
});

server.listen(port, "0.0.0.0", () => {
  console.log("Rida Checklist listening on port " + port);
});
