const ALLOWED = (process.env.GATEWAY_ALLOWED_DOMAINS || "")
  .split(",")
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);

function allowed(hostname) {
  const h = hostname.toLowerCase();
  return ALLOWED.some(d => h === d || h.endsWith("." + d));
}

function isBlockedHost(hostname) {
  const h = hostname.toLowerCase();
  return (
    h === "localhost" ||
    h.endsWith(".localhost") ||
    h === "127.0.0.1" ||
    h === "::1" ||
    h === "0.0.0.0" ||
    /^10\./.test(h) ||
    /^192\.168\./.test(h) ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(h) ||
    h.endsWith(".local") ||
    h.endsWith(".internal")
  );
}

function proxiedUrl(req, target) {
  const base = new URL(req.url, "https://gateway.invalid");
  return `/api/gateway?url=${encodeURIComponent(target.href)}`;
}

function rewriteHtml(html, target, req) {
  const origin = target.origin;
  return html
    .replace(/\b(href|src|action)=(["'])(.*?)\2/gi, (m, attr, q, value) => {
      if (!value || /^(?:#|data:|javascript:|mailto:|tel:)/i.test(value)) return m;
      try {
        const u = new URL(value, target.href);
        if (u.protocol !== "http:" && u.protocol !== "https:") return m;
        return `${attr}=${q}${proxiedUrl(req, u)}${q}`;
      } catch {
        return m;
      }
    })
    .replace(/<base\b[^>]*>/gi, "");
}

export default async function handler(req, res) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.status(405).setHeader("Allow", "GET, HEAD").end("Method Not Allowed");
    return;
  }

  if (!ALLOWED.length) {
    res.status(503).json({
      error: "Gateway is not configured",
      message: "Set GATEWAY_ALLOWED_DOMAINS in Vercel to domains you are authorized to access."
    });
    return;
  }

  let target;
  try {
    target = new URL(req.query.url || "");
  } catch {
    res.status(400).json({ error: "Invalid URL" });
    return;
  }

  if (!["http:", "https:"].includes(target.protocol)) {
    res.status(400).json({ error: "Only HTTP(S) URLs are supported" });
    return;
  }

  if (isBlockedHost(target.hostname) || !allowed(target.hostname)) {
    res.status(403).json({ error: "Destination is not authorized by this gateway" });
    return;
  }

  try {
    const upstream = await fetch(target.href, {
      method: req.method,
      redirect: "follow",
      headers: {
        "user-agent": "Privacy-Browser-Gateway/1.0",
        "accept": req.headers.accept || "*/*"
      }
    });

    const contentType = upstream.headers.get("content-type") || "application/octet-stream";
    const body = req.method === "HEAD" ? null : Buffer.from(await upstream.arrayBuffer());

    res.status(upstream.status);
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");

    if (body && /^text\/html(?:;|$)/i.test(contentType)) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.end(rewriteHtml(body.toString("utf8"), target, req));
      return;
    }

    res.setHeader("Content-Type", contentType);
    res.end(body);
  } catch {
    res.status(502).json({ error: "Unable to reach the authorized destination" });
  }
}
