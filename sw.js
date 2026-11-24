const CACHE_NAME = "satark-ai-py-v2.2.0";
const STATIC_ASSETS = ["/static/styles.css", "/static/app.js", "/static/icon.svg", "/manifest.webmanifest"];

self.addEventListener("install", event => {
  event.waitUntil(caches.open(CACHE_NAME).then(c => c.addAll(STATIC_ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k.startsWith("satark-ai-py-") && k !== CACHE_NAME).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", event => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  const hasSensitiveQuery =
    url.searchParams.has("text") || url.searchParams.has("url") ||
    url.searchParams.has("token") || url.searchParams.has("otp");
  if (hasSensitiveQuery || url.pathname.startsWith("/api/")) return;
  if (url.pathname.startsWith("/static/") || url.pathname === "/manifest.webmanifest") {
    event.respondWith(caches.match(req).then(hit => hit || fetch(req)));
  }
});
