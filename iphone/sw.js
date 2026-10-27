/* Cache only this app's bundled shell. Imported reports never reach this worker. */
const CACHE = 'wifi-scout-iphone-shell-v2';
const SHELL = ['./', './index.html', './style.css', './app.js', './manifest.webmanifest', './icon.svg', './icon-192.png', './icon-512.png'];
const ALLOWED = new Set(SHELL.map(path => new URL(path, self.registration.scope).href));
self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key.startsWith('wifi-scout-iphone-shell-') && key !== CACHE).map(key => caches.delete(key)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET' || !ALLOWED.has(event.request.url)) return;
  event.respondWith(caches.open(CACHE).then(cache => cache.match(event.request).then(cached => cached || fetch(event.request))));
});
