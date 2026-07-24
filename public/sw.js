// KAI service worker — exists mainly to satisfy PWA installability criteria
// (Chrome requires a registered service worker with a fetch handler before it
// will show the native "Install app" prompt or allow Play Store packaging).
//
// Caching strategy: network-first for the static app shell, with a cache
// fallback for offline use. API calls (/api/...) are NEVER intercepted or
// cached — pantry, shopping list, and auth data must always be live.

const CACHE_NAME = 'kai-static-v1';
const STATIC_ASSETS = [
    '/',
    '/index.html',
    '/manifest.json',
    '/icons/icon-192.png',
    '/icons/icon-512.png',
    '/icons/icon-maskable-512.png',
    '/icons/apple-touch-icon.png'
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => cache.addAll(STATIC_ASSETS))
            .catch((err) => console.warn('KAI SW: precache failed', err))
    );
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) =>
            Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key)))
        )
    );
    self.clients.claim();
});

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);

    // Never touch API calls or non-GET requests — always go straight to the network.
    if (url.pathname.startsWith('/api/')) return;
    if (event.request.method !== 'GET') return;

    event.respondWith(
        fetch(event.request)
            .then((response) => {
                const clone = response.clone();
                caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
                return response;
            })
            .catch(() => caches.match(event.request))
    );
});

// ==========================================
// PUSH NOTIFICATIONS & DEEP LINKING
// ==========================================

self.addEventListener('push', (event) => {
    let data = {};
    try {
        data = event.data ? event.data.json() : {};
    } catch(e) {
        data = { title: 'Expiring Ingredient Alert!', body: event.data.text() };
    }
    
    const title = data.title || 'Ingredient Expiring Soon!';
    const recipeId = data.recipeId || '';
    
    const options = {
        body: data.body || 'Tap to cook a recipe before it spoils!',
        icon: '/icons/icon-192.png',
        badge: '/icons/icon-192.png',
        vibrate: [100, 50, 100],
        data: {
            recipeId: recipeId,
            url: `/?openRecipe=${recipeId}`
        }
    };

    event.waitUntil(
        self.registration.showNotification(title, options)
    );
});

self.addEventListener('notificationclick', (event) => {
    event.notification.close();

    const targetUrl = event.notification.data.url;
    const recipeId = event.notification.data.recipeId;

    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
            for (const client of clientList) {
                if ('focus' in client) {
                    client.focus();
                    client.postMessage({
                        type: 'OPEN_RECIPE_MODAL',
                        recipeId: recipeId
                    });
                    return;
                }
            }
            if (clients.openWindow) {
                return clients.openWindow(targetUrl);
            }
        })
    );
});
