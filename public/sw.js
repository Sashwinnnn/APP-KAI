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
        data = { title: 'Kitchen Alert!', body: event.data.text() };
    }
    
    const itemName = data.itemName || data.item || 'Organic Milk';
    const isExpired = (data.action === 'delete') || (data.actionType === 'expired') || (data.url && (data.url.includes('delete') || data.url.includes('expired')));
    const actionType = isExpired ? 'expired' : 'cook';
    
    let defaultTitle = isExpired ? `KAI Expiration Alert: ${itemName} Has Expired! 🚨` : `KAI Expiration Alert: ${itemName} Expiring Soon! ⚠️`;
    let defaultBody = isExpired ? `${itemName} has passed its expiry date. Tap to review and remove from pantry.` : `${itemName} expires soon. Tap to generate a flashcard recipe deck!`;
    let defaultUrl = isExpired ? `/?action=delete&deleteItem=${encodeURIComponent(itemName)}` : `/?action=cook&cookItem=${encodeURIComponent(itemName)}`;

    const title = data.title || defaultTitle;
    
    const options = {
        body: data.body || defaultBody,
        icon: '/icons/icon-192.png',
        badge: '/icons/icon-192.png',
        vibrate: [100, 50, 100],
        data: {
            itemName: itemName,
            actionType: actionType,
            url: data.url || defaultUrl
        }
    };

    event.waitUntil(
        self.registration.showNotification(title, options)
    );
});

self.addEventListener('notificationclick', (event) => {
    event.notification.close();

    const notificationData = event.notification ? (event.notification.data || {}) : {};
    const itemName = notificationData.itemName || 'Organic Milk';
    const isExpired = (notificationData.actionType === 'expired') || (notificationData.url && (notificationData.url.includes('delete') || notificationData.url.includes('expired')));
    
    const targetUrl = notificationData.url || (isExpired ? `/?action=delete&deleteItem=${encodeURIComponent(itemName)}` : `/?action=cook&cookItem=${encodeURIComponent(itemName)}`);
    const msgType = isExpired ? 'ITEM_EXPIRED_ALERT' : 'COOK_EXPIRING_ITEM';

    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
            for (const client of clientList) {
                if ('focus' in client) {
                    client.focus();
                    client.postMessage({
                        type: msgType,
                        itemName: itemName
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
